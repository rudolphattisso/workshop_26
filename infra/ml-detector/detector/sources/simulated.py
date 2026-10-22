"""Générateur de trafic WAF simulé, fidèle à la plateforme de paiement de l'infra.

Assemble le trafic légitime (sim_normal.py) et les attaques (sim_attacks.py), puis applique,
dans l'ordre, ce qui modifie les réponses :
  1. limitation de débit du WAF, PAR IP (limit_req) : 429 au-delà du débit autorisé ;
  2. bannissement automatique « bad behavior » (valeurs du .env de l'infra : 20 réponses
     4xx/429 en 60 s => IP bannie 300 s) ;
  3. saturation du service : au-delà de sa capacité, une part des requêtes qui atteignent
     l'application reçoit 503, y compris celles des clients légitimes (effet d'un DDoS).

Chaque requête est formatée en ligne de journal nginx puis re-parsée : le parseur est donc
exercé exactement comme sur de vrais journaux. Chaque ligne porte une étiquette de vérité
terrain ("normal" ou le type d'attaque) qui sert UNIQUEMENT à l'évaluation, jamais au modèle.
"""
from __future__ import annotations

import random
from collections import defaultdict, deque
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone

from ..models import HttpRequestLog
from ..parsing import format_line, parse_line
from .base import LogSource
from .sim_attacks import ATTACK_KINDS, HEAVY_LIMIT, AttackSpec, generate_attack
from .sim_common import LabeledRecord
from .sim_normal import NormalTraffic

_WAF_REFUSALS = frozenset({403, 429, 444})     # réponses du WAF : la requête n'atteint pas l'application

__all__ = ["ATTACK_KINDS", "AttackSpec", "BadBehavior", "Capacity", "LabeledRecord", "RateLimit", "SimulatedSource"]


@dataclass(frozen=True)
class BadBehavior:
    """Paramètres du bannissement automatique BunkerWeb (USE_BAD_BEHAVIOR)."""
    statuses: frozenset = frozenset({400, 401, 403, 404, 405, 429, 444})   # BAD_BEHAVIOR_STATUS_CODES
    threshold: int = 20          # WAF_BADBEHAVIOR_THRESHOLD
    count_time_s: int = 60       # BAD_BEHAVIOR_COUNT_TIME
    ban_time_s: int = 300        # WAF_BAN_TIME


@dataclass(frozen=True)
class RateLimit:
    """Limitation de débit BunkerWeb (USE_LIMIT_REQ), comptée par IP et par seconde."""
    login_per_s: int = 5         # WAF_LOGIN_RATE (/api/auth/login)
    default_per_s: int = 20      # WAF_API_RATE (toutes les autres URL)
    login_path: str = "/api/auth/login"


@dataclass(frozen=True)
class Capacity:
    """Capacité du service derrière le WAF, en « unités » par seconde (1 requête = 1 unité).
    Le trafic normal culmine à ~12 req/s : 60 laisse une large marge à un afflux légitime."""
    units_per_s: float = 60.0
    heavy_cost: float = 40.0     # export volumineux (?limit > 1000) : 40 fois une requête normale


class SimulatedSource(LogSource):
    def __init__(self, seed: int = 42, n_users: int = 25, attacks: tuple[AttackSpec, ...] = (),
                 waf_blocking: bool = True, rushes: tuple[float, ...] = (),
                 bad_behavior: BadBehavior | None = BadBehavior(), origin: datetime | None = None,
                 rate_limit: RateLimit | None = RateLimit(), capacity: Capacity | None = Capacity(),
                 rush_visitors: int = 40):
        """
        waf_blocking : True = WAF en mode « On » (injections refusées en 403) ;
                       False = « DetectionOnly » (les charges atteignent l'API).
        rushes       : débuts d'afflux légitimes (secondes après origin).
        bad_behavior : None pour désactiver le bannissement automatique.
        rate_limit   : None pour désactiver la limitation de débit par IP.
        capacity     : None pour un service à capacité infinie (aucun 503 de saturation).
        rush_visitors: nombre de nouveaux visiteurs par afflux (sur 3 min).
        origin       : instant de référence des AttackSpec et rushes (défaut : début du fetch).
        """
        self.seed = seed
        self.n_users = n_users
        self.attacks = attacks
        self.waf_blocking = waf_blocking
        self.rushes = rushes
        self.bad_behavior = bad_behavior
        self.origin = origin
        self.rate_limit = rate_limit
        self.capacity = capacity
        self.rush_visitors = rush_visitors

    def fetch(self, start: datetime, end: datetime) -> list[HttpRequestLog]:
        return [lr.record for lr in self.generate(start, end)]

    def generate(self, start: datetime, end: datetime) -> list[LabeledRecord]:
        if start.tzinfo is None:
            start, end = start.replace(tzinfo=timezone.utc), end.replace(tzinfo=timezone.utc)
        origin = self.origin or start
        rng = random.Random(f"{self.seed}-{start.isoformat()}")

        out = NormalTraffic(rng, self.n_users, self.rushes, origin, self.rush_visitors).generate(start, end)
        for spec in self.attacks:
            a_start = max(start, origin + timedelta(seconds=spec.start_offset_s))
            a_end = min(end, origin + timedelta(seconds=spec.start_offset_s + spec.duration_s))
            if a_start < a_end:
                out += generate_attack(spec, a_start, a_end, rng, self.waf_blocking)

        out = sorted((lr for lr in out if start <= lr.record.ts < end), key=lambda lr: lr.record.ts)
        if self.rate_limit:
            out = self._apply_rate_limit(out, self.rate_limit)
        if self.bad_behavior:
            out = self._apply_bans(out, self.bad_behavior)
        if self.capacity:
            out = self._apply_saturation(out, self.capacity, rng)
        # Aller-retour par le format de journal nginx : même chemin que les vrais logs.
        return [LabeledRecord(parse_line(format_line(lr.record)), lr.label) for lr in out]

    @staticmethod
    def _apply_rate_limit(records: list[LabeledRecord], rl: RateLimit) -> list[LabeledRecord]:
        counts: dict[tuple, int] = defaultdict(int)
        out = []
        for lr in records:
            rec = lr.record
            is_login = rec.uri.split("?")[0] == rl.login_path
            key = (rec.client_ip, is_login, int(rec.ts.timestamp()))
            counts[key] += 1
            limit = rl.login_per_s if is_login else rl.default_per_s
            if counts[key] > limit:
                lr = LabeledRecord(replace(rec, status=429, bytes_sent=169), lr.label)
            out.append(lr)
        return out

    @staticmethod
    def _apply_saturation(records: list[LabeledRecord], cap: Capacity, rng: random.Random) -> list[LabeledRecord]:
        """Par seconde : si la charge des requêtes qui atteignent l'application dépasse la
        capacité, chacune reçoit 503 avec une probabilité 1 - capacité / charge."""
        def cost(rec: HttpRequestLog) -> float:
            return cap.heavy_cost if f"limit={HEAVY_LIMIT}" in rec.uri else 1.0

        reaching = lambda lr: lr.record.status not in _WAF_REFUSALS  # noqa: E731
        load: dict[int, float] = defaultdict(float)
        for lr in records:
            if reaching(lr):
                load[int(lr.record.ts.timestamp())] += cost(lr.record)
        out = []
        for lr in records:
            second_load = load[int(lr.record.ts.timestamp())]
            if reaching(lr) and second_load > cap.units_per_s and rng.random() > cap.units_per_s / second_load:
                lr = LabeledRecord(replace(lr.record, status=503, bytes_sent=197), lr.label)
            out.append(lr)
        return out

    @staticmethod
    def _apply_bans(records: list[LabeledRecord], bb: BadBehavior) -> list[LabeledRecord]:
        """Une IP qui cumule `threshold` mauvaises réponses en `count_time_s` est bannie :
        toutes ses requêtes reçoivent 403 pendant `ban_time_s`. Touche aussi le trafic légitime
        (ex. collègues derrière un même NAT), comme le vrai WAF."""
        window, ban = timedelta(seconds=bb.count_time_s), timedelta(seconds=bb.ban_time_s)
        bad: dict[str, deque] = defaultdict(deque)
        banned_until: dict[str, datetime] = {}
        out = []
        for lr in records:
            rec, ip = lr.record, lr.record.client_ip
            if ip in banned_until and rec.ts < banned_until[ip]:
                out.append(LabeledRecord(replace(rec, status=403, bytes_sent=555), lr.label))
                continue
            q = bad[ip]
            if rec.status in bb.statuses:
                q.append(rec.ts)
                while q and q[0] < rec.ts - window:
                    q.popleft()
                if len(q) >= bb.threshold:
                    banned_until[ip] = rec.ts + ban
                    q.clear()
            out.append(lr)
        return out
