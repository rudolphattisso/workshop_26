"""Historique récent par IP, pour situer un cluster anormal dans le passé de ses IP.

Un résumé de cluster ne contient que les requêtes anormales. Sans historique, une IP
d'entreprise bannie par erreur par le WAF (403 en série sur des chemins normaux) ressemble à un
attaquant ; avec, on voit qu'elle faisait juste avant des requêtes réussies (paiements, pages).

Seuls des compteurs sont conservés : aucune chaîne venant du client (URI, user-agent) n'est
renvoyée, donc rien à assainir ni à injecter dans le prompt du LLM.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

from .features import BLOCKED_STATUSES, attack_signals
from .models import HttpRequestLog

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_PAYLOAD_KEYS = ("sqli_hits", "xss_hits", "traversal_hits", "cmdi_hits", "scanner_path")


@dataclass(slots=True)
class IpProfile:
    """Comportement d'une IP AVANT la fenêtre analysée."""
    n_requests: int
    first_seen: str                 # ISO 8601
    share_2xx: float
    share_blocked: float            # refusées par le WAF (403/429/444)
    n_successful_writes: int        # POST/PUT/PATCH/DELETE en 2xx (paiements, connexions...)
    n_distinct_user_agents: int     # > 1 depuis une seule IP : NAT, proxy d'entreprise
    n_payload_requests: int         # requêtes avec motif d'injection ou chemin de scan

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class _Event:
    ts: datetime
    status: int
    write_ok: bool
    ua_hash: int
    payload: bool


class IpHistory:
    """Garde `horizon_s` secondes de requêtes par IP (toutes, pas seulement les anormales).

    Usage en continu : analyser la fenêtre avec `history=...`, PUIS `update(fenêtre)`.
    """

    def __init__(self, horizon_s: int = 3600):
        self.horizon = timedelta(seconds=horizon_s)
        self._events: dict[str, deque[_Event]] = defaultdict(deque)

    def update(self, records: list[HttpRequestLog]) -> None:
        for rec in records:
            signals = attack_signals(rec.uri)
            self._events[rec.client_ip].append(_Event(
                ts=rec.ts,
                status=rec.status,
                write_ok=rec.method.upper() in _WRITE_METHODS and 200 <= rec.status < 300,
                ua_hash=hash(rec.user_agent),
                payload=any(signals[k] for k in _PAYLOAD_KEYS),
            ))
        if records:
            self._prune(max(r.ts for r in records) - self.horizon)

    def profile(self, ip: str, before: datetime) -> IpProfile | None:
        events = [e for e in self._events.get(ip, ()) if before - self.horizon <= e.ts < before]
        if not events:
            return None
        n = len(events)
        return IpProfile(
            n_requests=n,
            first_seen=min(e.ts for e in events).isoformat(),
            share_2xx=round(sum(200 <= e.status < 300 for e in events) / n, 3),
            share_blocked=round(sum(e.status in BLOCKED_STATUSES for e in events) / n, 3),
            n_successful_writes=sum(e.write_ok for e in events),
            n_distinct_user_agents=len({e.ua_hash for e in events}),
            n_payload_requests=sum(e.payload for e in events),
        )

    def _prune(self, cutoff: datetime) -> None:
        for ip in list(self._events):
            q = self._events[ip]
            while q and q[0].ts < cutoff:
                q.popleft()
            if not q:
                del self._events[ip]
