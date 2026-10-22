"""Escalade vers le LLM : le détecteur tourne en continu (peu coûteux), le LLM n'est appelé que
pour ce qui le mérite (~40 s de GPU par analyse).

Gravité 0-100, déterministe et expliquée (chaque point a sa raison, lisible par l'opérateur) :
  - type d'attaque mesuré par le détecteur (botnet, requêtes lourdes, injection...) ;
  - IMPACT : part de 503 dans le groupe (le service tombe) ;
  - injection qui ATTEINT l'application (non bloquée par le WAF : ce que le module doit trouver) ;
  - le WAF bloque déjà presque tout, sans impact : malus (une attaque seule, contenue, ne nuit pas) ;
  - ampleur (IP, volume), persistance sur plusieurs fenêtres ;
  - alarmes externes : disponibilité (impact), ou WAF/Wazuh sur les mêmes IP (corroboration).
Au-delà du seuil : appel au LLM, par gravité décroissante, plafonné par fenêtre ; une campagne
déjà analysée ne l'est pas de nouveau pendant le délai de garde, sauf si elle s'aggrave nettement.
La gravité alimente aussi la métrique soc_waf_anomaly_score, avec ou sans appel au LLM.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .alarms import AUTH, AVAILABILITY, RECON, WAF_BAN, WAF_BLOCK, Alarm
from .config import _env
from .models import ClusterSummary

# Gravité de base par indice du détecteur (on prend le plus grave, +5 par autre indice fort).
_HINT_BASE = {
    "distributed_flood": 40, "heavy_requests": 35, "command_injection": 30, "credential_bruteforce": 30,
    "sql_injection": 25, "xss": 25, "path_traversal": 25, "request_flood": 20,
    "possible_waf_collateral": 15, "reconnaissance_scan": 10, "unknown_anomaly": 5,
}
_INJECTIONS = {"sql_injection", "xss", "path_traversal", "command_injection"}
_MIN_CAMPAIGN_REQUESTS = 20
_MIN_INJECTIONS_ANSWERED = 3     # une tentative isolée qui passe ne suffit pas


@dataclass(frozen=True)
class EscalationConfig:
    threshold: int = field(default_factory=lambda: _env("ESCALATION_THRESHOLD", 50, int))
    cooldown_s: int = field(default_factory=lambda: _env("ESCALATION_COOLDOWN_S", 1800, int))
    worsening: int = field(default_factory=lambda: _env("ESCALATION_WORSENING", 20, int))   # réanalyse si +20
    # Appels au LLM par minute glissante (~40 s de GPU par analyse) ; indépendant de la fréquence
    # d'analyse (fenêtre glissante de 60 s recalculée toutes les 10 s).
    max_per_minute: int = field(default_factory=lambda: _env("ESCALATION_MAX_PER_MINUTE", 2, int))
    persistence_s: int = field(default_factory=lambda: _env("ESCALATION_PERSISTENCE_S", 120, int))


@dataclass
class Decision:
    cluster: ClusterSummary
    severity: int
    reasons: list[str]
    escalate: bool
    skipped_because: str | None = None        # au-dessus du seuil mais non envoyé (délai de garde, plafond)

    def to_context(self) -> dict:
        """Joint à la requête /analyze : le LLM sait pourquoi on l'appelle."""
        return {"severity": self.severity, "reasons": self.reasons}


_FAMILIES = [   # du plus spécifique au plus général : la première famille présente l'emporte
    ("injection", _INJECTIONS),
    ("force_brute", {"credential_bruteforce"}),
    ("volumetrique", {"distributed_flood", "request_flood", "heavy_requests"}),
    ("reconnaissance", {"reconnaissance_scan"}),
    ("collateral", {"possible_waf_collateral"}),
]
_MAJOR_PATH_SHARE = 0.2


def campaign_key(cluster: ClusterSummary) -> tuple[str, frozenset]:
    """Identité d'une campagne d'un cycle à l'autre (délai de garde, persistance).

    La signature du détecteur dépend des indices et des deux premiers chemins, qui varient
    légèrement d'un cycle de 10 s à l'autre pour une même attaque (vu en démo : un chemin
    secondaire qui apparaît, un indice qui s'ajoute) : chaque variation ressemblait à une nouvelle
    campagne et repartait vers le LLM. On garde la FAMILLE d'attaque et les chemins MAJEURS
    (>= 20 % des requêtes du groupe)."""
    hints = set(cluster.attack_hints)
    family = next((name for name, members in _FAMILIES if hints & members), "anomalie")
    n = max(cluster.n_requests, 1)
    major = frozenset(str(p.get("path")) for p in cluster.top_paths if int(p.get("count", 0)) / n >= _MAJOR_PATH_SHARE)
    return family, major


@dataclass
class SymptomDecision:
    """Service dégradé sans campagne détectée (pas de cluster : le LLM reçoit la fenêtre entière)."""
    severity: int
    reasons: list[str]
    escalate: bool
    skipped_because: str | None = None
    trigger: str = "symptome_sans_campagne"

    def to_context(self) -> dict:
        return {"severity": self.severity, "reasons": self.reasons, "trigger": self.trigger}


_MIN_SYMPTOM_ALARMS = 3
# Une seule suffit : l'infra signale elle-même qu'elle n'a pas pu rétablir le service (Wazuh
# 100210, ou directement le journal du moteur de remédiation si Wazuh est tombé).
_CRITICAL_RULES = {"100210", "remediation_failed"}
SYMPTOM_KEY = _SYMPTOM_KEY = "__symptome__"   # identité du déclencheur « symptôme »
VISIBILITY_KEY = "__visibilite__"             # identité du déclencheur « perte de visibilité »
_VISIBILITY_SEVERITY = 60


def severity(cluster: ClusterSummary, alarms: list[Alarm], persisting_s: float = 0.0,
             persistence_s: int = 120) -> tuple[int, list[str]]:
    reasons: list[str] = []
    hints = [h for h in cluster.attack_hints if h in _HINT_BASE]
    score = 0
    if hints:
        ranked = sorted(hints, key=lambda h: -_HINT_BASE[h])
        score = _HINT_BASE[ranked[0]] + 5 * sum(_HINT_BASE[h] >= 20 for h in ranked[1:])
        reasons.append(f"{', '.join(ranked)} (+{score})")

    n = max(cluster.n_requests, 1)
    errors_5xx = sum(c for s, c in cluster.statuses.items() if str(s).startswith("5")) / n
    # L'impact (5xx) et les alarmes décrivent l'état du SERVICE : on ne les attribue qu'à une vraie
    # campagne, pas à quelques requêtes prises dans la tourmente (clients légitimes en 503...).
    campaign = cluster.n_requests >= _MIN_CAMPAIGN_REQUESTS
    if not campaign and not set(hints) - {"unknown_anomaly"}:
        reasons.append(f"groupe de {cluster.n_requests} requêtes sans motif d'attaque : l'impact mesuré concerne "
                       f"le service, pas ce groupe")
        return max(0, min(100, score)), reasons
    impact = campaign and errors_5xx >= 0.1
    if impact and errors_5xx >= 0.5:
        score += 40
        reasons.append(f"service saturé : {errors_5xx:.0%} de réponses 5xx (+40)")
    elif impact:
        score += 25
        reasons.append(f"service dégradé : {errors_5xx:.0%} de réponses 5xx (+25)")

    # Compté requête par requête par le détecteur : charge d'injection ET vraie réponse de
    # l'application (ni refus du WAF, ni 5xx d'un WAF qui redémarre : vu le 20/10 à 08:56). Une
    # proportion de statuts du groupe ne suffisait pas : en fenêtre glissante, 1 client ordinaire
    # dans un petit groupe naissant faisait « 20 % de réponses » (vu en démo).
    if set(hints) & _INJECTIONS and cluster.injections_answered >= _MIN_INJECTIONS_ANSWERED:
        score += 30
        reasons.append(f"injection qui atteint l'application : {cluster.injections_answered} requêtes d'injection "
                       f"ont reçu une réponse de l'application (+30)")
    if cluster.blocked_ratio >= 0.95 and not impact:
        score -= 30
        reasons.append(f"le WAF bloque déjà {cluster.blocked_ratio:.0%}, sans impact mesuré (-30)")

    if cluster.n_distinct_ips >= 50:
        score += 10
        reasons.append(f"{cluster.n_distinct_ips} IP distinctes (+10)")
    if cluster.n_requests >= 1000:
        score += 10
        reasons.append(f"{cluster.n_requests} requêtes en une fenêtre (+10)")
    if persisting_s >= persistence_s:
        score += 10
        reasons.append(f"persiste depuis {persisting_s / 60:.0f} min (+10)")

    if campaign and any(a.kind == AVAILABILITY for a in alarms):
        score += 20
        rules = sorted({a.rule for a in alarms if a.kind == AVAILABILITY})
        reasons.append(f"alarme de disponibilité pendant la fenêtre (règles {', '.join(rules)}) (+20)")
    ips = {e.get("ip") for e in cluster.top_ips}
    matching = [a for a in alarms if a.ip in ips and a.kind in (WAF_BAN, WAF_BLOCK, RECON, AUTH)]
    if matching:
        score += 10
        rules = sorted({a.rule for a in matching})
        reasons.append(f"corroboré par le WAF sur les mêmes IP (règles {', '.join(rules)}) (+10)")
    return max(0, min(100, score)), reasons


class Escalator:
    """État entre cycles : persistance des campagnes (en temps), dernières escalades (délai de
    garde) et appels récents (plafond par minute). Indépendant de la fréquence des cycles : fenêtres
    fixes de 60 s (démos) ou glissantes recalculées toutes les 10 s (service)."""

    _GAP_S = 90          # une campagne absente plus longtemps que ça « recommence » (persistance remise à 0)

    def __init__(self, config: EscalationConfig | None = None):
        self.config = config or EscalationConfig()
        self._seen: dict[str, tuple[datetime, datetime]] = {}  # signature -> (première, dernière observation)
        self._escalated: dict = {}   # campagne -> (date de la 1re analyse, gravité, déjà réanalysée ?)
        self._sent: list[datetime] = []                         # dates des appels récents (plafond par minute)
        self._critical_seen: datetime | None = None             # dernière alarme critique déjà analysée

    def decide(self, clusters: list[ClusterSummary], alarms: list[Alarm], now: datetime) -> list[Decision]:
        decisions = []
        for cluster in clusters:
            key = campaign_key(cluster)
            first, last = self._seen.get(key, (now, now))
            if (now - last).total_seconds() > self._GAP_S:
                first = now
            self._seen[key] = (first, now)
            score, reasons = severity(cluster, alarms, (now - first).total_seconds(), self.config.persistence_s)
            decisions.append(Decision(cluster, score, reasons, escalate=score >= self.config.threshold))

        for d in sorted(decisions, key=lambda d: -d.severity):
            if not d.escalate:
                continue
            key = campaign_key(d.cluster)
            previous = self._escalated.get(key)            # (première analyse, gravité, déjà réanalysée)
            in_cooldown = previous and now - previous[0] < timedelta(seconds=self.config.cooldown_s)
            worsened = in_cooldown and d.severity >= previous[1] + self.config.worsening and not previous[2]
            if in_cooldown and not worsened:
                why = "déjà réanalysée après aggravation" if previous[2] else "délai de garde"
                d.escalate, d.skipped_because = False, f"déjà analysée à {previous[0]:%H:%M} ({why})"
            elif not self._budget_left(now):
                d.escalate, d.skipped_because = False, "plafond d'analyses par minute atteint"
            else:
                # Une seule réanalyse sur aggravation par délai de garde (vu en démo : 55 -> 80 -> 100
                # donnait trois analyses de la même campagne en deux minutes).
                self._sent.append(now)
                self._escalated[key] = (previous[0], d.severity, True) if worsened else (now, d.severity, False)
        return sorted(decisions, key=lambda d: -d.severity)

    def release(self, key) -> None:
        """Analyse jamais envoyée (écartée de la file) : la campagne peut être réescaladée au cycle
        suivant, au lieu d'attendre la fin d'un délai de garde pour une analyse qui n'a pas eu lieu."""
        self._escalated.pop(key, None)

    def _budget_left(self, now: datetime) -> bool:
        self._sent = [t for t in self._sent if now - t < timedelta(seconds=60)]
        return len(self._sent) < self.config.max_per_minute

    def decide_symptom(self, alarms: list[Alarm], decisions: list[Decision], now: datetime) -> "SymptomDecision | None":
        """Le service souffre (alarmes de disponibilité) sans qu'aucune campagne détectée ne
        l'explique : attaque passée inaperçue, ou panne d'exploitation ? Le LLM reçoit alors le
        résumé de TOUTE la fenêtre (DetectionPipeline.overview)."""
        availability = [a for a in alarms if a.kind == AVAILABILITY]
        critical = any(a.rule in _CRITICAL_RULES for a in availability)
        # Seule une alarme critique NOUVELLE passe outre le délai de garde : la même reste 60 s dans
        # la fenêtre glissante et relançait une analyse à chaque cycle.
        fresh = [a.ts for a in availability if a.rule in _CRITICAL_RULES
                 and (self._critical_seen is None or a.ts > self._critical_seen)]
        if len(availability) < _MIN_SYMPTOM_ALARMS and not critical:
            return None
        if any(d.severity >= self.config.threshold for d in decisions):
            return None                                     # une campagne détectée l'explique déjà
        rules = {a.rule for a in availability}
        score, reasons = 40, [f"{len(availability)} alarme(s) de disponibilité sans campagne détectée (+40)"]
        if rules & _CRITICAL_RULES:
            score += 30
            reasons.append("remédiation automatique EN ÉCHEC, bascule PRA demandée (Wazuh 100210 ou journal du moteur) (+30)")
        elif "100211" in rules:
            score += 15
            reasons.append("WAF redémarré par la remédiation automatique (règle 100211) (+15)")
        if len(availability) >= 20:
            score += 10
            reasons.append("alarmes nombreuses (+10)")
        decision = SymptomDecision(min(100, score), reasons, escalate=score >= self.config.threshold)
        previous = self._escalated.get(_SYMPTOM_KEY)
        # Un échec de remédiation est un événement NOUVEAU, pas une simple aggravation : il passe
        # outre le délai de garde.
        if decision.escalate and not fresh and previous \
                and now - previous[0] < timedelta(seconds=self.config.cooldown_s) \
                and decision.severity < previous[1] + self.config.worsening:
            decision.escalate, decision.skipped_because = False, f"déjà analysé à {previous[0]:%H:%M} (délai de garde)"
        elif decision.escalate and not fresh and not self._budget_left(now):
            decision.escalate, decision.skipped_because = False, "plafond d'analyses par minute atteint"
        if decision.escalate:
            self._sent.append(now)
            self._escalated[_SYMPTOM_KEY] = (now, decision.severity, False)
            if fresh:
                self._critical_seen = max(fresh)
        return decision

    def decide_visibility(self, reasons: list[str], now: datetime) -> SymptomDecision:
        """Le détecteur ne voit plus (Loki injoignable, plus aucune requête, lecture tronquée) :
        c'est aussi ce que produit une attaque réussie. Le LLM reçoit ce qui a été vu AVANT la
        coupure, pour qu'un rapport sorte quand même. Une analyse par délai de garde."""
        decision = SymptomDecision(_VISIBILITY_SEVERITY, reasons, escalate=True, trigger="perte_de_visibilite")
        previous = self._escalated.get(VISIBILITY_KEY)
        if previous and now - previous[0] < timedelta(seconds=self.config.cooldown_s):
            decision.escalate, decision.skipped_because = False, f"déjà analysé à {previous[0]:%H:%M} (délai de garde)"
        elif not self._budget_left(now):
            decision.escalate, decision.skipped_because = False, "plafond d'analyses par minute atteint"
        else:
            self._sent.append(now)
            self._escalated[VISIBILITY_KEY] = (now, decision.severity, False)
        return decision

    @staticmethod
    def anomaly_score(decisions: list[Decision]) -> int:
        """Valeur de soc_waf_anomaly_score pour la fenêtre : la gravité la plus haute (0 si rien)."""
        return max((d.severity for d in decisions), default=0)
