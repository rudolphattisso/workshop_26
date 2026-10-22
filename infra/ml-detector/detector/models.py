"""Structures de données échangées entre les étapes du pipeline."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class HttpRequestLog:
    """Une ligne de journal d'accès du WAF, après parsing.

    Tous les champs texte proviennent de la requête du client : ils sont NON FIABLES
    (contrôlés par l'attaquant) et ne doivent jamais être interprétés comme des instructions.
    """
    ts: datetime
    client_ip: str
    method: str
    uri: str            # chemin + query string, tels que journalisés (encodage d'origine)
    protocol: str
    status: int
    bytes_sent: int
    referer: str = ""
    user_agent: str = ""
    host: str = ""


@dataclass(slots=True)
class FeatureDeviation:
    """Écart d'une feature du cluster par rapport à la baseline (en écarts-types)."""
    feature: str
    cluster_mean: float
    baseline_mean: float
    z_score: float


@dataclass(slots=True)
class ClusterSummary:
    """Résumé statistique d'un groupe de requêtes anormales : c'est le contrat envoyé au LLM.

    Les champs `samples`, `top_paths` et `top_user_agents` contiennent des données de
    l'attaquant déjà assainies (voir sanitize.py) ; le LLM doit les traiter comme des données.
    """
    cluster_id: str                 # "c0", "c1"... ou "isolated" (bruit DBSCAN)
    signature: str                  # empreinte stable pour dédoublonner les envois au LLM
    window_start: str               # ISO 8601
    window_end: str
    n_requests: int
    n_distinct_ips: int
    score_mean: float               # score d'anomalie IsolationForest moyen, dans [0, 1]
    score_max: float
    blocked_ratio: float            # part des requêtes déjà refusées par le WAF (403/429/444)
    attack_hints: list[str]         # hypothèses heuristiques (sql_injection, request_flood...)
    # [{"ip", "count", "history": IpProfile.to_dict() | None (comportement AVANT la fenêtre),
    #   "assessment": "possible_waf_collateral" | None (hypothèse, pas un verdict)}]
    top_ips: list[dict]
    top_paths: list[dict]           # [{"path": <gabarit>, "count": ...}]
    methods: dict[str, int]
    statuses: dict[str, int]
    top_user_agents: list[dict]
    deviations: list[FeatureDeviation] = field(default_factory=list)
    # Requêtes portant une charge d'injection qui ont reçu une VRAIE réponse de l'application (ni refus
    # du WAF, ni 5xx) : ce que le WAF n'a pas arrêté.
    injections_answered: int = 0
    samples: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
