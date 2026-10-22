"""Contrat de l'API /analyze : entrée (résumé de cluster du ml-detector) et sortie (rapport).

Entrée : copie du ClusterSummary du ml-detector (infra/ml-detector/detector/models.py).
Les champs texte viennent des requêtes de l'attaquant (déjà assainis côté ml-detector) : ils
sont revalidés ici (tailles bornées) et ne sont jamais interprétés comme des instructions.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

_Str = Field(max_length=600)


class _In(BaseModel):
    model_config = ConfigDict(extra="ignore")


class TopIp(_In):
    ip: str = Field(max_length=64)
    count: int
    history: dict[str, Any] | None = None
    assessment: str | None = Field(default=None, max_length=64)


class ClusterSummary(_In):
    cluster_id: str = Field(max_length=32)
    signature: str = Field(max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    window_start: str = Field(max_length=40)
    window_end: str = Field(max_length=40)
    n_requests: int = Field(ge=0)
    n_distinct_ips: int = Field(ge=0)
    score_mean: float
    score_max: float
    blocked_ratio: float = Field(ge=0, le=1)
    attack_hints: list[str] = Field(max_length=20)
    top_ips: list[TopIp] = Field(max_length=20)
    top_paths: list[dict[str, Any]] = Field(max_length=20)
    methods: dict[str, int]
    statuses: dict[str, int]
    top_user_agents: list[dict[str, Any]] = Field(max_length=20)
    deviations: list[dict[str, Any]] = Field(default_factory=list, max_length=20)
    samples: list[dict[str, Any]] = Field(default_factory=list, max_length=20)
    injections_answered: int = Field(default=0, ge=0)   # injections servies par l'application


class AnalyzeRequest(_In):
    cluster: ClusterSummary
    # Contexte en direct joint par le ml-detector (Prometheus, Wazuh... : detector/context/).
    context: dict[str, Any] = Field(default_factory=dict)


class Heartbeat(_In):
    """Signal de vie du ml-detector (toutes les 30 s)."""
    ts: str = Field(default="", max_length=40)
    statut: str = Field(default="ok", max_length=20)          # "ok" ou "aveugle" (sources injoignables)
    erreurs_consecutives: int = Field(default=0, ge=0)
    derniere_lecture: str | None = Field(default=None, max_length=40)
    file_llm: int = Field(default=0, ge=0)


# -- sortie ---------------------------------------------------------------------------------
class Verdict(str, Enum):
    ATTACK = "attaque"
    WAF_COLLATERAL = "bannissement_collateral_probable"
    FALSE_POSITIVE = "faux_positif_probable"
    OPERATIONS_INCIDENT = "incident_exploitation_probable"     # panne, saturation sans attaque
    UNDETERMINED = "indetermine"


class Confidence(str, Enum):
    LOW = "faible"
    MEDIUM = "moyenne"
    HIGH = "elevee"


class Engine(str, Enum):
    MODSECURITY = "modsecurity"
    BUNKERWEB = "bunkerweb"


class ProposedRule(BaseModel):
    """Règle COMPILÉE par le gateway (rule_compiler.py), prête à copier après les garde-fous."""
    engine: Engine
    content: str = Field(max_length=2000)       # directive(s) à copier-coller
    explanation: str = Field(max_length=1500)   # ce que fait la règle, en clair
    side_effects: str = Field(max_length=800)   # qui d'autre elle peut gêner


class LlmAnalysis(BaseModel):
    """Analyse après compilation des règles : ce que valident les garde-fous et qu'écrit le rapport."""
    verdict: Verdict
    confidence: Confidence
    attack_type: str = Field(max_length=120)
    summary: str = Field(max_length=2000)
    evidence: list[str] = Field(max_length=10)
    impact: str = Field(max_length=800)
    rules: list[ProposedRule] = Field(max_length=6)
    operator_actions: list[str] = Field(max_length=10)
    uncertainties: list[str] = Field(max_length=10)
    ideas_to_review: list[str] = Field(default_factory=list, max_length=5)   # « Pistes à expertiser »


# -- grammaire de règles : ce que le LLM DÉCRIT (le gateway écrit la syntaxe) ------------------------
# Le vocabulaire est imposé par le schéma JSON : le modèle ne peut pas inventer une variable, un
# opérateur ou un réglage, ni faire une faute de guillemets. Il compose librement les conditions.
class ModSecVariable(str, Enum):
    REQUEST_FILENAME = "REQUEST_FILENAME"    # chemin sans paramètres (/api/payments)
    REQUEST_URI = "REQUEST_URI"              # chemin + paramètres
    QUERY_STRING = "QUERY_STRING"
    REQUEST_METHOD = "REQUEST_METHOD"
    REMOTE_ADDR = "REMOTE_ADDR"              # IP du client
    ARGS_GET = "ARGS_GET"                    # un paramètre d'URL (name obligatoire)
    ARGS_GET_NAMES = "ARGS_GET_NAMES"        # noms des paramètres d'URL
    ARGS = "ARGS"                            # un paramètre d'URL ou du corps (name obligatoire)
    ARGS_NAMES = "ARGS_NAMES"
    REQUEST_HEADERS = "REQUEST_HEADERS"      # un en-tête (name obligatoire : User-Agent, Referer...)


class ModSecOperator(str, Enum):
    EQUALS = "equals"
    BEGINS_WITH = "begins_with"
    ENDS_WITH = "ends_with"
    CONTAINS = "contains"
    REGEX = "regex"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    IP_IN = "ip_in"                          # IP ou réseaux séparés par des virgules
    ABSENT = "absent"                        # l'en-tête ou le paramètre n'existe pas (value ignorée)


class Condition(BaseModel):
    variable: ModSecVariable
    name: str | None = Field(default=None, max_length=64)    # paramètre ou en-tête visé
    operator: ModSecOperator
    value: str = Field(default="", max_length=300)
    negate: bool = False                                      # « ne correspond PAS »


class ModSecRuleSpec(BaseModel):
    """Toutes les conditions doivent être vraies (ET) pour déclencher l'action."""
    conditions: list[Condition] = Field(min_length=1, max_length=4)
    action: str = Field(pattern=r"^(deny|log_only)$")         # log_only = détection seule (pass,log)
    message: str = Field(max_length=100)
    explanation: str = Field(max_length=600)
    side_effects: str = Field(max_length=400)


class BunkerWebSettingName(str, Enum):
    USE_ANTIBOT = "USE_ANTIBOT"
    ANTIBOT_URI = "ANTIBOT_URI"
    ANTIBOT_TIME_RESOLVE = "ANTIBOT_TIME_RESOLVE"
    ANTIBOT_TIME_VALID = "ANTIBOT_TIME_VALID"
    USE_LIMIT_REQ = "USE_LIMIT_REQ"
    LIMIT_REQ_URL = "LIMIT_REQ_URL"
    LIMIT_REQ_RATE = "LIMIT_REQ_RATE"
    USE_LIMIT_CONN = "USE_LIMIT_CONN"
    LIMIT_CONN_MAX_HTTP1 = "LIMIT_CONN_MAX_HTTP1"
    LIMIT_CONN_MAX_HTTP2 = "LIMIT_CONN_MAX_HTTP2"
    USE_BAD_BEHAVIOR = "USE_BAD_BEHAVIOR"
    BAD_BEHAVIOR_STATUS_CODES = "BAD_BEHAVIOR_STATUS_CODES"
    BAD_BEHAVIOR_THRESHOLD = "BAD_BEHAVIOR_THRESHOLD"
    BAD_BEHAVIOR_COUNT_TIME = "BAD_BEHAVIOR_COUNT_TIME"
    BAD_BEHAVIOR_BAN_TIME = "BAD_BEHAVIOR_BAN_TIME"
    USE_BLACKLIST = "USE_BLACKLIST"
    BLACKLIST_IP = "BLACKLIST_IP"
    BLACKLIST_USER_AGENT = "BLACKLIST_USER_AGENT"
    BLACKLIST_URI = "BLACKLIST_URI"
    USE_DNSBL = "USE_DNSBL"


class BunkerWebSetting(BaseModel):
    setting: BunkerWebSettingName
    suffix: int | None = Field(default=None, ge=1, le=9)     # LIMIT_REQ_URL_2 + LIMIT_REQ_RATE_2 vont ensemble
    value: str = Field(max_length=300)


class BunkerWebChangeSpec(BaseModel):
    settings: list[BunkerWebSetting] = Field(min_length=1, max_length=6)
    explanation: str = Field(max_length=600)
    side_effects: str = Field(max_length=400)


class LlmOutput(BaseModel):
    """Ce que le LLM doit produire (son JSON Schema est imposé à Ollama). Longueurs volontairement
    courtes : chaque token généré coûte ~45 ms avec la contrainte de format."""
    verdict: Verdict
    confidence: Confidence
    attack_type: str = Field(max_length=120)
    summary: str = Field(max_length=1200)
    evidence: list[str] = Field(max_length=6)
    impact: str = Field(max_length=500)
    modsecurity_rules: list[ModSecRuleSpec] = Field(max_length=3)
    bunkerweb_changes: list[BunkerWebChangeSpec] = Field(max_length=3)
    ideas_to_review: list[str] = Field(max_length=3)          # idées hors grammaire : relues par un expert
    operator_actions: list[str] = Field(max_length=6)
    uncertainties: list[str] = Field(max_length=5)


class RejectedRule(BaseModel):
    engine: str
    reason: str


class Timings(BaseModel):
    """Temps d'une analyse, en secondes. Les champs détaillés viennent d'Ollama quand il les fournit."""
    total_s: float
    rag_s: float                         # recherche dans la base de connaissances
    queue_s: float                       # attente du GPU (une autre analyse en cours)
    llm_s: float                         # appel au LLM, de bout en bout
    load_s: float | None = None          # chargement du modèle en mémoire (premier appel, changement de modèle)
    prompt_tokens: int | None = None
    prompt_s: float | None = None        # lecture du prompt
    output_tokens: int | None = None
    generation_s: float | None = None    # écriture de la réponse
    tokens_per_s: float | None = None
    other_s: float | None = None         # non détaillé par Ollama : surtout la contrainte de sortie JSON
    truncated: bool | None = None        # prompt coupé par la taille de contexte (num_ctx)


class AnalysisReport(BaseModel):
    """Réponse de /analyze : analyse revalidée, règles filtrées, emplacement du fichier de règles."""
    signature: str
    cluster_id: str
    generated_at: str
    model: str
    degraded: bool                       # True : LLM indisponible ou réponse invalide (analyse minimale)
    analysis: LlmAnalysis
    rejected_rules: list[RejectedRule]
    knowledge_used: list[str]            # doc_id des passages du RAG fournis au LLM
    rules_file: str | None
    # Contrôle de cohérence (consistency.py) : verdict contredit par les mesures, injection probable.
    warnings: list[str] = Field(default_factory=list)
    timings: Timings | None = None
    # Règles identiques à une règle proposée dans un rapport récent : citées, pas recopiées.
    already_proposed: list[dict] = Field(default_factory=list)


def llm_output_schema() -> dict:
    return LlmOutput.model_json_schema()
