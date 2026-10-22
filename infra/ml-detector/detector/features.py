"""Extraction de features à partir des requêtes HTTP du WAF.

Deux familles :
  - features PAR REQUÊTE : forme de l'URI, caractères spéciaux, entropie, motifs d'injection,
    méthode, statut, user-agent, rareté du chemin par rapport à la baseline ;
  - features PAR IP sur une fenêtre glissante (passée) : débit, chemins distincts, taux
    d'erreurs, échecs d'authentification. Elles révèlent flood, scan et force brute, invisibles
    requête par requête.

Les grandeurs à queue lourde (longueurs, compteurs) passent par log1p pour que quelques valeurs
extrêmes n'écrasent pas le reste.
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict, deque
from datetime import timedelta
from urllib.parse import parse_qsl, unquote_plus, urlsplit

import numpy as np

from .models import HttpRequestLog

# --- Motifs d'attaque (appliqués sur l'URI décodée, en minuscules) -------------------------
SQLI_PATTERNS = [
    r"\bunion\b[\s\S]{0,40}\bselect\b",
    r"\bselect\b[\s\S]{0,80}\bfrom\b",
    r"'\s*(or|and)\s*'?\d*'?\s*=",
    r"\b(or|and)\b\s+\d+\s*=\s*\d+",
    r"\b(sleep|benchmark|pg_sleep)\s*\(",
    r"\bwaitfor\s+delay\b",
    r";\s*(drop|delete|insert|update|truncate)\b",
    r"(--|#)\s*$",
    r"\binformation_schema\b",
]
XSS_PATTERNS = [
    r"<\s*script",
    r"javascript\s*:",
    r"\bon(error|load|mouseover|focus|click|toggle)\s*=",
    r"<\s*(img|svg|iframe|body|object|embed|details)\b",
    r"document\s*\.\s*(cookie|location|domain)",
    r"\balert\s*\(",
]
TRAVERSAL_PATTERNS = [
    r"\.\./", r"\.\.\\", r"/etc/(passwd|shadow|hosts)", r"(win|boot)\.ini", r"/proc/self/",
]
CMDI_PATTERNS = [
    r"[;|&]\s*(ls|cat|id|whoami|uname|wget|curl|nc|bash|sh|ping)\b",
    r"`[^`]+`",
    r"\$\([^)]+\)",
]
SCANNER_PATH = re.compile(
    r"(/\.env|/\.git|/\.svn|wp-admin|wp-login|xmlrpc|phpmyadmin|\.php\b|/admin\b|/actuator|"
    r"/server-status|\.bak\b|\.sql\b|\.old\b|/cgi-bin|/config\.|/backup)",
    re.IGNORECASE,
)
TOOL_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb|ffuf|wfuzz|nuclei|hydra|"
    r"curl|wget|python-requests|python-urllib|aiohttp|httpx|go-http-client|libwww|java/)",
    re.IGNORECASE,
)
SPECIAL_CHARS = set("<>'\"`;(){}[]|\\$*!^~@#")

_SQLI = [re.compile(p) for p in SQLI_PATTERNS]
_XSS = [re.compile(p) for p in XSS_PATTERNS]
_TRAV = [re.compile(p) for p in TRAVERSAL_PATTERNS]
_CMDI = [re.compile(p) for p in CMDI_PATTERNS]

_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_NUM = re.compile(r"^\d+$")
_TOKEN = re.compile(r"^[A-Za-z0-9_\-=]{24,}$")

# Statuts produits par le WAF (refus, limitation de débit, coupure) et non par l'application.
BLOCKED_STATUSES = {403, 429, 444}

# Indépendance vis-à-vis du WAF : le but est de trouver ce qu'il NE voit PAS, donc aucune feature
# ne doit encoder sa décision. Pas de « status_blocked » ; pour une réponse du WAF, le statut et
# la taille (la page de blocage BunkerWeb fait 69 298 octets) sont masqués (cf. app_status).
REQUEST_FEATURES = [
    "uri_len", "query_len", "n_params", "path_depth",
    "special_char_ratio", "query_entropy", "pct_encoded_ratio",
    "sqli_hits", "xss_hits", "traversal_hits", "cmdi_hits", "scanner_path",
    "method_get", "method_post", "method_other",
    "status_2xx", "status_3xx", "status_4xx", "status_5xx",   # réponse de l'APPLICATION
    "ua_len", "ua_tool", "ua_empty",
    "path_rarity",
    "bytes_log",           # taille des réponses 2xx : export anormalement lourd (DDoS applicatif)
]
WINDOW_FEATURES = [
    "ip_req_per_min", "ip_distinct_paths", "ip_error_ratio", "ip_auth_failures",
    "ip_errors_per_min",   # erreurs applicatives (401, 404, 422, 5xx...) par minute
    # DDoS distribué : chaque IP reste sous les seuils du WAF, seule la FOULE est anormale.
    # Nombre d'IP « automatisées » (cf. _AUTOMATED_*) visant le même endpoint sur la fenêtre ;
    # 0 pour une IP qui ne l'est pas, pour ne pas signaler les vrais clients pris dans l'attaque.
    "endpoint_sessionless_ips",
]
# IP « automatisée » sur la fenêtre : assez de requêtes, sur peu de chemins distincts, sans
# aucune action métier réussie (connexion, paiement : POST/PUT/PATCH/DELETE en 2xx).
_AUTOMATED_MIN_REQUESTS = 5
# Une foule commence à 5 IP : en dessous, c'est le comportement de chaque IP qui compte (features
# par IP). Sans ce minimum, une seule IP scriptée sortait de l'enveloppe (baseline sans foule).
_CROWD_MIN_IPS = 5
_AUTOMATED_MAX_PATH_RATIO = 0.3
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def app_status(status: int) -> int:
    """Statut vu par le modèle : une réponse du WAF est masquée et remplacée par la réponse la
    plus courante (200). La mettre à 0 créerait une combinaison inédite que le modèle apprendrait
    à repérer, ce qui reviendrait à réutiliser la décision du WAF."""
    return 200 if status in BLOCKED_STATUSES else status
FEATURE_NAMES = REQUEST_FEATURES + WINDOW_FEATURES


def decode_uri(uri: str, rounds: int = 2) -> str:
    """Décode l'encodage URL (deux passes pour le double encodage %252e) et passe en minuscules."""
    for _ in range(rounds):
        decoded = unquote_plus(uri)
        if decoded == uri:
            break
        uri = decoded
    return uri.lower()


def path_template(uri: str) -> str:
    """Gabarit de chemin : identifiants remplacés pour regrouper /api/payments/<uuid>."""
    path = urlsplit(uri).path or "/"
    path = _UUID.sub("{uuid}", path)
    segments = []
    for seg in path.split("/"):
        if _NUM.match(seg):
            seg = "{n}"
        elif _TOKEN.match(seg):
            seg = "{token}"
        segments.append(seg)
    return "/".join(segments)[:120]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _hits(patterns: list[re.Pattern], text: str) -> int:
    return sum(1 for p in patterns if p.search(text))


def attack_signals(uri: str) -> dict[str, int]:
    """Compteurs de motifs d'injection (aussi utilisés pour les indices envoyés au LLM)."""
    decoded = decode_uri(uri)
    return {
        "sqli_hits": _hits(_SQLI, decoded),
        "xss_hits": _hits(_XSS, decoded),
        "traversal_hits": _hits(_TRAV, decoded),
        "cmdi_hits": _hits(_CMDI, decoded),
        "scanner_path": int(bool(SCANNER_PATH.search(decoded))),
    }


class FeatureExtractor:
    """Transforme une liste de HttpRequestLog en matrice numérique (lignes = requêtes).

    `fit` apprend sur la baseline la fréquence des gabarits de chemins (feature path_rarity) ;
    `transform` calcule toutes les features. L'ordre des lignes en sortie est celui de l'entrée.
    """

    def __init__(self, window_seconds: int = 60, auth_paths: tuple[str, ...] = ("/api/auth/login",)):
        self.window_seconds = window_seconds
        self.auth_paths = tuple(auth_paths)
        self.path_counts: dict[str, int] = {}
        self.median_bytes: float = 0.0          # taille substituée à celle d'une réponse non 2xx
        # IP déjà « automatisées » en temps normal (sondes de monitoring...) : exclues du comptage
        # de foule, sinon une sonde qui interroge le même endpoint qu'un botnet est signalée avec
        # lui. Apprises sur la baseline, listées dans le .meta.json pour relecture par l'opérateur.
        self.known_automated_ips: frozenset[str] = frozenset()

    @property
    def feature_names(self) -> list[str]:
        return list(FEATURE_NAMES)

    def fit(self, records: list[HttpRequestLog]) -> "FeatureExtractor":
        self.path_counts = dict(Counter(path_template(r.uri) for r in records))
        self.median_bytes = float(np.median([r.bytes_sent for r in records])) if records else 0.0
        self.known_automated_ips = frozenset()
        automated: set[str] = set()
        self._window_features(sorted(records, key=lambda r: r.ts), automated_out=automated)
        self.known_automated_ips = frozenset(automated)
        return self

    def transform(self, records: list[HttpRequestLog]) -> np.ndarray:
        X = np.zeros((len(records), len(FEATURE_NAMES)), dtype=np.float64)
        n_req = len(REQUEST_FEATURES)
        for i, rec in enumerate(records):
            X[i, :n_req] = self._request_features(rec)
        X[:, n_req:] = self._window_features(records)
        return X

    # -- par requête --------------------------------------------------------------------
    def _request_features(self, rec: HttpRequestLog) -> list[float]:
        split = urlsplit(rec.uri)
        query = split.query
        decoded = decode_uri(rec.uri)
        decoded_query = decode_uri(query)
        signals = attack_signals(rec.uri)
        method = rec.method.upper()
        status = app_status(rec.status)
        ua = rec.user_agent
        n_special = sum(1 for c in decoded if c in SPECIAL_CHARS)

        return [
            math.log1p(len(rec.uri)),
            math.log1p(len(query)),
            min(len(parse_qsl(query, keep_blank_values=True)), 50),
            sum(1 for s in split.path.split("/") if s),
            n_special / max(len(decoded), 1),
            shannon_entropy(decoded_query),
            rec.uri.count("%") / max(len(rec.uri), 1),
            signals["sqli_hits"],
            signals["xss_hits"],
            signals["traversal_hits"],
            signals["cmdi_hits"],
            signals["scanner_path"],
            float(method == "GET"),
            float(method == "POST"),
            float(method not in ("GET", "POST")),
            float(200 <= status < 300),
            float(300 <= status < 400),
            float(400 <= status < 500),
            float(status >= 500),
            math.log1p(len(ua)),
            float(bool(TOOL_UA.search(ua))),
            float(not ua),
            1.0 / (1.0 + self.path_counts.get(path_template(rec.uri), 0)),
            # Réponses réussies seulement : BunkerWeb remplace les pages d'erreur (401, 502, 503...)
            # et de blocage par les siennes (~69 Ko), dont la taille ne dit rien de la requête.
            math.log1p(rec.bytes_sent if 200 <= rec.status < 300 else self.median_bytes),
        ]

    # -- par IP, fenêtre glissante passée ------------------------------------------------
    def _window_features(self, records: list[HttpRequestLog], automated_out: set | None = None) -> np.ndarray:
        """Pour chaque requête : état de son IP (et de la foule automatisée sur son endpoint)
        sur [ts - fenêtre, ts], calculé en un passage."""
        out = np.zeros((len(records), len(WINDOW_FEATURES)), dtype=np.float64)
        window = timedelta(seconds=self.window_seconds)
        per_min = 60.0 / self.window_seconds

        events: dict[str, deque] = defaultdict(deque)       # ip -> (ts, gabarit, erreur, échec auth, action)
        paths: dict[str, Counter] = defaultdict(Counter)
        errors: Counter = Counter()
        auth_fail: Counter = Counter()
        actions: Counter = Counter()
        crowd: dict[str, deque] = defaultdict(deque)        # gabarit -> (ts, ip) des IP automatisées
        crowd_ips: dict[str, Counter] = defaultdict(Counter)

        for i in sorted(range(len(records)), key=lambda k: records[k].ts):
            rec = records[i]
            ip = rec.client_ip
            q = events[ip]
            while q and q[0][0] < rec.ts - window:
                _, old_tpl, old_err, old_auth, old_action = q.popleft()
                paths[ip][old_tpl] -= 1
                if paths[ip][old_tpl] == 0:
                    del paths[ip][old_tpl]
                errors[ip] -= old_err
                auth_fail[ip] -= old_auth
                actions[ip] -= old_action

            tpl = path_template(rec.uri)
            is_err = int(app_status(rec.status) >= 400)
            # 401 seulement : un 403 sur la page de login vient du WAF (IP bannie), pas d'un mot de
            # passe refusé ; le compter faisait passer les clients bannis par collatéral pour de la force brute.
            is_auth_fail = int(rec.status == 401 and urlsplit(rec.uri).path in self.auth_paths)
            status = app_status(rec.status)
            is_action = int(rec.method.upper() in _WRITE_METHODS and 200 <= status < 300)
            q.append((rec.ts, tpl, is_err, is_auth_fail, is_action))
            paths[ip][tpl] += 1
            errors[ip] += is_err
            auth_fail[ip] += is_auth_fail
            actions[ip] += is_action

            count = len(q)
            automated = (count >= _AUTOMATED_MIN_REQUESTS and actions[ip] == 0
                         and len(paths[ip]) / count <= _AUTOMATED_MAX_PATH_RATIO)
            if automated and automated_out is not None:
                automated_out.add(ip)
            automated = automated and ip not in self.known_automated_ips
            c, c_ips = crowd[tpl], crowd_ips[tpl]
            while c and c[0][0] < rec.ts - window:
                _, old_ip = c.popleft()
                c_ips[old_ip] -= 1
                if c_ips[old_ip] == 0:
                    del c_ips[old_ip]
            if automated:
                c.append((rec.ts, ip))
                c_ips[ip] += 1

            out[i] = [
                math.log1p(count * per_min),
                math.log1p(len(paths[ip])),
                errors[ip] / count,
                math.log1p(auth_fail[ip]),
                math.log1p(errors[ip] * per_min),
                math.log1p(len(c_ips)) if automated and len(c_ips) >= _CROWD_MIN_IPS else 0.0,
            ]
        return out
