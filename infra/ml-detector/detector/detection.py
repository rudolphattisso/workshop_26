"""Détection : IsolationForest + enveloppe (score par requête) puis DBSCAN (regroupement).

Pourquoi :
  - IsolationForest est non supervisé : il apprend la forme du trafic normal (baseline) et
    note chaque requête dans [0, 1] (plus c'est haut, plus elle est facile à isoler = rare) ;
    l'enveloppe de la baseline couvre ce qu'il voit mal (valeurs hors de la plage apprise) ;
  - DBSCAN regroupe ensuite les requêtes anormales qui se ressemblent. On passe de
    « 3 000 requêtes suspectes » à « 2 campagnes : un scan et une injection SQL », ce qui est
    le bon niveau de résumé pour le LLM et l'opérateur. Les points isolés (bruit DBSCAN)
    forment un groupe « isolated ».
"""
from __future__ import annotations

import hashlib
import math
from collections import Counter
from dataclasses import dataclass

import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest

from .config import DetectorConfig
from .features import BLOCKED_STATUSES, FEATURE_NAMES, FeatureExtractor, path_template
from .ip_history import IpHistory, IpProfile
from .models import ClusterSummary, FeatureDeviation, HttpRequestLog
from .sanitize import sanitize_untrusted

NOT_ANOMALOUS = -2      # étiquette des requêtes normales (DBSCAN utilise -1 pour le bruit)
_STD_FLOOR = 0.1        # écart-type plancher (features constantes en baseline) : z-scores lisibles
_FLOOD_FLOOR = math.log1p(60)   # indice request_flood : au moins 60 req (ou erreurs) / min / IP
_CROWD_FLOOR = math.log1p(10)   # indice distributed_flood : au moins 10 IP automatisées sur un endpoint
_COLLATERAL_MIN_HISTORY = 10    # requêtes passées minimales pour juger qu'une IP « était saine »


def _binary(v):
    return np.minimum(v, 1.0)


def _log_scaled(cap: float):
    """Pour une feature déjà en log1p : ramène [0, log1p(cap)] dans [0, 1], plafonné."""
    return lambda v: np.clip(v / math.log1p(cap), 0.0, 1.0)


# Espace de clustering = « signature de comportement ».
# IsolationForest utilise les 30 features ; DBSCAN seulement celles qui décrivent le TYPE
# d'attaque. Celles qui varient à l'intérieur d'une même campagne (longueurs, entropie, taille
# de réponse) sont écartées, sinon deux SQLi aux charges différentes s'éloigneraient pour rien.
# Chaque feature est ramenée dans [0, 1] puis multipliée par un poids <= 1 : sa contribution
# à la distance est bornée par ce poids, ce qui rend eps lisible (eps 0.5 = deux requêtes
# diffèrent de moins d'une demi-caractéristique).
#          (feature,            transformation,     poids)  # rôle
SIGNATURE = [
    ("sqli_hits",          _binary,             1.0),  # présence de motifs SQLi
    ("xss_hits",           _binary,             1.0),  # présence de motifs XSS
    ("traversal_hits",     _binary,             1.0),  # présence de ../, /etc/passwd...
    ("cmdi_hits",          _binary,             1.0),  # présence d'injection de commande
    # Poids réduits : au sein d'un même scan ou d'une même injection, certaines URI ont un
    # chemin connu (/api/payments?limit=<charge>) et d'autres non (/api/payments/<charge>) ;
    # ces deux features seules ne doivent pas couper la campagne en deux (0.4² + 0.3² = 0.5²).
    ("scanner_path",       _binary,             0.4),  # chemin typique de scan (/.env, /wp-admin...)
    ("path_rarity",        _binary,             0.3),  # chemin jamais vu dans la baseline
    ("method_post",        _binary,             0.7),  # POST (force brute) vs GET (scan, flood)
    ("ip_req_per_min",     _log_scaled(600),    1.0),  # débit de l'IP, 1.0 = 600 req/min (10 r/s)
    ("ip_distinct_paths",  _log_scaled(50),     1.0),  # nb de chemins distincts : scan
    ("ip_auth_failures",   _log_scaled(30),     1.0),  # échecs de login sur la fenêtre : force brute
    ("endpoint_sessionless_ips", _log_scaled(100), 1.0),  # foule d'IP automatisées : DDoS distribué
    ("ua_tool",            _binary,             0.5),  # outil automatisé (sqlmap, gobuster, curl...)
    # Le statut (applicatif, la décision du WAF n'est jamais utilisée) pèse peu : il ne doit pas
    # suffire à couper une campagne en deux.
    ("status_4xx",         _binary,             0.4),  # erreur client (404 de scan, 401 de login)
]
_SIGNATURE_COLS = [FEATURE_NAMES.index(name) for name, _, _ in SIGNATURE]


def signature_space(X: np.ndarray) -> np.ndarray:
    """Projette la matrice de features dans l'espace de clustering, chaque colonne dans [0, poids]."""
    return np.column_stack([
        fn(X[:, j]) * weight for j, (_, fn, weight) in zip(_SIGNATURE_COLS, SIGNATURE)
    ])


# Enveloppe de la baseline : features pour lesquelles « dépasser tout ce qui a été vu en
# temps normal » est en soi un signal. Complète IsolationForest, qui n'extrapole pas : une
# valeur hors de la plage d'entraînement tombe dans la même feuille que les points extrêmes
# de la baseline (480 req/min « ressemble » à la sonde à 36 req/min), et une feature toujours
# nulle à l'entraînement (motifs SQLi) n'est jamais utilisée pour couper.
# Les features de forme (longueurs, entropie, user-agent) n'y sont PAS : un navigateur au
# user-agent un peu plus long n'a rien de suspect ; IsolationForest s'en charge. Exception :
# la taille de réponse, au-delà de 3 fois la plus grosse vue (export coûteux, DDoS applicatif).
# ua_tool non plus : une intégration marchand légitime utilise python-requests, et le filtre
# d'entraînement retire ces UA de la baseline (max = 0) => chacune de ses requêtes dépassait.
ENVELOPE_FEATURES = [
    "sqli_hits", "xss_hits", "traversal_hits", "cmdi_hits", "scanner_path",
    "path_rarity", "ip_req_per_min", "ip_distinct_paths", "ip_auth_failures", "ip_errors_per_min",
    "endpoint_sessionless_ips", "bytes_log",
]
_ENVELOPE_COLS = [FEATURE_NAMES.index(name) for name in ENVELOPE_FEATURES]
_LOG_FEATURES = ("ip_req_per_min", "ip_distinct_paths", "ip_auth_failures", "ip_errors_per_min",
                 "endpoint_sessionless_ips", "bytes_log")
_ENVELOPE_LOG_IDX = [k for k, name in enumerate(ENVELOPE_FEATURES) if name in _LOG_FEATURES]
# Avec le plancher _STD_FLOOR, une feature constante en baseline (0) dépasse de 10 écarts dès qu'elle vaut 1.


class AnomalyDetector:
    """Deux détecteurs non supervisés appris sur la baseline, ramenés au même seuil :

      - IsolationForest (30 features) : combinaisons inhabituelles ;
      - enveloppe : dépassement du maximum observé en baseline de plus de `envelope_z`
        écarts-types, sur ENVELOPE_FEATURES.
    Score final = max des deux, dans [0, 1[ ; une requête est anormale si score > threshold.
    """

    def __init__(self, config: DetectorConfig):
        self.config = config
        self.forest = IsolationForest(
            n_estimators=config.n_estimators,
            contamination="auto",
            random_state=config.random_state,
            n_jobs=1,
        )
        self.threshold: float = 1.0
        self.mean: np.ndarray | None = None
        self.std: np.ndarray | None = None
        self.p99: np.ndarray | None = None
        self.env_max: np.ndarray | None = None
        self.env_std: np.ndarray | None = None

    def fit(self, X_baseline: np.ndarray) -> "AnomalyDetector":
        self.forest.fit(X_baseline)
        self.mean = X_baseline.mean(axis=0)
        self.std = np.maximum(X_baseline.std(axis=0), _STD_FLOOR)
        self.p99 = np.quantile(X_baseline, 0.99, axis=0)
        env = X_baseline[:, _ENVELOPE_COLS]
        self.env_max = env.max(axis=0)
        self.env_std = np.maximum(env.std(axis=0), _STD_FLOOR)
        # Features en log1p : envelope_z écarts-types ne doivent pas dépasser un facteur
        # envelope_max_factor au-dessus du max (log(a·F) - log(a) = log F).
        self.env_std[_ENVELOPE_LOG_IDX] = np.minimum(
            self.env_std[_ENVELOPE_LOG_IDX], math.log(self.config.envelope_max_factor) / self.config.envelope_z)
        self.threshold = float(np.quantile(self.forest_score(X_baseline), self.config.threshold_quantile))
        return self

    def forest_score(self, X: np.ndarray) -> np.ndarray:
        """Score d'anomalie de l'article original d'IsolationForest, dans ]0, 1[."""
        return -self.forest.score_samples(X)

    def envelope_excess(self, X: np.ndarray) -> np.ndarray:
        """Plus grand dépassement du maximum de la baseline, en écarts-types (0 si dans l'enveloppe)."""
        return ((X[:, _ENVELOPE_COLS] - self.env_max) / self.env_std).max(axis=1).clip(min=0)

    def envelope_score(self, X: np.ndarray) -> np.ndarray:
        """Dépassement converti sur l'échelle du score : envelope_z écarts-types => seuil exact,
        au-delà le score tend vers 1."""
        excess, t, z = self.envelope_excess(X), self.threshold, self.config.envelope_z
        return np.where(excess <= z, t * excess / z, t + (1 - t) * (1 - np.exp(-(excess - z) / z)))

    def score(self, X: np.ndarray) -> np.ndarray:
        return np.maximum(self.forest_score(X), self.envelope_score(X))


@dataclass
class DetectionResult:
    scores: np.ndarray            # score par requête
    is_anomaly: np.ndarray        # bool par requête
    labels: np.ndarray            # NOT_ANOMALOUS, -1 (isolée) ou n° de cluster
    clusters: list[ClusterSummary]

    @property
    def max_score(self) -> float:
        return float(self.scores.max()) if len(self.scores) else 0.0


class DetectionPipeline:
    """Assemble extraction, score et clustering. Un pipeline = un modèle entraîné."""

    def __init__(self, extractor: FeatureExtractor, detector: AnomalyDetector, config: DetectorConfig):
        self.extractor = extractor
        self.detector = detector
        self.config = config

    def features(self, records: list[HttpRequestLog]) -> np.ndarray:
        return self.extractor.transform(records)

    def analyze(self, records: list[HttpRequestLog], X: np.ndarray | None = None,
                history: IpHistory | None = None) -> DetectionResult:
        """Analyse une fenêtre de requêtes.

        `X` peut être fourni s'il a été calculé avec plus d'historique que la fenêtre (les
        features par IP regardent le passé) : c'est le cas en fonctionnement continu.
        `history` (requêtes précédant la fenêtre) ajoute aux IP des clusters leur profil passé
        et l'hypothèse « bannissement collatéral » ; le mettre à jour APRÈS l'analyse.
        """
        if X is None:
            X = self.features(records)
        if len(records) == 0:
            empty = np.zeros(0)
            return DetectionResult(empty, empty.astype(bool), empty.astype(int), [])

        scores = self.detector.score(X)
        is_anomaly = scores > self.detector.threshold
        labels = np.full(len(records), NOT_ANOMALOUS, dtype=int)

        idx = np.flatnonzero(is_anomaly)
        if len(idx):
            if len(idx) >= self.config.dbscan_min_samples:
                labels[idx] = self._cluster(signature_space(X[idx]))
            else:
                labels[idx] = -1

        clusters = [
            self._summarize(label, np.flatnonzero(labels == label), records, X, scores, history)
            for label in sorted(set(labels[idx].tolist()))
        ]
        clusters.sort(key=lambda c: c.n_requests, reverse=True)
        return DetectionResult(scores, is_anomaly, labels, clusters)

    def overview(self, records: list[HttpRequestLog], X: np.ndarray | None = None,
                 history: IpHistory | None = None, window: tuple[str, str] = ("", "")) -> ClusterSummary:
        """Résumé de TOUTE la fenêtre (pas seulement des requêtes anormales), pour une escalade
        déclenchée par un symptôme (alarmes de disponibilité) qu'aucune campagne n'explique.
        Fenêtre sans requête (le service ne répond plus du tout) : résumé vide, les alarmes parlent."""
        if not records:
            return ClusterSummary(cluster_id="fenetre", signature="symptomevide", window_start=window[0],
                                  window_end=window[1], n_requests=0, n_distinct_ips=0, score_mean=0.0, score_max=0.0,
                                  blocked_ratio=0.0, attack_hints=["service_degradation"], top_ips=[], top_paths=[],
                                  methods={}, statuses={}, top_user_agents=[])
        X = self.features(records) if X is None else X
        summary = self._summarize(0, np.arange(len(records)), records, X, self.detector.score(X), history)
        summary.cluster_id = "fenetre"
        summary.signature = f"symptome{summary.signature}"
        summary.attack_hints = [h for h in summary.attack_hints if h != "unknown_anomaly"] + ["service_degradation"]
        return summary

    def _cluster(self, S: np.ndarray) -> np.ndarray:
        """DBSCAN sur les points distincts, pondérés par leur nombre.

        Un botnet produit des milliers de requêtes quasi identiques dans l'espace signature :
        chacune est voisine de toutes les autres et DBSCAN devient quadratique (20 000 requêtes
        anormales : 17 s ; 60 000 par minute en DDoS : plus que la fenêtre). Arrondir à 0,01
        (négligeable devant eps = 0,5) puis regrouper les doublons donne le même résultat sur
        quelques centaines de points.
        """
        unique, inverse, counts = np.unique(np.round(S, 2), axis=0, return_inverse=True, return_counts=True)
        unique_labels = DBSCAN(eps=self.config.dbscan_eps,
                               min_samples=self.config.dbscan_min_samples).fit_predict(unique, sample_weight=counts)
        return unique_labels[inverse.ravel()]

    # -- résumé d'un cluster --------------------------------------------------------------
    def _summarize(self, label: int, idx: np.ndarray, records: list[HttpRequestLog],
                   X: np.ndarray, scores: np.ndarray, history: IpHistory | None) -> ClusterSummary:
        recs = [records[i] for i in idx]
        Xc = X[idx]
        max_len = self.config.sanitize_max_len
        hints = self._attack_hints(Xc, recs)
        window_start = min(r.ts for r in recs)

        ip_counts = Counter(r.client_ip for r in recs)
        top_ips = []
        for ip, count in ip_counts.most_common(5):
            entry = {"ip": ip, "count": count, "history": None, "assessment": None}
            if history is not None:
                profile = history.profile(ip, before=window_start)
                entry["history"] = profile.to_dict() if profile else None
                own = np.array([r.client_ip == ip for r in recs])
                if self._looks_like_waf_collateral(Xc[own], [r for r in recs if r.client_ip == ip], profile):
                    entry["assessment"] = "possible_waf_collateral"
            top_ips.append(entry)
        collateral = sum(e["count"] for e in top_ips if e["assessment"])
        if collateral * 2 >= len(recs):
            hints = [h for h in hints if h != "unknown_anomaly"] + ["possible_waf_collateral"]
        paths = Counter(path_template(r.uri) for r in recs)

        z_mean = (Xc.mean(axis=0) - self.detector.mean) / self.detector.std
        top = np.argsort(-np.abs(z_mean))[:5]
        deviations = [
            FeatureDeviation(FEATURE_NAMES[j], round(float(Xc[:, j].mean()), 3),
                             round(float(self.detector.mean[j]), 3), round(float(z_mean[j]), 1))
            for j in top
        ]

        # Échantillons : les plus anormaux d'abord, assainis (données de l'attaquant).
        order = idx[np.argsort(-scores[idx])][: self.config.max_samples_per_cluster]
        samples = [
            {
                "ts": records[i].ts.isoformat(),
                "ip": records[i].client_ip,
                "method": sanitize_untrusted(records[i].method, 16),
                "uri": sanitize_untrusted(records[i].uri, max_len),
                "status": records[i].status,
                "user_agent": sanitize_untrusted(records[i].user_agent, 120),
                "score": round(float(scores[i]), 3),
            }
            for i in order
        ]

        top_paths = [{"path": sanitize_untrusted(p, max_len), "count": c} for p, c in paths.most_common(5)]
        signature_src = "|".join(sorted(hints) + [p["path"] for p in top_paths[:2]])

        return ClusterSummary(
            cluster_id="isolated" if label == -1 else f"c{label}",
            signature=hashlib.sha1(signature_src.encode()).hexdigest()[:12],
            window_start=window_start.isoformat(),
            window_end=max(r.ts for r in recs).isoformat(),
            n_requests=len(recs),
            n_distinct_ips=len({r.client_ip for r in recs}),
            score_mean=round(float(scores[idx].mean()), 3),
            score_max=round(float(scores[idx].max()), 3),
            # Contexte pour le LLM uniquement : la décision du WAF n'entre jamais dans le score.
            blocked_ratio=round(sum(r.status in BLOCKED_STATUSES for r in recs) / len(recs), 3),
            injections_answered=int(sum(
                1 for row, r in zip(Xc, recs)
                if any(row[FEATURE_NAMES.index(k)] > 0 for k in ("sqli_hits", "xss_hits", "traversal_hits", "cmdi_hits"))
                and r.status not in BLOCKED_STATUSES and r.status < 500)),
            attack_hints=hints,
            top_ips=top_ips,
            top_paths=top_paths,
            methods=dict(Counter(sanitize_untrusted(r.method or "<vide>", 16) for r in recs).most_common(5)),
            statuses={str(k): v for k, v in Counter(r.status for r in recs).most_common()},
            top_user_agents=[{"user_agent": sanitize_untrusted(ua or "<vide>", 120), "count": c}
                             for ua, c in Counter(r.user_agent for r in recs).most_common(3)],
            deviations=deviations,
            samples=samples,
        )

    def _attack_hints(self, Xc: np.ndarray, recs: list[HttpRequestLog]) -> list[str]:
        """Hypothèses lisibles déduites des features : un point de départ pour le LLM, pas un verdict."""
        col = {name: Xc[:, j] for j, name in enumerate(FEATURE_NAMES)}
        share = lambda name: float((col[name] > 0).mean())  # noqa: E731
        hints = []
        if share("sqli_hits") >= 0.2:
            hints.append("sql_injection")
        if share("xss_hits") >= 0.2:
            hints.append("xss")
        if share("traversal_hits") >= 0.2:
            hints.append("path_traversal")
        if share("cmdi_hits") >= 0.2:
            hints.append("command_injection")
        if share("scanner_path") >= 0.2 or (
            math.expm1(col["ip_distinct_paths"].mean()) >= 15 and col["status_4xx"].mean() >= 0.5
        ):
            hints.append("reconnaissance_scan")
        if math.expm1(col["ip_auth_failures"].mean()) >= 10:
            hints.append("credential_bruteforce")
        # > 3x le p99 de la baseline, et jamais sous _FLOOD_MIN_PER_MIN (les erreurs sont si rares en
        # baseline que 3x leur p99 qualifiait de flood une IP bannie à 20 req/min).
        flood_floor = max(self.detector.p99[FEATURE_NAMES.index("ip_req_per_min")] + math.log(3), _FLOOD_FLOOR)
        error_floor = max(self.detector.p99[FEATURE_NAMES.index("ip_errors_per_min")] + math.log(3), _FLOOD_FLOOR)
        if col["ip_req_per_min"].mean() >= flood_floor or col["ip_errors_per_min"].mean() >= error_floor:
            hints.append("request_flood")
        crowd_floor = max(self._env_limit("endpoint_sessionless_ips"), _CROWD_FLOOR)
        if col["endpoint_sessionless_ips"].mean() >= crowd_floor:
            hints.append("distributed_flood")
        if float((col["bytes_log"] >= self._env_limit("bytes_log")).mean()) >= 0.5:
            hints.append("heavy_requests")
        if share("ua_tool") >= 0.5:
            hints.append("automated_tool")
        return hints or ["unknown_anomaly"]

    def _env_limit(self, feature: str) -> float:
        """Valeur (en log1p) au-delà de laquelle la feature sort de l'enveloppe : max baseline x facteur."""
        return float(self.detector.env_max[ENVELOPE_FEATURES.index(feature)]
                     + math.log(self.config.envelope_max_factor))

    def _looks_like_waf_collateral(self, Xi: np.ndarray, recs: list[HttpRequestLog],
                                   profile: IpProfile | None) -> bool:
        """Hypothèse (pas un verdict) : client légitime bloqué par le WAF, ex. NAT d'entreprise
        banni par « bad behavior ». Tout doit être réuni :
          - passé connu et sain : assez de requêtes, majorité de 2xx, aucune charge d'attaque ;
          - dans le cluster : requêtes surtout bloquées, sans charge ni outil, sur des chemins
            connus de la baseline, à un débit qui reste dans l'enveloppe (sinon c'est un flood,
            même venant d'une IP au passé propre).
        """
        if profile is None or profile.n_requests < _COLLATERAL_MIN_HISTORY:
            return False
        if profile.share_2xx < 0.5 or profile.n_payload_requests:
            return False
        col = {name: Xi[:, j] for j, name in enumerate(FEATURE_NAMES)}
        if any(col[k].any() for k in ("sqli_hits", "xss_hits", "traversal_hits", "cmdi_hits", "scanner_path", "ua_tool")):
            return False
        rate_cap = self._env_limit("ip_req_per_min")
        blocked = sum(r.status in BLOCKED_STATUSES for r in recs) / len(recs)
        return bool(blocked >= 0.8 and (col["path_rarity"] < 1.0).all()
                    and col["ip_req_per_min"].max() <= rate_cap)
