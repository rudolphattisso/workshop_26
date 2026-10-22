"""Entraînement de la baseline, garde-fous anti-empoisonnement, sauvegarde du modèle.

Règles (décidées avec l'équipe) :
  1. Pas de réentraînement automatique. Un modèle de référence est livré dans l'image ;
     tout réentraînement est déclenché par l'opérateur sur une plage qu'il choisit.
  2. Les données d'entraînement sont filtrées : on retire ce qui ressemble à une attaque
     (requêtes refusées par le WAF, motifs d'injection, chemins de scan, outils automatisés).
  3. Un nouveau modèle n'est accepté que s'il détecte encore un jeu d'attaques connues
     (« canaris »). Sinon il est rejeté et l'ancien reste en place.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np

from .config import DetectorConfig
from .detection import AnomalyDetector, DetectionPipeline
from .features import BLOCKED_STATUSES, TOOL_UA, FeatureExtractor, attack_signals
from .models import HttpRequestLog

MODEL_FORMAT_VERSION = 4   # 2 : ip_errors_per_min ; 3 : indépendance WAF ; 4 : DDoS (bytes_log, endpoint_sessionless_ips)


class ModelRejected(Exception):
    """Le modèle candidat ne passe pas la validation par canaris."""


@dataclass
class FilterReport:
    kept: int
    excluded: dict[str, int]


def filter_training_records(records: list[HttpRequestLog]) -> tuple[list[HttpRequestLog], FilterReport]:
    """Retire de la baseline les requêtes suspectes (protection contre l'empoisonnement)."""
    kept, excluded = [], Counter()
    for rec in records:
        signals = attack_signals(rec.uri)
        if rec.status in BLOCKED_STATUSES:
            excluded["blocked_by_waf"] += 1
        elif any(signals[k] for k in ("sqli_hits", "xss_hits", "traversal_hits", "cmdi_hits")):
            excluded["injection_pattern"] += 1
        elif signals["scanner_path"]:
            excluded["scanner_path"] += 1
        elif TOOL_UA.search(rec.user_agent):
            excluded["automated_tool"] += 1
        else:
            kept.append(rec)
    return kept, FilterReport(kept=len(kept), excluded=dict(excluded))


def train(records: list[HttpRequestLog], config: DetectorConfig) -> DetectionPipeline:
    records = sorted(records, key=lambda r: r.ts)
    extractor = FeatureExtractor(config.window_seconds, config.auth_paths).fit(records)
    X = extractor.transform(records)
    detector = AnomalyDetector(config).fit(X)
    return DetectionPipeline(extractor, detector, config)


def validate_canaries(pipeline: DetectionPipeline, canaries: list[tuple[HttpRequestLog, str]],
                      min_recall: float = 0.8) -> dict[str, float]:
    """Taux de détection, par type d'attaque connue, des requêtes que le WAF n'a PAS bloquées ;
    lève ModelRejected sous `min_recall`. Le module doit trouver ce que le WAF ne voit pas :
    retrouver seulement ses 403 ne compte pas.

    Les canaris peuvent être mêlés à du trafic "normal" (contexte réaliste pour les features
    par IP) : seules les lignes étiquetées attaque comptent dans le résultat.
    """
    records = [r for r, _ in canaries]
    flagged = pipeline.analyze(records).is_anomaly
    by_kind: dict[str, list[bool]] = defaultdict(list)
    for (rec, kind), hit in zip(canaries, flagged):
        if kind != "normal" and rec.status not in BLOCKED_STATUSES:
            by_kind[kind].append(bool(hit))
    recall = {kind: round(float(np.mean(hits)), 3) for kind, hits in sorted(by_kind.items())}
    failed = {k: v for k, v in recall.items() if v < min_recall}
    if failed:
        raise ModelRejected(f"canaris insuffisamment détectés (< {min_recall}) : {failed}")
    return recall


# -- persistance -------------------------------------------------------------------------
# joblib = pickle : charger un fichier modifié par un tiers permet d'exécuter du code.
# La vraie protection est que le modèle soit livré dans l'image (lecture seule) ; l'empreinte
# SHA-256 du fichier .meta.json détecte seulement une corruption ou un remplacement maladroit
# (quelqu'un qui peut réécrire les deux fichiers peut aussi recalculer l'empreinte).

def save(pipeline: DetectionPipeline, path: Path, metadata: dict) -> dict:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"format": MODEL_FORMAT_VERSION, "pipeline": pipeline}, path)
    meta = {
        **metadata,
        "format": MODEL_FORMAT_VERSION,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "threshold": pipeline.detector.threshold,
        # Exclues du comptage de foule DDoS : à relire (une IP d'attaquant ici serait aveuglée).
        "known_automated_ips": sorted(pipeline.extractor.known_automated_ips),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    path.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    return meta


def load(path: Path) -> DetectionPipeline:
    path = Path(path)
    meta = json.loads(path.with_suffix(".meta.json").read_text(encoding="utf-8"))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != meta.get("sha256"):
        raise ValueError(f"empreinte du modèle invalide ({path}) : fichier modifié ?")
    bundle = joblib.load(path)
    if bundle.get("format") != MODEL_FORMAT_VERSION:
        raise ValueError(f"format de modèle {bundle.get('format')} non supporté")
    return bundle["pipeline"]
