"""Paramètres du détecteur, surchargeables par variables d'environnement (docker-compose)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default, cast=str):
    value = os.getenv(name)
    return default if value is None or value == "" else cast(value)


@dataclass(frozen=True)
class DetectorConfig:
    # Fenêtre glissante des features par IP (débit, chemins distincts, erreurs) et des clusters.
    window_seconds: int = field(default_factory=lambda: _env("DETECTOR_WINDOW_SECONDS", 60, int))
    # Endpoints d'authentification : les échecs (401/403) y sont comptés à part (force brute).
    auth_paths: tuple[str, ...] = field(
        default_factory=lambda: tuple(_env("DETECTOR_AUTH_PATHS", "/api/auth/login").split(","))
    )

    # IsolationForest
    n_estimators: int = field(default_factory=lambda: _env("DETECTOR_N_ESTIMATORS", 200, int))
    # Seuil d'anomalie = quantile des scores de la baseline (0.995 => ~0,5 % de faux positifs attendus).
    threshold_quantile: float = field(default_factory=lambda: _env("DETECTOR_THRESHOLD_QUANTILE", 0.995, float))
    random_state: int = 42
    # Enveloppe : anormal si une feature dépasse le max de la baseline de plus de N écarts-types.
    envelope_z: float = field(default_factory=lambda: _env("DETECTOR_ENVELOPE_Z", 3.0, float))
    # Compteurs par IP (débit, chemins distincts, échecs d'auth) : anormal au plus tard à N fois le
    # max de la baseline. Sans ce plafond, l'écart-type en log du débit normal (1 à 39 req/min)
    # repoussait le seuil à ~760 req/min et le flood réel du 19/10 (80-320 req/min) passait.
    envelope_max_factor: float = field(default_factory=lambda: _env("DETECTOR_ENVELOPE_MAX_FACTOR", 3.0, float))

    # DBSCAN (appliqué uniquement aux requêtes anormales, dans l'espace « signature » de
    # detection.py où chaque feature pèse au plus 1 : eps 0.5 = moins d'une demi-caractéristique d'écart)
    dbscan_eps: float = field(default_factory=lambda: _env("DETECTOR_DBSCAN_EPS", 0.5, float))
    dbscan_min_samples: int = field(default_factory=lambda: _env("DETECTOR_DBSCAN_MIN_SAMPLES", 5, int))

    # Résumés envoyés au LLM
    max_samples_per_cluster: int = field(default_factory=lambda: _env("DETECTOR_MAX_SAMPLES", 5, int))
    sanitize_max_len: int = field(default_factory=lambda: _env("DETECTOR_SANITIZE_MAX_LEN", 200, int))
