"""Le détecteur doit suivre le temps réel PENDANT un DDoS : analyser une fenêtre de 60 s en
nettement moins de 60 s, quel que soit le volume.

Pas de seuil serré (il dépendrait de la machine) : un budget large, et surtout un rapport
d'échelle, indépendant de la machine, qui attrape une complexité quadratique. Ce test aurait
attrapé le DBSCAN quadratique corrigé le 2026-10-21 (20 000 requêtes de botnet : 17 s).
"""
import random
import time
from datetime import timedelta

import pytest

from detector.config import DetectorConfig
from detector.models import HttpRequestLog
from detector.training import filter_training_records, train
from scripts.scenarios import T0, baseline_traffic


@pytest.fixture(scope="module")
def pipeline():
    records, _ = filter_training_records([lr.record for lr in baseline_traffic(minutes=10)])
    return train(records, DetectorConfig())


def botnet_minute(n: int, seed: int = 1) -> list[HttpRequestLog]:
    """n requêtes quasi identiques de 300 IP en une minute : le pire cas pour le regroupement."""
    rng = random.Random(seed)
    return sorted((HttpRequestLog(T0 + timedelta(seconds=rng.uniform(0, 60)), f"10.9.{i % 300 // 250}.{i % 250 + 1}",
                                  "GET", "/", "HTTP/1.1", 200, 2412, "", "Mozilla/5.0") for i in range(n)),
                  key=lambda r: r.ts)


def analysis_seconds(pipeline, records) -> float:
    best = float("inf")
    for _ in range(2):                                   # meilleur de 2 : moins sensible au bruit
        start = time.perf_counter()
        pipeline.analyze(records, pipeline.features(records))
        best = min(best, time.perf_counter() - start)
    return best


def test_ddos_minute_analyzed_well_within_the_window(pipeline):
    # 20 000 requêtes/min (~330 req/s) : ~1 s mesurée ; budget 20 s pour toute machine raisonnable.
    assert analysis_seconds(pipeline, botnet_minute(20_000)) < 20


def test_analysis_time_scales_linearly(pipeline):
    small = analysis_seconds(pipeline, botnet_minute(4_000))
    large = analysis_seconds(pipeline, botnet_minute(16_000))
    # x4 de volume : ~x4 attendu en linéaire, x16 en quadratique ; marge pour le bruit de mesure.
    assert large / small < 8, f"x4 requêtes => x{large / small:.1f} de temps"
