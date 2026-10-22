"""Tests de bout en bout sur trafic simulé : entraînement, canaris, clustering, persistance."""
import json
from datetime import timedelta

import numpy as np
import pytest

from detector.config import DetectorConfig
from detector.features import BLOCKED_STATUSES
from detector.ip_history import IpHistory
from detector.models import HttpRequestLog
from detector.sources.sim_normal import RUSH_NET
from detector.sources.simulated import AttackSpec, SimulatedSource
from detector.training import ModelRejected, filter_training_records, load, save, train, validate_canaries
from scripts.scenarios import T0, baseline_traffic, canary_traffic, demo_traffic


@pytest.fixture(scope="module")
def pipeline():
    records, _ = filter_training_records([lr.record for lr in baseline_traffic(minutes=20)])
    return train(records, DetectorConfig())


def test_simulator_lines_all_parse():
    assert all(lr.record is not None for lr in demo_traffic(minutes=15))


def test_training_filter_removes_attacks():
    raw = [lr.record for lr in canary_traffic()]
    kept, report = filter_training_records(raw)
    assert report.excluded and len(kept) < len(raw)
    assert not any(r.status == 403 for r in kept)


def test_canaries_detected(pipeline):
    recall = validate_canaries(pipeline, [(lr.record, lr.label) for lr in canary_traffic()])
    assert set(recall) == {"xss", "sqli", "traversal", "scan", "bruteforce", "flood",
                           "ddos_distributed", "ddos_cachebust", "ddos_heavy"}


def test_model_trained_on_attacks_is_rejected():
    """Garde-fou anti-empoisonnement : une baseline contaminée par un flood ne passe pas."""
    poisoned = [lr.record for lr in canary_traffic(seed=5)] * 3       # attaques non filtrées
    with pytest.raises(ModelRejected):
        validate_canaries(train(poisoned, DetectorConfig()), [(lr.record, lr.label) for lr in canary_traffic()])


def test_low_false_positive_rate(pipeline):
    labeled = baseline_traffic(minutes=10, seed=123)               # trafic normal jamais vu
    flagged = pipeline.analyze([lr.record for lr in labeled]).is_anomaly
    assert flagged.mean() < 0.02


def test_moderate_flood_detected_by_rate_alone(pipeline):
    """Cas réel du 19/10 : flood à 80-320 req/min/IP, bien en deçà des floods simulés (~1 800)."""
    normal = [lr.record for lr in baseline_traffic(minutes=3, seed=321)]
    flood = [HttpRequestLog(ts=T0 + timedelta(seconds=60 + i * 0.2), client_ip="172.30.10.1", method="GET",
                            uri="/", protocol="HTTP/1.1", status=200, bytes_sent=2400, user_agent=normal[0].user_agent)
             for i in range(300)]
    records = sorted(normal + flood, key=lambda r: r.ts)
    flagged = pipeline.analyze(records).is_anomaly
    is_flood = np.array([r.client_ip == "172.30.10.1" for r in records])
    assert flagged[is_flood][-50:].all()         # une fois le débit établi (> 3 × max baseline)


def _collateral_scenario(window_uri: str, with_history: bool = True):
    """Une IP d'entreprise au passé sain (pages + paiements réussis, plusieurs navigateurs),
    puis bannie par le WAF : 90 requêtes en 403 sur la minute analysée."""
    ip, uas = "192.168.137.100", ["Mozilla/5.0 (Windows NT 10.0) Chrome/129.0", "Mozilla/5.0 (Macintosh) Safari/605.1"]
    past = [HttpRequestLog(ts=T0 + timedelta(seconds=10 * i), client_ip=ip, method="POST" if i % 3 else "GET",
                           uri="/api/payments", protocol="HTTP/1.1", status=201 if i % 3 else 200, bytes_sent=400,
                           user_agent=uas[i % 2]) for i in range(40)] if with_history else []
    w0 = T0 + timedelta(minutes=10)
    banned = [HttpRequestLog(ts=w0 + timedelta(seconds=i * 60 / 90), client_ip=ip, method="GET", uri=window_uri,
                             protocol="HTTP/1.1", status=403, bytes_sent=555, user_agent=uas[i % 2]) for i in range(90)]
    return past, banned, ip


def _analyze_after(pipeline, past, window):
    history = IpHistory()
    history.update(past)
    return pipeline.analyze(window, pipeline.features(past + window)[len(past):], history=history), history


def test_waf_ban_of_legit_client_is_not_an_anomaly(pipeline):
    """La décision du WAF n'entre pas dans le score : un client banni qui se comporte
    normalement (débit, chemins, navigateurs) n'est pas signalé."""
    past, banned, _ = _collateral_scenario("/api/payments")
    result, _ = _analyze_after(pipeline, past, banned)
    assert not result.is_anomaly.any()


def test_collateral_hypothesis(pipeline):
    past, banned, ip = _collateral_scenario("/api/payments")
    X = pipeline.features(past + banned)[len(past):]
    profile = IpHistory()
    profile.update(past)
    profile = profile.profile(ip, before=banned[0].ts)
    assert profile.n_successful_writes > 0
    assert pipeline._looks_like_waf_collateral(X, banned, profile)
    assert not pipeline._looks_like_waf_collateral(X, banned, None)          # sans historique

    _, xss, _ = _collateral_scenario("/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert not pipeline._looks_like_waf_collateral(pipeline.features(past + xss)[len(past):], xss, profile)


def test_attack_from_ip_with_clean_past_is_not_collateral(pipeline):
    past, xss, ip = _collateral_scenario("/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    result, _ = _analyze_after(pipeline, past, xss)
    entries = [e for c in result.clusters for e in c.top_ips if e["ip"] == ip]
    assert entries and not any(e["assessment"] for e in entries)
    assert entries[0]["history"]["n_successful_writes"] > 0


def test_attack_missed_by_waf_is_detected(pipeline):
    """Ce que le WAF laisse passer (DetectionOnly) doit être trouvé par le module."""
    labeled = demo_traffic(minutes=15, waf_blocking=False)
    records = [lr.record for lr in labeled]
    flagged = pipeline.analyze(records).is_anomaly
    missed = np.array([lr.label not in ("normal", "flood") and lr.record.status not in BLOCKED_STATUSES
                       for lr in labeled])
    assert missed.sum() > 100 and flagged[missed].mean() > 0.8


def test_distributed_ddos_under_waf_thresholds_is_detected_but_not_a_legit_rush(pipeline):
    """Botnet sous les seuils du WAF (aucune requête bloquée) : détecté. Afflux légitime : non signalé."""
    src = SimulatedSource(seed=3, attacks=(AttackSpec("ddos_distributed", 240, 60, rate_per_s=50, n_ips=100, first_ip=66),),
                          rushes=(60,), rush_visitors=100)
    labeled = src.generate(T0, T0 + timedelta(minutes=6))
    flagged = pipeline.analyze([lr.record for lr in labeled]).is_anomaly
    ddos = np.array([lr.label == "ddos_distributed" for lr in labeled])
    rush = np.array([lr.label == "normal" and lr.record.client_ip.startswith(RUSH_NET) for lr in labeled])
    assert not any(lr.record.status in BLOCKED_STATUSES for lr in np.array(labeled)[ddos])
    assert flagged[ddos].mean() > 0.8
    assert flagged[rush].mean() < 0.03


def test_clusters_separate_attack_campaigns(pipeline):
    labeled = demo_traffic(minutes=15)
    records = [lr.record for lr in labeled]
    truth = np.array([lr.label for lr in labeled])
    # Fenêtre 04:30-05:30 : injection SQL et XSS simultanées (voir DEMO_ATTACKS).
    ts = np.array([r.ts.timestamp() for r in records]) - records[0].ts.timestamp()
    X = pipeline.features(records)
    idx = np.flatnonzero((ts >= 300) & (ts < 360))
    result = pipeline.analyze([records[i] for i in idx], X[idx])
    hints = {h for c in result.clusters for h in c.attack_hints}
    assert {"sql_injection", "xss"} <= hints
    for c in result.clusters:
        if c.cluster_id != "isolated":
            members = truth[idx][result.labels == int(c.cluster_id[1:])]
            # Chaque cluster est dominé par une seule campagne.
            assert max(np.unique(members, return_counts=True)[1]) / len(members) >= 0.8


def test_summary_is_json_and_sanitized(pipeline):
    labeled = demo_traffic(minutes=15)
    result = pipeline.analyze([lr.record for lr in labeled])
    payload = json.dumps([c.to_dict() for c in result.clusters], ensure_ascii=False)
    assert "\n" not in "".join(s["uri"] for c in result.clusters for s in c.samples)
    assert len(payload) < 200_000


def test_save_load_and_tamper_detection(pipeline, tmp_path):
    path = tmp_path / "m.joblib"
    save(pipeline, path, {"source": "test"})
    assert load(path).detector.threshold == pipeline.detector.threshold
    path.write_bytes(path.read_bytes() + b"x")
    with pytest.raises(ValueError):
        load(path)
