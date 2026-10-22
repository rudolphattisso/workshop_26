"""Mesure des délais réels des sources (detector.calibrate) : calculs et recommandations."""
import json
from datetime import datetime, timedelta, timezone

from detector import calibrate

T = datetime(2026, 10, 19, 16, 43, tzinfo=timezone.utc)


def access(at, path="/", ua="resilience-blackbox/1.0"):
    return (f'localhost 172.30.40.5 - - [{at:%d/%b/%Y:%H:%M:%S} +0000] "GET {path} HTTP/1.1" 200 10 "-" "{ua}"')


def test_probe_interval_per_path_and_largest_gap():
    lines = [access(T + timedelta(seconds=5 * i), p) for i in range(24) for p in ("/", "/api/auth/ready")
             if not (10 <= i < 13)]                                  # trou de 20 s au milieu
    lines.append(access(T, ua="Mozilla/5.0"))                         # pas une sonde
    stats = calibrate.probe_stats(lines, "resilience-blackbox/")
    assert stats["par_chemin"]["/"]["p50"] == 5 and stats["par_chemin"]["/"]["max"] == 20
    assert stats["toutes"]["max"] == 20


def test_wazuh_lateness_compares_alert_time_with_the_request_it_reports():
    alert = {"timestamp": (T + timedelta(seconds=7)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
             "full_log": access(T, ua="curl/8")}
    assert calibrate.wazuh_lateness(["<132>Oct 19 wazuh: " + json.dumps(alert), "bruit"])["max"] == 7


def test_volume_counts_empty_minutes():
    lines = [access(T)] * 10 + [access(T + timedelta(minutes=2))]
    stats = calibrate.volume_stats(lines)
    assert stats["n"] == 3 and stats["max"] == 10 and stats["p50"] == 1


def test_recommendations_come_from_measures():
    probes = {"par_chemin": {"/": {"p50": 5.0}, "/x": {"p50": 5.1}}, "toutes": {"p99": 21.0}}
    rec = calibrate.recommend({"p99": 3.4}, probes, {"p99": 12.0}, outage_s=24.0)
    assert rec == {"DETECTOR_INGEST_DELAY_S": 5, "DETECTOR_PROBE_INTERVAL_S": 5, "DETECTOR_PROBE_MISSED": 6,
                   "LOKI_WAZUH_MARGIN_S": 17, "DETECTOR_VISIBILITY_ERRORS": 4}
    assert calibrate.recommend({}, {"par_chemin": {}, "toutes": {}}, {}, None) == {}   # rien mesuré : rien proposé


def test_live_ingestion_delay_ignores_the_history_read_on_first_poll(monkeypatch):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    polls = [[(1, access(now - timedelta(minutes=5), ua="x"))],             # historique : ignoré
             [(1, access(now - timedelta(minutes=5), ua="x")), (2, access(now - timedelta(seconds=3), ua="x"))]]

    class Fake:
        def entries(self, query, start, end):
            return polls.pop(0) if polls else []
    monkeypatch.setattr(calibrate.time, "sleep", lambda s: None)
    clock = iter([0, 1, 2, 3, 100])
    monkeypatch.setattr(calibrate.time, "time", lambda: next(clock))
    stats, latencies = calibrate.measure_ingestion(Fake(), "{}", duration_s=10, poll_s=0)
    assert stats["n"] == 1 and 3 <= stats["max"] < 5 and len(latencies) == 3
