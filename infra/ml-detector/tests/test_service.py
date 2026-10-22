"""Service continu : file vers le LLM (priorité, fusion, péremption) et réanalyses."""
import json
import logging
from datetime import datetime, timedelta, timezone

from detector.escalation import EscalationConfig, Escalator
from detector.llm_queue import LlmQueue
from detector.models import ClusterSummary
from detector.service import DetectorService

T = datetime(2026, 10, 20, 14, 0, tzinfo=timezone.utc)


def item(name):
    return {"trigger": "campagne", "cluster": {"signature": name}, "context": {}, "mise_a_jour": False}


def test_most_severe_first_and_one_place_per_campaign():
    q = LlmQueue()
    q.put("scan", 55, item("scan"), T)
    q.put("botnet", 90, item("botnet-v1"), T)
    q.put("botnet", 85, item("botnet-v2"), T + timedelta(seconds=10))       # même campagne : fusion
    assert len(q) == 2
    first = q.get(lambda: T + timedelta(seconds=20))
    assert first.key == "botnet" and first.item["cluster"]["signature"] == "botnet-v2"   # données les plus récentes
    assert first.severity == 90 and first.merged == 1 and first.queued_at == T          # l'ancienneté est gardée
    assert q.get(lambda: T + timedelta(seconds=20)).key == "scan"


def test_stale_and_overflow_are_dropped_and_reported():
    dropped = []
    q = LlmQueue(max_size=2, max_age_s=300, on_drop=lambda queued, why: dropped.append((queued.key, why)))
    q.put("a", 60, item("a"), T)
    q.put("b", 80, item("b"), T)
    q.put("c", 70, item("c"), T)                                           # file pleine : la moins grave sort
    assert dropped == [("a", "file pleine")]
    assert q.get(lambda: T + timedelta(minutes=6)) is None                 # tout est périmé
    assert sorted(dropped) == [("a", "file pleine"), ("b", "périmée"), ("c", "périmée")]


class FakeGateway:
    def __init__(self):
        self.calls = []

    def analyze(self, cluster, context):
        self.calls.append((cluster, context))
        return {"signature": cluster["signature"], "generated_at": "2026-10-20T14:00:00+00:00",
                "rules_file": "/app/reports/20261020T140000Z_" + cluster["signature"] + ".md",
                "analysis": {"verdict": "attaque", "summary": "Botnet sur /", "confidence": "elevee",
                             "attack_type": "DDoS", "rules": [{"content": "USE_ANTIBOT=javascript"}]},
                "warnings": [], "timings": {"total_s": 41.0}}


class FakeDetections:
    """Pipeline minimal : chaque cycle produit le groupe qu'on lui donne."""
    class config:
        window_seconds = 60

    def __init__(self):
        self.next = []

    def features(self, records):
        import numpy as np
        return np.zeros((len(records), 1))

    def analyze(self, records, X, history=None):
        return type("R", (), {"clusters": self.next})()


class OneRequest:
    def fetch(self, start, end):
        from detector.models import HttpRequestLog
        return [HttpRequestLog(end - timedelta(seconds=1), "10.66.0.1", "GET", "/", "HTTP/1.1", 200, 10)]


def botnet(statuses):
    c = ClusterSummary(cluster_id="c0", signature="sig", window_start="", window_end="", n_requests=9000,
                       n_distinct_ips=300, score_mean=1.0, score_max=1.0, blocked_ratio=0.0,
                       attack_hints=["distributed_flood"], top_ips=[{"ip": "10.66.0.1", "count": 40}],
                       top_paths=[{"path": "/", "count": 9000}], methods={"GET": 9000}, statuses=statuses,
                       top_user_agents=[])
    return c


def service(gateway, **escalation):
    pipeline = FakeDetections()
    svc = DetectorService(pipeline, OneRequest(), None, Escalator(EscalationConfig(**{
        "threshold": 50, "cooldown_s": 1800, "worsening": 20, "max_per_minute": 2, **escalation})),
        gateway, reports_url="http://pc-ia:8080/reports")
    return svc, pipeline


def test_reanalysis_carries_the_previous_report(caplog):
    gw = FakeGateway()
    svc, pipeline = service(gw)
    pipeline.next = [botnet({"200": 9000})]                                 # gravité 60
    svc.tick(T)
    svc.drain(T)
    pipeline.next = [botnet({"503": 9000})]                                 # gravité 100 : aggravation
    with caplog.at_level(logging.INFO, logger="ml_detector"):
        svc.tick(T + timedelta(minutes=1))
        svc.drain(T + timedelta(minutes=1))
    assert len(gw.calls) == 2
    assert "analyse_precedente" not in gw.calls[0][1]
    previous = gw.calls[1][1]["analyse_precedente"]
    assert previous["verdict"] == "attaque" and previous["regles_deja_proposees"] == ["USE_ANTIBOT=javascript"]
    line = json.loads(next(r.message for r in caplog.records if '"event": "rapport"' in r.message))
    assert line["mise_a_jour"] is True and line["lien"] == "http://pc-ia:8080/reports/20261020T140000Z_sig.md"


def test_dropped_analysis_releases_the_campaign_for_a_fresh_one():
    gw = FakeGateway()
    svc, pipeline = service(gw)
    pipeline.next = [botnet({"503": 9000})]
    svc.tick(T)                                                            # mise en file, jamais envoyée
    svc.drain(T + timedelta(minutes=10))                                   # périmée : écartée
    assert gw.calls == [] and svc.metrics.get("soc_llm_dropped_total", reason="périmée") == 1
    svc.tick(T + timedelta(minutes=10))                                    # réescaladée tout de suite
    svc.drain(T + timedelta(minutes=10))
    assert len(gw.calls) == 1


def test_window_ends_before_now_to_wait_for_loki_ingestion():
    seen = []

    class Recording(OneRequest):
        def fetch(self, start, end):
            seen.append((start, end))
            return super().fetch(start, end)
    svc = DetectorService(FakeDetections(), Recording(), None, Escalator(EscalationConfig()), None, ingest_delay_s=5)
    now = datetime(2026, 10, 19, 16, 43, tzinfo=timezone.utc)
    svc.tick(now)
    assert max(end for _, end in seen) == now - timedelta(seconds=5)


def test_loki_outage_does_not_kill_the_service_and_is_caught_up():
    from detector.sources.loki import LokiError
    now = datetime(2026, 10, 19, 16, 43, tzinfo=timezone.utc)
    seen = []

    class Flaky(OneRequest):
        def fetch(self, start, end):
            seen.append((start, end))
            if len(seen) == 2:
                raise LokiError("Loki injoignable")
            return super().fetch(start, end)

    class StepClock:
        def __init__(self, t):
            self.t = t

        def now(self):
            return self.t

        def sleep(self, seconds):
            self.t += timedelta(seconds=10)

    svc = DetectorService(FakeDetections(), Flaky(), None, Escalator(EscalationConfig()), None)
    svc.run(StepClock(now), until=now + timedelta(seconds=30))
    assert len(seen) == 3 and svc.metrics.get("soc_detector_errors_total") == 1
    assert seen[2][0] == seen[0][1]                      # le cycle suivant relit la période manquée
