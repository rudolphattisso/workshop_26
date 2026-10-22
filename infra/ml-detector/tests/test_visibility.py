"""Actions de l'infra dans les rapports, et rapports maintenus quand les sources de données tombent."""
import json
import threading
from datetime import datetime, timedelta, timezone

from detector.alarms import AVAILABILITY, Alarm
from detector.escalation import EscalationConfig, Escalator
from detector.infra_actions import InfraAction, parse_line, to_context
from detector.models import ClusterSummary, HttpRequestLog
from detector.service import DetectorService
from detector.sources.loki import LokiClient, LokiError, LokiRemediationSource
from tests.test_loki import fake_loki, ns
from tests.test_service import FakeDetections, FakeGateway, botnet

T = datetime(2026, 10, 20, 14, 0, tzinfo=timezone.utc)


def remediation(msg, at="2026-10-20T13:59:30Z", **fields):
    return json.dumps({"ts": at, "level": "info", "service": "remediation", "msg": msg,
                       "alertname": "WafDown", "action": "restart", "target": "bunkerweb", **fields})


class Overview(FakeDetections):
    def overview(self, records, X=None, history=None, window=("", "")):
        return ClusterSummary(cluster_id="fenetre", signature=f"symptome{len(records)}", window_start=window[0],
                              window_end=window[1], n_requests=len(records), n_distinct_ips=1, score_mean=0.0,
                              score_max=0.0, blocked_ratio=0.0, attack_hints=["service_degradation"], top_ips=[],
                              top_paths=[], methods={}, statuses={}, top_user_agents=[])


class Traffic:
    """n requêtes par fetch, ou une panne de Loki si `down`."""
    def __init__(self, n=50):
        self.n, self.down = n, False

    def fetch(self, start, end):
        if self.down:
            raise LokiError("Loki injoignable")
        return [HttpRequestLog(end - timedelta(seconds=1), "10.0.0.1", "GET", "/", "HTTP/1.1", 200, 10)] * self.n


class Actions:
    def __init__(self, actions):
        self.items = actions

    def fetch(self, start, end):
        return [a for a in self.items if start <= a.ts < end]


def make(gateway=None, logs=None, actions=None, **kw):
    pipeline = Overview()
    svc = DetectorService(pipeline, logs or Traffic(), None, Escalator(EscalationConfig(threshold=50)), gateway,
                          actions=actions, **kw)
    return svc, pipeline


# -- actions de remédiation -------------------------------------------------------------------
def test_remediation_log_lines_are_read():
    failed = parse_line(remediation("remediation_failed", recovery_seconds=90, verification={"ok": False}))
    assert (failed.event, failed.action, failed.target) == ("remediation_failed", "restart", "bunkerweb")
    assert "vérification" in failed.detail
    ok = parse_line(remediation("remediation_succeeded", recovery_seconds=12.5))
    assert ok.detail == "service rétabli en 12.5 s"
    assert parse_line(remediation("remediation_action_done")) is None          # étape intermédiaire
    assert parse_line(remediation("webhook_unauthorized")) is None
    assert parse_line("pas du json") is None


def test_remediation_source_reads_loki(monkeypatch):
    fake_loki(monkeypatch, [[[ns(T), remediation("remediation_started", at="2026-10-20T14:00:00Z")]]])
    [action] = LokiRemediationSource().fetch(T, T + timedelta(seconds=10))
    assert to_context([action])[0]["evenement"] == "remédiation lancée"


def test_infra_actions_are_sent_with_every_analysis():
    gw = FakeGateway()
    restarted = InfraAction(T - timedelta(seconds=30), "remediation_succeeded", "WafDown", "restart", "bunkerweb",
                            "service rétabli en 12 s")
    svc, pipeline = make(gw, actions=Actions([restarted]))
    pipeline.next = [botnet({"503": 9000})]
    svc.tick(T)
    svc.drain(T)
    [(_, context)] = gw.calls
    assert context["actions_infra"][0]["evenement"] == "remédiation réussie"
    assert context["actions_infra"][0]["cible"] == "bunkerweb"


def test_failed_remediation_alone_triggers_an_analysis_even_without_wazuh():
    gw = FakeGateway()
    failed = InfraAction(T - timedelta(seconds=20), "remediation_failed", "WafDown", "restart", "bunkerweb", "x")
    svc, _ = make(gw, actions=Actions([failed]))
    for i in range(6):                                  # l'échec reste 60 s dans la fenêtre glissante
        svc.tick(T + timedelta(seconds=10 * i))
        svc.drain(T + timedelta(seconds=10 * i))
    assert len(gw.calls) == 1                           # une seule analyse pour un seul événement
    assert gw.calls[0][1]["escalade"]["trigger"] == "symptome_sans_campagne"


def test_a_new_critical_alarm_still_bypasses_the_cooldown():
    esc = Escalator()
    first = esc.decide_symptom([Alarm(T, AVAILABILITY, "wazuh", "100210", "échec")], [], T)
    again = esc.decide_symptom([Alarm(T, AVAILABILITY, "wazuh", "100210", "échec")], [], T + timedelta(seconds=10))
    later = esc.decide_symptom([Alarm(T + timedelta(minutes=3), AVAILABILITY, "wazuh", "100210", "échec")], [],
                               T + timedelta(minutes=3))
    assert first.escalate and not again.escalate and later.escalate


# -- perte de visibilité ----------------------------------------------------------------------
class StepClock:
    def __init__(self, t):
        self.t = t

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += timedelta(seconds=10)


def test_loki_outage_still_produces_one_report_from_what_was_seen_before():
    gw, logs = FakeGateway(), Traffic(50)
    svc, _ = make(gw, logs=logs, heartbeat_s=0)
    svc.tick(T)                                          # du trafic avant la panne
    logs.down = True
    svc.run(StepClock(T + timedelta(seconds=10)), until=T + timedelta(minutes=2))
    assert len(gw.calls) == 1                            # une analyse, pas une par cycle en panne
    cluster, context = gw.calls[0]
    assert cluster["attack_hints"] == ["visibility_loss"] and cluster["n_requests"] == 50
    assert context["escalade"]["trigger"] == "perte_de_visibilite"
    assert context["escalade"]["donnees_jusqu_a"] == T.isoformat()
    assert "injoignables depuis 3 cycles" in context["escalade"]["reasons"][0]


def test_sudden_silence_after_traffic_is_reported():
    gw, logs = FakeGateway(), Traffic(50)
    svc, _ = make(gw, logs=logs)
    svc.tick(T)
    logs.n = 0
    for i in range(1, 8):                                # la fenêtre de 60 s se vide
        svc.tick(T + timedelta(seconds=10 * i))
        svc.drain(T + timedelta(seconds=10 * i))
    assert len(gw.calls) == 1 and "plus AUCUNE requête" in gw.calls[0][1]["escalade"]["reasons"][0]


def test_quiet_traffic_is_not_a_loss_of_visibility():
    gw, logs = FakeGateway(), Traffic(3)                 # quelques requêtes, puis plus rien : normal la nuit
    svc, _ = make(gw, logs=logs)
    svc.tick(T)
    logs.n = 0
    for i in range(1, 8):
        svc.tick(T + timedelta(seconds=10 * i))
        svc.drain(T + timedelta(seconds=10 * i))
    assert gw.calls == []


def test_truncated_read_is_flagged(monkeypatch):
    fake_loki(monkeypatch, [[[ns(T + timedelta(milliseconds=i)), "x"] for i in range(2)]] * 3)
    client = LokiClient(page_size=2, max_pages=3)
    assert len(client.lines("{}", T, T + timedelta(seconds=1))) == 6 and client.truncated


def test_heartbeat_reaches_the_gateway_and_reports_blindness():
    beats, got = [], threading.Event()

    class Beating(FakeGateway):
        def heartbeat(self, status):
            beats.append(status)
            got.set()
            return {}

    logs = Traffic(50)
    logs.down = True
    svc, _ = make(Beating(), logs=logs, heartbeat_s=0.01, visibility_errors=1)
    svc.errors_in_row = 1
    stop = threading.Event()
    threading.Thread(target=svc._heartbeat, args=(StepClock(T), stop), daemon=True).start()
    assert got.wait(2)
    stop.set()
    assert beats[0]["statut"] == "aveugle" and beats[0]["erreurs_consecutives"] == 1


# -- sondes de supervision de l'infra (blackbox, toutes les 5 s, à travers le WAF) -------------
class Probed:
    """Sondes toutes les 5 s jusqu'à `stop`, et `users` requêtes d'utilisateurs par fetch."""
    def __init__(self, stop, users=0):
        self.stop, self.users = stop, users
        self.users_until = None                          # après cette date, plus aucune requête utilisateur

    def fetch(self, start, end):
        out, t = [], start
        while t < end:
            if t < self.stop:
                out.append(HttpRequestLog(t, "172.30.40.5", "GET", "/", "HTTP/1.1", 200, 10,
                                          user_agent="resilience-blackbox/1.0"))
            t += timedelta(seconds=5)
        users = 0 if self.users_until and end > self.users_until else self.users
        return out + [HttpRequestLog(end - timedelta(seconds=1), "10.0.0.9", "GET", "/", "HTTP/1.1", 200, 10)] * users


def ticks(svc, n, start=T):
    for i in range(n):
        svc.tick(start + timedelta(seconds=10 * i))
        svc.drain(start + timedelta(seconds=10 * i))


def test_missing_probes_are_seen_in_15_seconds_not_60(caplog):
    gw = FakeGateway()
    svc, _ = make(gw, logs=Probed(stop=T + timedelta(seconds=30), users=5))
    svc.logs.users_until = T + timedelta(seconds=30)    # le WAF meurt : plus rien du tout ensuite
    with caplog.at_level("INFO", logger="ml_detector"):
        ticks(svc, 6)                                   # dernière sonde à T+25 s ; alerte à T+50 s
    assert len(gw.calls) == 1
    reason = gw.calls[0][1]["escalade"]["reasons"][0]
    assert "aucune sonde" in reason and "WAF arrêté" in reason
    assert sum('"perte_de_visibilite"' in r.message for r in caplog.records) == 1   # pas une ligne par cycle


def test_probes_missing_while_other_traffic_flows_says_so():
    gw = FakeGateway()
    svc, _ = make(gw, logs=Probed(stop=T + timedelta(seconds=30), users=40))
    ticks(svc, 6)
    assert "autres requêtes sont arrivées" in gw.calls[0][1]["escalade"]["reasons"][0]


def test_regular_probes_never_raise_an_alert(caplog):
    gw = FakeGateway()
    svc, _ = make(gw, logs=Probed(stop=T + timedelta(hours=1)))
    with caplog.at_level("INFO", logger="ml_detector"):
        ticks(svc, 30)
    assert gw.calls == [] and not any("visibilite" in r.message for r in caplog.records)


def test_recovery_is_logged_once(caplog):
    svc, _ = make(None, logs=Probed(stop=T + timedelta(seconds=30)))
    ticks(svc, 6)
    svc.logs.stop = T + timedelta(hours=1)              # les sondes reviennent
    with caplog.at_level("INFO", logger="ml_detector"):
        ticks(svc, 3, start=T + timedelta(seconds=60))
    assert sum('"visibilite_retablie"' in r.message for r in caplog.records) == 1


def test_remediation_lines_in_the_common_log_format_are_read():
    line = json.dumps({"timestamp": "2026-10-20T13:59:30.000+00:00", "level": "ERROR", "service": "remediation",
                       "trace_id": None, "event": "remediation_failed", "logger": "remediation",
                       "alertname": "WafDown", "action": "restart", "target": "bunkerweb"})
    action = parse_line(line)
    assert (action.event, action.target, action.ts) == ("remediation_failed", "bunkerweb", T - timedelta(seconds=30))
