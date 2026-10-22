"""Sources Loki (production) : pagination, lignes BunkerWeb réelles, alertes Wazuh en syslog."""
import io
import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import pytest

from detector.logs import JsonFormatter
from detector.sources.loki import LokiClient, LokiError, LokiSource, LokiWazuhAlarmSource

T = datetime(2026, 10, 19, 16, 43, tzinfo=timezone.utc)
ACCESS = ('localhost 172.30.10.1 - 68b7cd9283258c88b03e70f37c2a147a - [19/Oct/2026:16:43:05 +0000] '
          '"GET /?q=%3Cscript%3E HTTP/1.1" 403 69298 "-" "resilience-labtest/1.0"')
ERROR = '2026/10/19 16:43:05 [warn] 183#183: *7468 ModSecurity: Warning. detected XSS using libinjection.'
WAZUH = ('<132>Oct 19 16:43:48 wazuh.manager ossec: {"timestamp":"2026-10-19T16:43:48.000+0000",'
         '"rule":{"id":"100110","description":"IP bannie"},"data":{"srcip":"172.30.10.1"}}')


def fake_loki(monkeypatch, pages):
    """Simule /loki/api/v1/query_range : une réponse par appel, requêtes mémorisées."""
    calls = []

    def urlopen(url, timeout=None):
        calls.append(url)
        values = pages[len(calls) - 1]
        body = {"status": "success", "data": {"resultType": "streams",
                                              "result": [{"stream": {"service": "bunkerweb"}, "values": values}]}}
        return io.BytesIO(json.dumps(body).encode())
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return calls


def ns(dt):
    return str(int(dt.timestamp() * 1e9))


def test_access_lines_are_parsed_and_error_lines_ignored(monkeypatch):
    fake_loki(monkeypatch, [[[ns(T), ERROR], [ns(T + timedelta(seconds=1)), ACCESS]]])
    records = LokiSource().fetch(T, T + timedelta(seconds=10))
    assert len(records) == 1 and records[0].client_ip == "172.30.10.1" and records[0].status == 403


def test_pagination_continues_after_the_last_line(monkeypatch):
    first = [[ns(T + timedelta(milliseconds=i)), ACCESS] for i in range(3)]
    calls = fake_loki(monkeypatch, [first, [[ns(T + timedelta(seconds=5)), ACCESS]]])
    lines = LokiClient(page_size=3).lines('{service="bunkerweb"}', T, T + timedelta(seconds=10))
    assert len(lines) == 4 and len(calls) == 2
    assert f"start={int(first[-1][0]) + 1}" in calls[1]                     # pas de ligne relue deux fois


def test_wazuh_alerts_from_syslog_lines(monkeypatch):
    fake_loki(monkeypatch, [[[ns(T + timedelta(seconds=48)), WAZUH], [ns(T), "pas une alerte"]]])
    alarms = LokiWazuhAlarmSource().fetch(T, T + timedelta(minutes=1))
    assert [(a.kind, a.rule, a.ip) for a in alarms] == [("waf_ban", "100110", "172.30.10.1")]


def test_unreachable_loki_raises_a_clear_error(monkeypatch):
    def urlopen(url, timeout=None):
        raise urllib.error.URLError("connexion refusée")
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    with pytest.raises(LokiError):
        LokiSource().fetch(T, T + timedelta(seconds=10))


def test_log_lines_follow_the_infra_contract():
    record = logging.LogRecord("ml_detector", logging.INFO, "", 0, json.dumps({"event": "rapport", "verdict": "attaque"}), None, None)
    line = json.loads(JsonFormatter().format(record))
    assert list(line)[:6] == ["timestamp", "level", "service", "trace_id", "event", "logger"]   # contrat commun
    assert (line["service"], line["level"], line["event"], line["verdict"]) == ("ml-detector", "INFO", "rapport", "attaque")
    plain = json.loads(JsonFormatter().format(logging.LogRecord("x", logging.WARNING, "", 0, "texte libre", None, None)))
    assert (plain["event"], plain["message"], plain["level"]) == ("message", "texte libre", "WARNING")


@pytest.mark.parametrize("rule,kind", [("100103", "waf_block"), ("100112", "waf_ban"), ("100200", "auth"),
                                       ("100201", "auth"), ("100210", "availability")])
def test_infra_local_rules_are_mapped(rule, kind):
    from detector.alarms import WazuhAlarmSource
    alert = {"timestamp": "2026-10-19T16:43:48.000+0000", "rule": {"id": rule, "description": "x"}}
    assert WazuhAlarmSource._to_alarm(json.dumps(alert)).kind == kind


def test_probes_follow_the_common_service_conventions():
    import urllib.request as req
    from detector.metrics import Metrics, serve
    state = {"loki": "ok"}
    server = serve(Metrics(), 0, checks=lambda: dict(state))
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        assert json.loads(req.urlopen(base + "/health").read()) == {"status": "ok", "service": "ml-detector"}
        assert json.loads(req.urlopen(base + "/ready").read())["checks"] == {"loki": "ok"}
        state["loki"] = "down"
        with pytest.raises(urllib.error.HTTPError) as err:
            req.urlopen(base + "/ready")
        assert err.value.code == 503
    finally:
        server.shutdown()


def test_invalid_gateway_url_is_a_handled_error_not_a_crash():
    # Vu au premier déploiement : « LLM_GATEWAY_URL=   # commentaire » donnait l'URL « # ex. http://... »,
    # et le ValueError d'urllib tuait le fil du signal de vie.
    from detector.gateway_client import GatewayClient, GatewayError
    with pytest.raises(GatewayError):
        GatewayClient("# ex. http://192.168.137.y:8080", "t" * 40).heartbeat({"statut": "ok"})


def test_uncaught_thread_error_is_logged_as_one_json_line(capsys):
    import threading
    from detector import logs
    root = logging.getLogger()
    saved = (root.handlers[:], root.level, threading.excepthook)
    try:
        logs.setup()
        worker = threading.Thread(target=lambda: 1 / 0, name="essai")
        worker.start()
        worker.join()
        out = capsys.readouterr().out
    finally:                                         # configuration globale : rendue aux autres tests
        root.handlers[:], threading.excepthook = saved[0], saved[2]
        root.setLevel(saved[1])
    line = json.loads(out.strip().splitlines()[0])
    assert (line["event"], line["fil"], line["level"]) == ("fil_arrete", "essai", "ERROR")
