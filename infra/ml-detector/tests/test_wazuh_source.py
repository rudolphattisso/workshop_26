import json
from datetime import datetime, timezone

from detector.parsing import parse_line
from detector.sources.wazuh import WazuhJsonlSource

ACCESS = ('localhost 172.30.10.1 - 68b7cd9283258c88b03e70f37c2a147a - [19/Oct/2026:12:50:05 +0000] '
          '"GET /?q=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E HTTP/1.1" 403 69298 "-" "resilience-labtest/1.0"')
HEALTH = ('bwapi 172.30.80.3 - 8d093f3ff370ee75e361d6f399b0c4f9 - [19/Oct/2026:12:49:36 +0000] '
          '"GET /health HTTP/1.1" 444 0 "-" "bwapi"')
ERRORLOG = '2026/10/19 12:50:05 [warn] 183#183: *7468 ModSecurity: Warning. detected XSS using libinjection.'


def _alert(decoder, full_log):
    return json.dumps({"decoder": {"name": decoder}, "full_log": full_log, "rule": {"id": "31101"}})


def test_parse_bunkerweb_line_with_request_id():
    rec = parse_line(ACCESS)
    assert rec is not None
    assert (rec.host, rec.client_ip, rec.method, rec.status, rec.user_agent) == (
        "localhost", "172.30.10.1", "GET", 403, "resilience-labtest/1.0")
    assert rec.uri.startswith("/?q=%3Cimg")


def test_wazuh_source_keeps_only_client_access_logs(tmp_path):
    path = tmp_path / "alerts.jsonl"
    path.write_text("\n".join([
        _alert("web-accesslog", ACCESS),
        _alert("web-accesslog", HEALTH),
        _alert("nginx-errorlog", ERRORLOG),
        json.dumps({"_source": json.loads(_alert("web-accesslog", ACCESS.replace("12:50:05", "12:50:01")))}),
        json.dumps({"rule": {"id": "502"}}),
        "pas du json",
        "",
    ]), encoding="utf-8")

    records = WazuhJsonlSource(path).read_all()
    assert [r.ts.second for r in records] == [1, 5]          # triées, bwapi et non-accès exclus
    assert all(r.host == "localhost" for r in records)

    window = WazuhJsonlSource(path).fetch(datetime(2026, 10, 19, 12, 50, 3, tzinfo=timezone.utc),
                                          datetime(2026, 10, 19, 12, 51, tzinfo=timezone.utc))
    assert len(window) == 1 and window[0].ts.second == 5
