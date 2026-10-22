from datetime import timedelta

from detector.ip_history import IpHistory
from detector.models import HttpRequestLog
from scripts.scenarios import T0


def req(ip, s, method="GET", uri="/", status=200, ua="Mozilla/5.0"):
    return HttpRequestLog(T0 + timedelta(seconds=s), ip, method, uri, "HTTP/1.1", status, 100, "", ua)


def test_profile_counts_only_the_past_before_the_window():
    h = IpHistory()
    h.update([req("1.1.1.1", 0, "POST", "/api/payments", 201, "A"), req("1.1.1.1", 10, ua="B"),
              req("1.1.1.1", 20, uri="/?q=%3Cscript%3E", status=403, ua="B"), req("1.1.1.1", 100)])
    p = h.profile("1.1.1.1", before=T0 + timedelta(seconds=50))
    assert (p.n_requests, p.n_successful_writes, p.n_distinct_user_agents, p.n_payload_requests) == (3, 1, 2, 1)
    assert p.share_blocked == round(1 / 3, 3)
    assert h.profile("9.9.9.9", before=T0) is None


def test_history_forgets_beyond_its_horizon():
    h = IpHistory(horizon_s=3600)
    h.update([req("1.1.1.1", 0)])
    h.update([req("2.2.2.2", 4000)])                      # purge : 1.1.1.1 a plus d'une heure
    assert h.profile("1.1.1.1", before=T0 + timedelta(seconds=4001)) is None
    assert h.profile("2.2.2.2", before=T0 + timedelta(seconds=4001)).n_requests == 1
