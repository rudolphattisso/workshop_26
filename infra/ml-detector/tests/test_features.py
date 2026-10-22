from datetime import datetime, timedelta, timezone

import pytest

from detector.features import FEATURE_NAMES, FeatureExtractor, attack_signals, path_template
from detector.models import HttpRequestLog

T0 = datetime(2026, 10, 20, 14, 0, tzinfo=timezone.utc)


def req(uri="/", method="GET", status=200, ip="192.168.137.20", ua="Mozilla/5.0", dt=0.0):
    return HttpRequestLog(ts=T0 + timedelta(seconds=dt), client_ip=ip, method=method, uri=uri,
                          protocol="HTTP/1.1", status=status, bytes_sent=100, user_agent=ua)


@pytest.mark.parametrize("uri, signal", [
    ("/api/payments?limit=1%27%20OR%20%271%27%3D%271", "sqli_hits"),
    ("/api/payments?id=%27%20UNION%20SELECT%20username,password_hash%20FROM%20users--", "sqli_hits"),
    ("/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "xss_hits"),
    ("/?q=<img%20src=x%20onerror=alert(1)>", "xss_hits"),
    ("/?file=..%2f..%2f..%2fetc%2fpasswd", "traversal_hits"),
    ("/?file=%252e%252e%252fetc%252fpasswd", "traversal_hits"),   # double encodage
    ("/?host=127.0.0.1%3Bcat%20/etc/hosts", "cmdi_hits"),
    ("/.git/config", "scanner_path"),
])
def test_attack_signals_detected(uri, signal):
    assert attack_signals(uri)[signal] > 0


@pytest.mark.parametrize("uri", ["/", "/api/payments?limit=20", "/api/auth/login",
                                 "/api/payments/0b6a6b0e-6f2c-4c5e-9a43-2d1f8c3b9e10"])
def test_legit_uris_have_no_signal(uri):
    assert not any(attack_signals(uri).values())


def test_path_template_groups_identifiers():
    assert path_template("/api/payments/0b6a6b0e-6f2c-4c5e-9a43-2d1f8c3b9e10?x=1") == "/api/payments/{uuid}"
    assert path_template("/api/orders/123") == "/api/orders/{n}"


def test_matrix_shape_and_path_rarity():
    ex = FeatureExtractor().fit([req("/api/payments")] * 9)
    X = ex.transform([req("/api/payments"), req("/wp-admin/")])
    assert X.shape == (2, len(FEATURE_NAMES))
    rarity = FEATURE_NAMES.index("path_rarity")
    assert X[0, rarity] == pytest.approx(0.1) and X[1, rarity] == 1.0


def test_window_features_capture_rate_and_auth_failures():
    flood = [req("/api/auth/login", "POST", 401, ip="10.0.0.66", dt=i * 0.1) for i in range(100)]
    calm = [req("/", ip="192.168.137.21", dt=i * 10) for i in range(5)]
    ex = FeatureExtractor(window_seconds=60)
    X = ex.transform(flood + calm)
    rate, fails = FEATURE_NAMES.index("ip_req_per_min"), FEATURE_NAMES.index("ip_auth_failures")
    assert X[99, rate] > X[104, rate] + 2.5        # log1p(100/min) = 4.6 vs log1p(5/min) = 1.8
    assert X[99, fails] > X[104, fails]


@pytest.mark.parametrize("waf_status", [403, 429, 444])
def test_features_ignore_waf_decision(waf_status):
    """Le module doit trouver ce que le WAF ne voit pas : sa décision n'entre dans aucune feature.
    Une réponse du WAF (page de blocage de 69 298 octets) vaut un 200 de taille médiane."""
    def stream(status, size):
        return [HttpRequestLog(ts=T0 + timedelta(seconds=i), client_ip="10.0.0.66", method=method,
                               uri="/?q=%3Cscript%3E", protocol="HTTP/1.1", status=status,
                               bytes_sent=size, user_agent="x")
                for i in range(30) for method in ("GET", "POST")]
    ex = FeatureExtractor().fit([req()])                       # taille médiane apprise : 100
    assert (ex.transform(stream(waf_status, 69298)) == ex.transform(stream(200, 100))).all()


def test_waf_403_on_login_is_not_an_auth_failure():
    banned = [req("/api/auth/login", "POST", 403, dt=i) for i in range(10)]
    X = FeatureExtractor().transform(banned)
    assert X[-1, FEATURE_NAMES.index("ip_auth_failures")] == 0


def test_window_forgets_old_requests():
    old = [req(dt=i) for i in range(30)]
    later = req(dt=200)                             # 200 s après : hors fenêtre de 60 s
    X = FeatureExtractor(window_seconds=60).transform(old + [later])
    assert X[-1, FEATURE_NAMES.index("ip_req_per_min")] == pytest.approx(0.6931, abs=1e-3)  # log1p(1)
