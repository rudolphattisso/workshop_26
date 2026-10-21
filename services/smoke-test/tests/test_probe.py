import json
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY
from resilience_common.identity import account_id

from app.probe import AMOUNT_CENTS, ProbeConfig, TransactionProbe

CONFIG = ProbeConfig(target="http://waf", username="smoke-client", password="smoke-password-123", timeout=1)
OWN = str(account_id("smoke-client"))
MERCHANT = str(account_id("smoke-merchant"))


class FakePlatform:
    """Imite auth + payment-api derrière le WAF. Chaque test casse une étape pour vérifier le diagnostic."""

    def __init__(self, login_status=200, payment_status="CAPTURED", readback_amount=AMOUNT_CENTS, down=False):
        self.login_status = login_status
        self.payment_status = payment_status
        self.readback_amount = readback_amount
        self.down = down
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.down:
            raise httpx.ConnectError("WAF injoignable", request=request)
        path = request.url.path
        if path == "/api/auth/login":
            if self.login_status != 200:
                return httpx.Response(self.login_status, json={"title": "Identifiants invalides"})
            assert json.loads(request.content) == {"username": "smoke-client", "password": "smoke-password-123"}
            return httpx.Response(200, json={"access_token": "jwt", "token_type": "Bearer", "expires_in": 900})
        assert request.headers["Authorization"] == "Bearer jwt"
        if path == "/api/accounts":
            return httpx.Response(200, json=[{"id": OWN, "balance_cents": 99_999}])
        if path == "/api/payments" and request.method == "POST":
            order = json.loads(request.content)
            assert (order["from_account_id"], order["to_account_id"]) == (OWN, MERCHANT)
            rejected = self.payment_status == "REJECTED"
            return httpx.Response(422 if rejected else 201, json={
                "id": "pay-1", "status": self.payment_status, "amount_cents": order["amount_cents"],
                "rejection_reason": "INSUFFICIENT_FUNDS" if rejected else None,
            })
        if path == "/api/payments/pay-1":
            return httpx.Response(200, json={"id": "pay-1", "status": "CAPTURED", "amount_cents": self.readback_amount})
        return httpx.Response(404)


def probe_with(platform: FakePlatform) -> TransactionProbe:
    return TransactionProbe(CONFIG, transport=httpx.MockTransport(platform))


def metric(name: str, **labels) -> float | None:
    return REGISTRY.get_sample_value(name, labels)


def test_successful_transaction_walks_the_whole_customer_journey():
    platform = FakePlatform()
    result = probe_with(platform).run()

    assert result["ok"] is True
    assert result["tx_id"] == "pay-1"
    assert [r.url.path for r in platform.requests] == [
        "/api/auth/login", "/api/accounts", "/api/payments", "/api/payments/pay-1",
    ]
    assert metric("synthetic_transaction_success") == 1
    assert metric("synthetic_account_balance_cents") == 99_999


def test_one_trace_id_follows_the_transaction_and_is_the_idempotency_key():
    platform = FakePlatform()
    result = probe_with(platform).run()

    assert {r.headers["X-Trace-Id"] for r in platform.requests} == {result["trace_id"]}
    payment = next(r for r in platform.requests if r.method == "POST" and r.url.path == "/api/payments")
    assert payment.headers["Idempotency-Key"] == result["trace_id"]
    assert json.loads(payment.content)["amount_cents"] == 1


def test_each_run_is_a_new_payment():
    platform = FakePlatform()
    probe = probe_with(platform)
    assert probe.run()["trace_id"] != probe.run()["trace_id"]


@pytest.mark.parametrize(
    ("platform", "step", "error"),
    [
        (FakePlatform(down=True), "login", "ConnectError"),
        (FakePlatform(login_status=401), "login", "HTTP 401"),
        (FakePlatform(login_status=429), "login", "HTTP 429"),  # limitation de débit du WAF
        (FakePlatform(payment_status="REJECTED"), "payment", "HTTP 422"),
        (FakePlatform(readback_amount=500), "readback", "ne correspond pas"),
    ],
)
def test_failure_reports_the_broken_step_without_raising(platform, step, error):
    before = metric("synthetic_transactions_total", result="failure", step=step) or 0
    result = probe_with(platform).run()

    assert result["ok"] is False
    assert result["step"] == step
    assert error in result["error"]
    assert metric("synthetic_transaction_success") == 0
    assert metric("synthetic_transactions_total", result="failure", step=step) == before + 1


def test_password_never_appears_in_the_failure_report():
    result = probe_with(FakePlatform(login_status=401)).run()
    assert CONFIG.password not in json.dumps(result)


# ------------------------------------------------------------------ service HTTP


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("PROBE_PASSWORD", "smoke-password-123")
    monkeypatch.setenv("PROBE_INTERVAL_SECONDS", "0")  # pas de boucle de fond pendant les tests
    from app.main import app, get_probe

    platform = FakePlatform()
    app.dependency_overrides[get_probe] = lambda: probe_with(platform)
    with TestClient(app) as test_client:
        yield test_client, platform
    app.dependency_overrides.clear()
    get_probe.cache_clear()


def test_check_returns_200_with_the_txprobe_contract(client):
    test_client, _ = client
    response = test_client.get("/check")
    assert response.status_code == 200
    assert {"ok", "tx_id", "duration_s"} <= response.json().keys()


def test_check_returns_503_when_the_platform_is_down(client):
    test_client, platform = client
    platform.down = True
    response = test_client.get("/check")
    assert response.status_code == 503
    assert response.json()["ok"] is False


def test_service_exposes_probes_and_synthetic_metrics(client):
    test_client, _ = client
    test_client.get("/check")
    assert test_client.get("/health").json() == {"status": "ok", "service": "smoke-test"}
    assert "synthetic_transaction_success" in test_client.get("/metrics").text


def test_missing_password_stops_the_service_at_startup(monkeypatch):
    monkeypatch.delenv("PROBE_PASSWORD", raising=False)
    monkeypatch.delenv("PROBE_PASSWORD_FILE", raising=False)
    from app.main import app, get_probe

    get_probe.cache_clear()
    with pytest.raises(Exception, match="PROBE_PASSWORD"):
        with TestClient(app):
            pass
    get_probe.cache_clear()


def test_account_ids_match_payment_api_seed():
    assert OWN == str(uuid.uuid5(uuid.NAMESPACE_URL, "resilience-alpha:account:smoke-client"))
