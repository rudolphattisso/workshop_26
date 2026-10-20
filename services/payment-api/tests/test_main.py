from fastapi.testclient import TestClient

from app.main import app


def test_payment_api_exposes_common_probes():
    client = TestClient(app)
    assert client.get("/health").json() == {"status": "ok", "service": "payment-api"}
    assert client.get("/ready").status_code == 200
    assert "http_requests_total" in client.get("/metrics").text
