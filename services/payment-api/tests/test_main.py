from fastapi.testclient import TestClient

from app import db
from app.main import app


def test_payment_api_exposes_common_probes():
    client = TestClient(app)
    assert client.get("/health").json() == {"status": "ok", "service": "payment-api"}
    assert "http_requests_total" in client.get("/metrics").text


def test_ready_ok_when_database_reachable():
    response = TestClient(app).get("/ready")
    assert response.status_code == 200
    assert response.json()["checks"] == {"database": "ok"}


def test_ready_is_published_under_the_waf_prefix():
    # Sonde boîte noire de l'Infra : http://bunkerweb:8080/api/payments/ready (et non /api/payments/{id}).
    response = TestClient(app).get("/api/payments/ready")
    assert response.status_code == 200
    assert response.json()["checks"] == {"database": "ok"}


def test_ready_503_when_database_unreachable(monkeypatch):
    # Port fermé : simule une base tombée. Les caches du moteur sont vidés avant et après.
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://nobody:nothing@127.0.0.1:1/none")
    db.get_engine.cache_clear()
    try:
        response = TestClient(app).get("/ready")
    finally:
        monkeypatch.undo()
        db.get_engine.cache_clear()
        db.get_sessionmaker.cache_clear()
    assert response.status_code == 503
    assert response.json()["checks"] == {"database": "down"}
