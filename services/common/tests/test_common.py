import json
import logging
import time

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field

from resilience_common import create_app
from resilience_common.logs import JsonFormatter, trace_id_var


class Item(BaseModel):
    amount_cents: int = Field(gt=0)


def failing_check() -> None:
    raise ConnectionError("db unreachable")


def make_client(ready_checks=None) -> TestClient:
    app = create_app("test-svc", ready_checks=ready_checks)

    @app.get("/items/{item_id}")
    def get_item(item_id: int) -> dict:
        if item_id == 0:
            raise HTTPException(404, "Introuvable")
        return {"id": item_id}

    @app.post("/items")
    def post_item(item: Item) -> Item:
        return item

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError("secret interne")

    return TestClient(app, raise_server_exceptions=False)


def test_health_is_ok():
    response = make_client().get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "test-svc"}


def test_ready_ok_without_checks():
    response = make_client().get("/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_ready_503_when_a_dependency_is_down():
    response = make_client({"database": failing_check}).get("/ready")
    assert response.status_code == 503
    assert response.json()["checks"] == {"database": "down"}


def test_ready_answers_fast_when_a_dependency_hangs(monkeypatch):
    monkeypatch.setattr("resilience_common.probes.READY_CHECK_TIMEOUT", 0.2)
    start = time.perf_counter()
    response = make_client({"database": lambda: time.sleep(2)}).get("/ready")
    assert time.perf_counter() - start < 1
    assert response.status_code == 503
    assert response.json()["checks"] == {"database": "down"}


def test_hanging_checks_run_in_parallel(monkeypatch):
    """Deux dépendances qui pendent : /ready répond en un seul délai, pas en deux (sinon le watchdog abandonne)."""
    monkeypatch.setattr("resilience_common.probes.READY_CHECK_TIMEOUT", 0.3)
    hang = lambda: time.sleep(2)  # noqa: E731
    app = create_app("test-svc", ready_checks={"database": hang}, info_checks={"auth_jwks": hang})
    start = time.perf_counter()
    body = TestClient(app).get("/ready").json()
    assert time.perf_counter() - start < 0.6
    assert body["checks"] == {"database": "down"} and body["info"] == {"auth_jwks": "down"}


def test_info_checks_are_reported_without_failing_ready():
    app = create_app(
        "test-svc",
        ready_checks={"database": lambda: None},
        info_checks={"auth_jwks": failing_check},
        public_prefix="/api/items",
    )
    client = TestClient(app)
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json()["info"] == {"auth_jwks": "down"}
    assert "info" not in client.get("/api/items/ready").json()  # pas exposé à travers le WAF


def test_public_prefix_serves_health_and_ready_but_not_metrics():
    app = create_app("test-svc", public_prefix="/api/items")

    @app.get("/api/items/{item_id}")
    def get_item(item_id: int) -> dict:
        return {"id": item_id}

    client = TestClient(app)
    # Les sondes sont enregistrées avant les routes métier : « ready » n'est pas pris pour un item_id.
    assert client.get("/api/items/ready").json()["status"] == "ok"
    assert client.get("/api/items/health").json()["status"] == "ok"
    assert client.get("/api/items/metrics").status_code != 200
    assert client.get("/metrics").status_code == 200  # toujours servi à la racine, sur le réseau interne


def test_trace_id_is_generated_and_returned():
    response = make_client().get("/health")
    assert len(response.headers["X-Trace-Id"]) == 32


def test_valid_incoming_trace_id_is_propagated():
    response = make_client().get("/health", headers={"X-Trace-Id": "abc-12345678"})
    assert response.headers["X-Trace-Id"] == "abc-12345678"


def test_malicious_trace_id_is_replaced():
    response = make_client().get("/health", headers={"X-Trace-Id": "x\"}\n{\"level\":\"FAKE"})
    assert response.headers["X-Trace-Id"] != "x\"}\n{\"level\":\"FAKE"


def test_http_error_uses_problem_json():
    response = make_client().get("/items/0", headers={"X-Trace-Id": "trace-0000001"})
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["title"] == "Introuvable"
    assert response.json()["trace_id"] == "trace-0000001"


def test_validation_error_names_field_without_echoing_value():
    response = make_client().post("/items", json={"amount_cents": -5})
    assert response.status_code == 400
    body = response.json()
    assert "amount_cents" in body["detail"]
    assert "-5" not in body["detail"]


def test_unexpected_error_hides_internals_and_keeps_trace_id():
    response = make_client().get("/boom", headers={"X-Trace-Id": "trace-0000002"})
    assert response.status_code == 500
    assert "secret interne" not in response.text
    assert response.json()["trace_id"] == "trace-0000002"
    assert response.headers["X-Trace-Id"] == "trace-0000002"


def test_metrics_use_route_template_not_raw_path():
    client = make_client()
    client.get("/items/42")
    metrics = client.get("/metrics").text
    assert 'route="/items/{item_id}"' in metrics
    assert 'route="/items/42"' not in metrics


def test_docs_disabled_by_default():
    assert make_client().get("/docs").status_code == 404


def test_docs_enabled_by_env(monkeypatch):
    monkeypatch.setenv("ENABLE_DOCS", "true")
    assert make_client().get("/docs").status_code == 200


def test_json_log_has_contract_fields():
    record = logging.makeLogRecord({"msg": "payment_captured", "levelname": "INFO", "payment_id": "p1"})
    token = trace_id_var.set("trace-xyz")
    try:
        line = json.loads(JsonFormatter("test-svc").format(record))
    finally:
        trace_id_var.reset(token)
    for field in ("timestamp", "level", "service", "trace_id", "event"):
        assert field in line
    assert line["trace_id"] == "trace-xyz"
    assert line["event"] == "payment_captured"
    assert line["payment_id"] == "p1"


@pytest.fixture(autouse=True)
def _no_docs_env(monkeypatch):
    monkeypatch.delenv("ENABLE_DOCS", raising=False)
