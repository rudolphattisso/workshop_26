import pytest
from fastapi.testclient import TestClient

from conftest import FakeLLM, llm_output, load_cluster
from llm_gateway.analyzer import Analyzer
from llm_gateway.app import create_app
from llm_gateway.config import GatewayConfig


@pytest.fixture
def client(config):
    return TestClient(create_app(config, Analyzer(config, FakeLLM(llm_output()), "fake")))


def auth(config):
    return {"Authorization": f"Bearer {config.token}"}


def test_analyze_requires_token(client, config):
    body = {"cluster": load_cluster("heavy_requests")}
    assert client.post("/analyze", json=body).status_code == 401
    assert client.post("/analyze", json=body, headers={"Authorization": "Bearer faux"}).status_code == 401
    r = client.post("/analyze", json=body, headers=auth(config))
    assert r.status_code == 200 and r.json()["analysis"]["verdict"] == "attaque"


def test_invalid_payload_rejected(client, config):
    bad = load_cluster("heavy_requests")
    bad["signature"] = "../../etc/passwd"                   # sert aussi de nom de fichier
    assert client.post("/analyze", json={"cluster": bad}, headers=auth(config)).status_code == 422


def test_oversized_body_rejected(client, config):
    huge = {"cluster": load_cluster("heavy_requests"), "context": {"x": "a" * 300_000}}
    assert client.post("/analyze", json=huge, headers=auth(config)).status_code == 413


def test_health_and_weak_token(config):
    assert TestClient(create_app(config, Analyzer(config, FakeLLM(llm_output()), "fake"))).get("/health").json()["status"] == "ok"
    with pytest.raises(RuntimeError):
        create_app(GatewayConfig(token="court"), Analyzer(config, FakeLLM(llm_output()), "fake"))
