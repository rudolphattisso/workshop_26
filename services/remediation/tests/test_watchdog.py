import asyncio
import json
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY
from resilience_common.jwt_auth import CurrentUser

from app.topology import DEGRADED, DOWN, UNKNOWN, UP, Endpoints, evaluate, measure, snapshot
from app.watchdog import Watchdog, event_stream

ENDPOINTS = Endpoints(waf="http://waf", auth="http://auth", payment_api="http://pay", smoke_test="http://smoke")


class FakePlatform:
    """Imite les services sondés. Chaque test casse un élément et vérifie ce que voit le watchdog."""

    def __init__(self):
        self.down: set[str] = set()  # hôtes injoignables : waf, auth, pay, smoke
        self.payment_db = "ok"
        self.auth_db = "ok"
        self.jwks = "ok"
        self.smoke = {"ok": True, "duration_s": 0.12, "age_s": 3}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        host, path = request.url.host, request.url.path
        if host in self.down:
            raise httpx.ConnectError("injoignable", request=request)
        if host == "auth":
            return self._service(path, {"database": self.auth_db}, None)
        if host == "pay":
            return self._service(path, {"database": self.payment_db}, {"auth_jwks": self.jwks})
        if host == "smoke":
            return httpx.Response(200, json=self.smoke if path == "/last" else {"status": "ok"})
        # WAF : il répond même si un back-end est tombé (502), comme BunkerWeb
        if path == "/":
            return httpx.Response(200, text="<!doctype html>")
        backend = "auth" if path.startswith("/api/auth") else "pay"
        if backend in self.down:
            return httpx.Response(502, text="Bad Gateway")
        return self(httpx.Request("GET", f"http://{backend}/ready"))

    @staticmethod
    def _service(path, checks, info):
        if path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        ok = all(v == "ok" for v in checks.values())
        body = {"status": "ok" if ok else "down", "checks": checks, **({"info": info} if info else {})}
        return httpx.Response(200 if ok else 503, json=body)


def observe(platform: FakePlatform):
    return evaluate(measure(ENDPOINTS, transport=httpx.MockTransport(platform)))


def test_everything_up():
    nodes, links = observe(FakePlatform())
    assert {state for state, _ in nodes.values()} == {UP}
    assert {state for state, _ in links.values()} == {UP}


def test_payment_database_down():
    platform = FakePlatform()
    platform.payment_db = "down"
    nodes, links = observe(platform)
    assert nodes["payment-api"][0] == DEGRADED  # vivant mais pas prêt : ne pas le redémarrer pour rien
    assert nodes["payment-db"][0] == DOWN
    assert links[("payment-api", "payment-db")][0] == DOWN
    assert links[("bunkerweb", "payment-api")][0] == DOWN  # vu de l'extérieur, le service est indisponible
    assert nodes["auth"][0] == UP and links[("auth", "auth-db")][0] == UP


def test_auth_down():
    platform = FakePlatform()
    platform.down.add("auth")
    platform.jwks = "down"
    nodes, links = observe(platform)
    assert nodes["auth"][0] == DOWN
    assert nodes["auth-db"][0] == UNKNOWN  # on ne peut plus rien en dire : pas de faux « en panne »
    assert links[("bunkerweb", "auth")] == (DOWN, "HTTP 502")
    assert links[("payment-api", "auth")][0] == DOWN
    assert nodes["payment-api"][0] == UP  # payment-api continue avec ses clés en cache


def test_waf_down():
    platform = FakePlatform()
    platform.down.add("waf")
    nodes, links = observe(platform)
    assert nodes["bunkerweb"][0] == DOWN
    assert nodes["frontend"][0] == UNKNOWN
    assert links[("bunkerweb", "auth")][0] == UNKNOWN
    assert nodes["auth"][0] == UP  # les services internes vont bien


@pytest.mark.parametrize(
    ("smoke", "state", "words"),
    [
        ({"ok": False, "step": "payment", "error": "HTTP 503", "age_s": 2}, DOWN, "payment"),
        ({"ok": True, "duration_s": 0.1, "age_s": 300}, DOWN, "périmé"),
        ({"ok": None, "age_s": None}, UNKNOWN, "aucune transaction"),
    ],
)
def test_end_to_end_transaction_link(smoke, state, words):
    platform = FakePlatform()
    platform.smoke = smoke
    _, links = observe(platform)
    assert links[("smoke-test", "bunkerweb")][0] == state
    assert words in links[("smoke-test", "bunkerweb")][1]


# ------------------------------------------------------------------ watchdog


def make_watchdog(platform: FakePlatform) -> Watchdog:
    return Watchdog(lambda: snapshot(*observe(platform)), interval=0)


def test_state_changes_are_recorded_most_recent_first():
    platform = FakePlatform()
    watchdog = make_watchdog(platform)
    watchdog.tick()
    assert watchdog.current()[1]["changes"] == []  # premier passage : rien n'a « changé »

    platform.payment_db = "down"
    watchdog.tick()
    platform.payment_db = "ok"
    watchdog.tick()

    changes = watchdog.current()[1]["changes"]
    db = [c for c in changes if c["id"] == "payment-api->payment-db"]
    assert [(c["from"], c["to"]) for c in db] == [(DOWN, UP), (UP, DOWN)]
    assert db[0]["label"] == "API paiement → Base paiement"


def test_metrics_follow_the_state():
    platform = FakePlatform()
    watchdog = make_watchdog(platform)
    platform.down.add("auth")
    watchdog.tick()
    assert REGISTRY.get_sample_value("remediation_component_up", {"kind": "node", "id": "auth"}) == 0
    platform.down.clear()
    watchdog.tick()
    assert REGISTRY.get_sample_value("remediation_component_up", {"kind": "node", "id": "auth"}) == 1


def test_event_stream_sends_state_then_heartbeat():
    watchdog = make_watchdog(FakePlatform())
    watchdog.tick()
    calls = {"n": 0}

    async def disconnected():
        calls["n"] += 1
        return calls["n"] > 3

    async def collect():
        return [chunk async for chunk in event_stream(watchdog, disconnected, poll=0, heartbeat=0)]

    chunks = asyncio.run(collect())
    assert chunks[0].startswith("event: services\n")
    assert json.loads(chunks[0].split("data: ", 1)[1])["nodes"][0]["name"] == "bunkerweb"
    assert all(c.startswith("event: heartbeat\n") for c in chunks[1:])


# ------------------------------------------------------------------ API


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("WATCHDOG_INTERVAL_SECONDS", "0")
    from app.main import app, get_watchdog
    from app.security import get_current_user

    watchdog = make_watchdog(FakePlatform())
    app.dependency_overrides[get_watchdog] = lambda: watchdog
    get_watchdog.cache_clear()

    def as_role(role):
        app.dependency_overrides[get_current_user] = lambda: CurrentUser(id=uuid.uuid4(), role=role)

    with TestClient(app) as client:
        yield client, watchdog, as_role
    app.dependency_overrides.clear()
    get_watchdog.cache_clear()


def test_services_requires_a_token(api):
    client, _, _ = api
    assert client.get("/services").status_code == 401


def test_services_is_operator_only(api):
    client, watchdog, as_role = api
    watchdog.tick()
    as_role("client")
    assert client.get("/services").status_code == 403
    as_role("operator")
    body = client.get("/services").json()
    assert len(body["nodes"]) == 7 and len(body["links"]) == 7


def test_services_503_before_first_pass(api):
    client, _, as_role = api
    as_role("operator")
    assert client.get("/services").status_code == 503


def test_engine_exposes_common_probes(api):
    client, _, _ = api
    assert client.get("/health").json() == {"status": "ok", "service": "remediation"}
    _, watchdog, _ = api
    watchdog.tick()
    assert 'remediation_component_up{id="auth",kind="node"} 1.0' in client.get("/metrics").text
