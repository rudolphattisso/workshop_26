"""Topologie surveillée : les composants (nœuds) et les connexions entre eux (liens).

Chaque état est **mesuré**, jamais supposé : un appel HTTP réel par mesure, lancé depuis le réseau interne.

| Mesure | Ce qu'elle prouve |
|---|---|
| `/health`, `/ready` de auth et payment-api | le processus vit ; il peut servir |
| `checks.database` de `/ready` | lien service → sa base |
| `info.auth_jwks` du `/ready` de payment-api | lien payment-api → auth (clés publiques) |
| `/`, `/api/auth/ready`, `/api/payments/ready` à travers le WAF | liens WAF → front, auth, payment-api |
| `/last` du smoke test | la dernière transaction de bout en bout (sans en déclencher une) |

`evaluate()` est une fonction pure (mesures → états) : testable sans réseau.
"""

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

UP, DEGRADED, DOWN, UNKNOWN = "up", "degraded", "down", "unknown"

# (nom, libellé, rôle). Le nom est celui du service Compose de l'Infra quand il existe : c'est la cible des
# remédiations (contracts/alert.schema.json). Les deux bases sont hébergées par le conteneur `postgres`.
NODES = [
    ("bunkerweb", "WAF", "edge"),
    ("frontend", "Front web", "app"),
    ("auth", "Auth", "app"),
    ("payment-api", "API paiement", "app"),
    ("auth-db", "Base auth", "data"),
    ("payment-db", "Base paiement", "data"),
    ("smoke-test", "Smoke test", "probe"),
]

# (source, cible, libellé) : la source appelle la cible.
LINKS = [
    ("bunkerweb", "frontend", "HTTP"),
    ("bunkerweb", "auth", "HTTP /api/auth"),
    ("bunkerweb", "payment-api", "HTTP /api/payments"),
    ("payment-api", "auth", "Clés JWKS"),
    ("auth", "auth-db", "SQL"),
    ("payment-api", "payment-db", "SQL"),
    ("smoke-test", "bunkerweb", "Transaction de bout en bout"),
]

LABELS = {name: label for name, label, _ in NODES}


@dataclass(frozen=True)
class Endpoints:
    waf: str
    auth: str
    payment_api: str
    smoke_test: str


def endpoints_from_env() -> Endpoints:
    return Endpoints(
        waf=os.getenv("WATCH_WAF_URL", "http://bunkerweb:8080"),
        auth=os.getenv("WATCH_AUTH_URL", "http://auth:8000"),
        payment_api=os.getenv("WATCH_PAYMENT_API_URL", "http://payment-api:8000"),
        smoke_test=os.getenv("WATCH_SMOKE_TEST_URL", "http://txprobe:8000"),
    )


@dataclass(frozen=True)
class Http:
    """Résultat d'un appel : `status` vaut None si le service n'a pas répondu du tout."""

    status: int | None
    body: Any = None
    error: str | None = None

    @property
    def reached(self) -> bool:
        return self.status is not None

    @property
    def why(self) -> str:
        return f"HTTP {self.status}" if self.reached else (self.error or "injoignable")


def _get(client: httpx.Client, url: str) -> Http:
    try:
        response = client.get(url)
    except httpx.HTTPError as exc:
        return Http(None, error=type(exc).__name__)
    try:
        body = response.json()
    except ValueError:
        body = None  # ex. la page HTML du front
    return Http(response.status_code, body)


def measure(endpoints: Endpoints, transport: httpx.BaseTransport | None = None, timeout: float = 3.5) -> dict[str, Http]:
    """Toutes les mesures en parallèle : un passage dure au plus `timeout`, même si plusieurs services pendent.

    3,5 s : plus que la limite de /ready (2 s, READY_CHECK_TIMEOUT_SECONDS) ; quand une dépendance pend, on reçoit
    quand même la réponse détaillée du service (« base : down ») au lieu d'un simple délai dépassé."""
    urls = {
        "auth_health": f"{endpoints.auth}/health",
        "auth_ready": f"{endpoints.auth}/ready",
        "pay_health": f"{endpoints.payment_api}/health",
        "pay_ready": f"{endpoints.payment_api}/ready",
        "smoke_health": f"{endpoints.smoke_test}/health",
        "smoke_last": f"{endpoints.smoke_test}/last",
        "waf_root": f"{endpoints.waf}/",
        "waf_auth": f"{endpoints.waf}/api/auth/ready",
        "waf_pay": f"{endpoints.waf}/api/payments/ready",
    }
    with httpx.Client(timeout=timeout, transport=transport, headers={"User-Agent": "resilience-watchdog/1.0"}) as client:
        with ThreadPoolExecutor(max_workers=len(urls)) as pool:
            futures = {key: pool.submit(_get, client, url) for key, url in urls.items()}
            return {key: future.result() for key, future in futures.items()}


def _service(health: Http, ready: Http) -> tuple[str, str]:
    if health.status != 200:
        return DOWN, f"/health : {health.why}"
    if ready.status != 200:
        return DEGRADED, f"vivant mais pas prêt (/ready : {ready.why})"
    return UP, "vivant et prêt"


def _dependency(ready: Http, section: str, name: str) -> tuple[str, str]:
    """État d'une dépendance tel que rapporté par le /ready du service qui l'utilise."""
    if not isinstance(ready.body, dict):
        return UNKNOWN, f"service appelant injoignable ({ready.why})"
    state = ready.body.get(section, {}).get(name)
    if state == "ok":
        return UP, "connexion OK"
    if state == "down":
        return DOWN, "connexion en échec"
    return UNKNOWN, "non rapporté"


def _through_waf(waf_root: Http, call: Http) -> tuple[str, str]:
    if not waf_root.reached:
        return UNKNOWN, "WAF injoignable"
    return (UP, "OK") if call.status == 200 else (DOWN, call.why)


def _smoke(last: Http, stale_after: float) -> tuple[str, str]:
    if not isinstance(last.body, dict):
        return UNKNOWN, f"smoke test injoignable ({last.why})"
    result = last.body
    if result.get("ok") is None:
        return UNKNOWN, "aucune transaction pour l'instant"
    age = result.get("age_s") or 0
    if age > stale_after:
        return DOWN, f"résultat périmé (dernière transaction il y a {age:.0f} s)"
    if result["ok"]:
        return UP, f"réussie il y a {age:.0f} s ({result.get('duration_s', 0) * 1000:.0f} ms)"
    return DOWN, f"échec à l'étape « {result.get('step')} » : {result.get('error')}"


def evaluate(m: dict[str, Http], stale_after: float = 45.0) -> tuple[dict[str, tuple[str, str]], dict[tuple[str, str], tuple[str, str]]]:
    """Mesures → (état, explication) de chaque nœud et de chaque lien."""
    auth_db = _dependency(m["auth_ready"], "checks", "database")
    payment_db = _dependency(m["pay_ready"], "checks", "database")
    if not m["waf_root"].reached:
        frontend = (UNKNOWN, "WAF injoignable")
    elif m["waf_root"].status == 200:
        frontend = (UP, "page servie")
    else:
        frontend = (DOWN, m["waf_root"].why)

    nodes = {
        "bunkerweb": (UP, "répond") if m["waf_root"].reached else (DOWN, m["waf_root"].why),
        "frontend": frontend,
        "auth": _service(m["auth_health"], m["auth_ready"]),
        "payment-api": _service(m["pay_health"], m["pay_ready"]),
        "auth-db": auth_db,
        "payment-db": payment_db,
        "smoke-test": (UP, "vivant") if m["smoke_health"].status == 200 else (DOWN, m["smoke_health"].why),
    }
    links = {
        ("bunkerweb", "frontend"): frontend,
        ("bunkerweb", "auth"): _through_waf(m["waf_root"], m["waf_auth"]),
        ("bunkerweb", "payment-api"): _through_waf(m["waf_root"], m["waf_pay"]),
        ("payment-api", "auth"): _dependency(m["pay_ready"], "info", "auth_jwks"),
        ("auth", "auth-db"): auth_db,
        ("payment-api", "payment-db"): payment_db,
        ("smoke-test", "bunkerweb"): _smoke(m["smoke_last"], stale_after),
    }
    return nodes, links


def snapshot(nodes: dict, links: dict) -> dict:
    """Format publié par GET /services et le flux /events (contracts/openapi-remediation.yaml, `Topology`)."""
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "nodes": [
            {"name": name, "label": label, "role": role, "state": nodes[name][0], "detail": nodes[name][1]}
            for name, label, role in NODES
        ],
        "links": [
            {"source": s, "target": t, "label": label, "state": links[(s, t)][0], "detail": links[(s, t)][1]}
            for s, t, label in LINKS
        ],
    }
