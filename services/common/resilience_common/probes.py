"""Sondes communes : /health (vivant), /ready (prêt), /metrics (Prometheus).

/health ne vérifie que le processus : un échec veut dire « redémarrer le conteneur ».
/ready vérifie les dépendances : un échec veut dire « le service tourne mais ne peut pas servir ».
Le moteur de remédiation s'appuie sur cette distinction pour choisir son action.
"""

import logging
import os
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as CheckTimeout

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, generate_latest

log = logging.getLogger("resilience.probes")

# Une vérification de dépendance : renvoie normalement si tout va bien, lève une exception sinon.
ReadyCheck = Callable[[], None]

# Une sonde doit répondre vite même si une dépendance « pend » (DNS lent, réseau coupé) : les vérifications
# tournent en parallèle et /ready répond en READY_CHECK_TIMEOUT au plus, quel que soit leur nombre.
# Un dépassement compte comme une panne.
READY_CHECK_TIMEOUT = float(os.getenv("READY_CHECK_TIMEOUT_SECONDS", "2"))
_check_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="ready-check")

DEPENDENCY_UP = Gauge(
    "service_dependency_up",
    "1 si la dépendance répond lors du dernier /ready, 0 sinon",
    ["service", "dependency"],
)


def _run_checks(service: str, checks: dict[str, ReadyCheck]) -> dict[str, str]:
    """Lance toutes les vérifications en même temps et attend au plus READY_CHECK_TIMEOUT au total."""
    futures = {name: _check_executor.submit(check) for name, check in checks.items()}
    deadline = time.monotonic() + READY_CHECK_TIMEOUT
    states = {}
    for name, future in futures.items():
        try:
            future.result(timeout=max(0.0, deadline - time.monotonic()))
            states[name] = "ok"
        except CheckTimeout:
            log.warning("dependency_timeout", extra={"dependency": name, "timeout_s": READY_CHECK_TIMEOUT})
            states[name] = "down"
        except Exception as exc:
            log.warning("dependency_down", extra={"dependency": name, "error": type(exc).__name__})
            states[name] = "down"
        DEPENDENCY_UP.labels(service, name).set(1 if states[name] == "ok" else 0)
    return states


def build_probe_router(
    service: str,
    ready_checks: dict[str, ReadyCheck],
    info_checks: dict[str, ReadyCheck] | None = None,
    prefix: str = "",
    with_metrics: bool = True,
) -> APIRouter:
    """`ready_checks` décident de /ready (503 si l'un échoue). `info_checks` sont seulement rapportés dans `info` :
    une dépendance dont le service se passe un moment (ex. l'auth, grâce aux clés en cache) ne doit pas le faire
    déclarer « pas prêt », mais son état intéresse la supervision (lien entre services sur le dashboard)."""
    router = APIRouter(prefix=prefix, tags=["probes"])

    @router.get("/health")
    def health() -> dict:
        return {"status": "ok", "service": service}

    @router.get("/ready")
    def ready() -> JSONResponse:
        # Préfixe « info: » le temps du calcul : un seul lot parallèle pour les deux familles de vérifications.
        states = _run_checks(service, {**ready_checks, **{f"info:{n}": c for n, c in (info_checks or {}).items()}})
        checks = {name: states[name] for name in ready_checks}
        all_ok = all(state == "ok" for state in checks.values())
        body = {"status": "ok" if all_ok else "down", "service": service, "checks": checks}
        if info_checks:
            body["info"] = {name: states[f"info:{name}"] for name in info_checks}
        return JSONResponse(body, status_code=200 if all_ok else 503)

    if with_metrics:
        @router.get("/metrics")
        def metrics() -> Response:
            return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return router
