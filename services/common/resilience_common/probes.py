"""Sondes communes : /health (vivant), /ready (prêt), /metrics (Prometheus).

/health ne vérifie que le processus : un échec veut dire « redémarrer le conteneur ».
/ready vérifie les dépendances : un échec veut dire « le service tourne mais ne peut pas servir ».
Le moteur de remédiation s'appuie sur cette distinction pour choisir son action.
"""

import logging
import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as CheckTimeout

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, generate_latest

log = logging.getLogger("resilience.probes")

# Une vérification de dépendance : renvoie normalement si tout va bien, lève une exception sinon.
ReadyCheck = Callable[[], None]

# Une sonde doit répondre vite même si une dépendance « pend » (DNS lent, réseau coupé) :
# chaque vérification est bornée, et un dépassement compte comme une panne.
READY_CHECK_TIMEOUT = float(os.getenv("READY_CHECK_TIMEOUT_SECONDS", "2"))
_check_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ready-check")

DEPENDENCY_UP = Gauge(
    "service_dependency_up",
    "1 si la dépendance répond lors du dernier /ready, 0 sinon",
    ["service", "dependency"],
)


def build_probe_router(service: str, ready_checks: dict[str, ReadyCheck]) -> APIRouter:
    router = APIRouter(tags=["probes"])

    @router.get("/health")
    def health() -> dict:
        return {"status": "ok", "service": service}

    @router.get("/ready")
    def ready() -> JSONResponse:
        checks = {}
        for name, check in ready_checks.items():
            try:
                _check_executor.submit(check).result(timeout=READY_CHECK_TIMEOUT)
                checks[name] = "ok"
            except CheckTimeout:
                log.warning("dependency_timeout", extra={"dependency": name, "timeout_s": READY_CHECK_TIMEOUT})
                checks[name] = "down"
            except Exception as exc:
                log.warning("dependency_down", extra={"dependency": name, "error": type(exc).__name__})
                checks[name] = "down"
            DEPENDENCY_UP.labels(service, name).set(1 if checks[name] == "ok" else 0)
        all_ok = all(state == "ok" for state in checks.values())
        body = {"status": "ok" if all_ok else "down", "service": service, "checks": checks}
        return JSONResponse(body, status_code=200 if all_ok else 503)

    @router.get("/metrics")
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return router
