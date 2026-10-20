"""Fabrique d'application : chaque service obtient le même socle en une ligne."""

import os

from fastapi import FastAPI

from resilience_common.logs import configure_logging
from resilience_common.observability import ObservabilityMiddleware
from resilience_common.probes import ReadyCheck, build_probe_router
from resilience_common.problems import register_problem_handlers


def create_app(service: str, ready_checks: dict[str, ReadyCheck] | None = None, **fastapi_kwargs) -> FastAPI:
    """Crée une application FastAPI avec logs JSON, trace_id, métriques, sondes et erreurs RFC 9457.

    La documentation interactive (/docs, /openapi.json) n'est servie que si ENABLE_DOCS=true :
    utile en développement, désactivée par défaut pour ne pas exposer la surface d'API.
    """
    configure_logging(service)

    if os.getenv("ENABLE_DOCS", "false").lower() != "true":
        fastapi_kwargs.setdefault("docs_url", None)
        fastapi_kwargs.setdefault("redoc_url", None)
        fastapi_kwargs.setdefault("openapi_url", None)

    app = FastAPI(title=service, **fastapi_kwargs)
    app.add_middleware(ObservabilityMiddleware, service=service)
    register_problem_handlers(app)
    app.include_router(build_probe_router(service, ready_checks or {}))
    return app
