"""Fabrique d'application : chaque service obtient le même socle en une ligne."""

import os

from fastapi import FastAPI

from resilience_common.logs import configure_logging
from resilience_common.observability import ObservabilityMiddleware
from resilience_common.probes import ReadyCheck, build_probe_router
from resilience_common.problems import register_problem_handlers


def create_app(
    service: str,
    ready_checks: dict[str, ReadyCheck] | None = None,
    public_prefix: str | None = None,
    **fastapi_kwargs,
) -> FastAPI:
    """Crée une application FastAPI avec logs JSON, trace_id, métriques, sondes et erreurs RFC 9457.

    Les sondes sont servies à la racine (/health, /ready, /metrics) pour Docker et Prometheus, sur le réseau
    interne. Avec `public_prefix` (ex. "/api/payments"), /health et /ready sont aussi servis sous ce préfixe,
    seul chemin que le WAF transmet : les sondes boîte noire testent ainsi le service *à travers* le WAF.
    /metrics n'y est jamais publié, pour ne pas exposer nos métriques sur Internet.

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
    if public_prefix:
        # Enregistrées avant les routes métier : /api/payments/ready ne doit pas être pris pour /api/payments/{id}.
        app.include_router(build_probe_router(service, ready_checks or {}, prefix=public_prefix, with_metrics=False))
    return app
