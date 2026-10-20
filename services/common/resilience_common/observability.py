"""Middleware d'observabilité : trace_id, métriques HTTP et log d'accès JSON.

- trace_id : repris de l'en-tête `X-Trace-Id` s'il est valide, sinon généré ; renvoyé dans la réponse
  et présent dans tous les logs de la requête (corrélation entre services dans Loki).
- Métriques : compteur et histogramme de latence par route *modèle* (`/payments/{paymentId}`),
  jamais par URL brute, pour ne pas faire exploser le nombre de séries Prometheus.
"""

import logging
import re
import time
import uuid

from prometheus_client import Counter, Histogram
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from resilience_common.logs import trace_id_var
from resilience_common.problems import problem

TRACE_HEADER = "X-Trace-Id"
# On n'accepte qu'un identifiant court et sans caractères spéciaux : pas d'injection dans les logs.
_TRACE_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{8,64}$")
# Requêtes de sondes et de scraping : comptées dans les métriques mais logguées en DEBUG pour ne pas noyer Loki.
_QUIET_PATHS = {"/health", "/ready", "/metrics"}

HTTP_REQUESTS = Counter(
    "http_requests_total",
    "Nombre de requêtes HTTP traitées",
    ["service", "method", "route", "status"],
)
HTTP_LATENCY = Histogram(
    "http_request_duration_seconds",
    "Durée de traitement des requêtes HTTP",
    ["service", "method", "route"],
)

log = logging.getLogger("resilience.http")


class ObservabilityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, service: str):
        super().__init__(app)
        self.service = service

    async def dispatch(self, request: Request, call_next) -> Response:
        incoming = request.headers.get(TRACE_HEADER, "")
        trace_id = incoming if _TRACE_ID_PATTERN.match(incoming) else uuid.uuid4().hex
        token = trace_id_var.set(trace_id)
        start = time.perf_counter()
        status = 500
        try:
            try:
                response = await call_next(request)
            except Exception:
                # Intercepté ici (et non plus haut) pour que la réponse 500 garde son trace_id.
                log.exception("unhandled_exception")
                response = problem(500, "Erreur interne")
            status = response.status_code
            response.headers[TRACE_HEADER] = trace_id
            return response
        finally:
            duration = time.perf_counter() - start
            # La route modèle n'est connue qu'après le routage ; "unmatched" pour les 404 hors routes.
            route = getattr(request.scope.get("route"), "path", "unmatched")
            HTTP_REQUESTS.labels(self.service, request.method, route, str(status)).inc()
            HTTP_LATENCY.labels(self.service, request.method, route).observe(duration)
            level = logging.DEBUG if request.url.path in _QUIET_PATHS else logging.INFO
            log.log(
                level,
                "http_request",
                extra={
                    "method": request.method,
                    "route": route,
                    "status": status,
                    "duration_ms": round(duration * 1000, 2),
                    "client_ip": request.client.host if request.client else None,
                },
            )
            trace_id_var.reset(token)
