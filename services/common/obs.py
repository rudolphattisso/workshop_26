"""Observabilité commune aux services Python : logs JSON + métriques Prometheus.

Copié dans chaque image au build (voir Dockerfile). Contrat infra :
  - logs JSON sur stdout (collectés par Alloy -> Loki, sans fichier local)
  - /metrics au format Prometheus (scrapé par Prometheus sur le réseau monitoring)
"""
import json
import logging
import os
import sys
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

SERVICE = os.getenv("SERVICE_NAME", "unknown")

HTTP_REQUESTS = Counter(
    "http_requests_total", "Requêtes HTTP traitées", ["service", "method", "route", "status"]
)
HTTP_LATENCY = Histogram(
    "http_request_duration_seconds", "Latence des requêtes HTTP", ["service", "method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
)


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + "Z",
            "level": record.levelname.lower(),
            "service": SERVICE,
            "msg": record.getMessage(),
        }
        payload.update(getattr(record, "extra_fields", {}))
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def get_logger():
    logger = logging.getLogger(SERVICE)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))
        logger.propagate = False
    return logger


def log(level, msg, **fields):
    get_logger().log(level, msg, extra={"extra_fields": fields})


def read_secret(name, default=None):
    """Lit un secret Docker (/run/secrets/<name>) ; repli sur la variable d'env <NAME>."""
    path = os.getenv(f"{name.upper()}_FILE", f"/run/secrets/{name}")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return os.getenv(name.upper(), default)


def instrument(app: FastAPI):
    @app.middleware("http")
    async def _observe(request: Request, call_next):
        start = time.perf_counter()
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["x-request-id"] = request_id
            return response
        finally:
            route = request.scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            elapsed = time.perf_counter() - start
            if route_path != "/metrics":
                HTTP_REQUESTS.labels(SERVICE, request.method, route_path, str(status)).inc()
                HTTP_LATENCY.labels(SERVICE, request.method, route_path).observe(elapsed)
                log(
                    logging.WARNING if status >= 500 else logging.INFO,
                    "http_request",
                    request_id=request_id,
                    method=request.method,
                    route=route_path,
                    status=status,
                    duration_ms=round(elapsed * 1000, 2),
                    client_ip=request.headers.get("x-real-ip", request.client.host if request.client else ""),
                    user_agent=request.headers.get("user-agent", ""),
                )

    @app.get("/metrics", include_in_schema=False)
    def metrics():
        return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)
