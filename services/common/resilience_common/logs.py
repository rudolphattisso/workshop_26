"""Logs JSON sur stdout, au format de contracts/service-conventions.md.

Chaque ligne est un objet JSON : timestamp, level, service, trace_id, event, puis les champs
passés via `extra=`. Loki les collecte tels quels et l'équipe IA peut s'en servir comme features.

    log = logging.getLogger(__name__)
    log.info("payment_captured", extra={"payment_id": pid, "amount_cents": 2500})
"""

import json
import logging
import os
import sys
from contextvars import ContextVar
from datetime import datetime, timezone

# trace_id de la requête en cours : positionné par le middleware, lu par le formateur.
trace_id_var: ContextVar[str | None] = ContextVar("trace_id", default=None)

# Attributs standards d'un LogRecord : tout le reste vient de `extra=` et est ajouté au JSON.
# color_message : variante colorée qu'Uvicorn ajoute à ses messages, inutile en JSON.
_STANDARD_ATTRS = set(vars(logging.makeLogRecord({}))) | {"message", "asctime", "taskName", "color_message"}


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str):
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "service": self.service,
            "trace_id": trace_id_var.get(),
            "event": record.getMessage(),
            "logger": record.name,
        }
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS and key not in entry:
                entry[key] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str, ensure_ascii=False)


def configure_logging(service: str) -> None:
    """Remplace la configuration de logs (y compris celle d'Uvicorn) par une sortie JSON unique."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service))

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())

    # Uvicorn installe ses propres handlers texte : on les renvoie vers le handler JSON.
    for name in ("uvicorn", "uvicorn.error"):
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.propagate = True
    # Le log d'accès d'Uvicorn ferait doublon avec "http_request" (qui porte trace_id, route et durée).
    logging.getLogger("uvicorn.access").disabled = True
