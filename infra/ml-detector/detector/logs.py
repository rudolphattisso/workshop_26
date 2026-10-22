"""Journal au format commun (contracts/service-conventions.md, même sortie que
services/common/resilience_common/logs.py) : une ligne JSON par événement sur stdout, avec
timestamp, level, service, trace_id, event, logger, puis les champs propres à l'événement.
Alloy l'envoie à Loki sous {service="ml-detector"} ; le tableau Grafana filtre sur "event".

Le détecteur journalise un objet JSON ({"event": "rapport", ...}) : ses champs sont remontés au
premier niveau. Un message texte devient l'événement "message" avec son texte dans "message".
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str = "ml-detector"):
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        text = record.getMessage()
        try:
            fields = json.loads(text)
            if not isinstance(fields, dict):
                raise ValueError
        except ValueError:
            fields = {"event": "message", "message": text}
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "service": self.service,
            "trace_id": None,                     # pas de requête HTTP : service à boucle de fond
            "event": str(fields.pop("event", "message")),
            "logger": record.name,
        }
        entry.update({k: v for k, v in fields.items() if k not in entry})
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False, default=str)


def setup(level: int | str | None = None) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level or os.getenv("LOG_LEVEL", "INFO").upper())
