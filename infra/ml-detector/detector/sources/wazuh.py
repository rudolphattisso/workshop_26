"""Source Wazuh (rejeu hors ligne) : export JSON Lines des alertes du manager Wazuh.

Chaque ligne est une alerte ; seules celles décodées « web-accesslog » portent une requête HTTP,
dont la ligne d'accès BunkerWeb brute est dans `full_log` (re-parsée par parsing.parse_line,
même chemin que les autres sources). Les autres alertes (nginx-errorlog/ModSecurity, SCA,
syscheck...) sont ignorées.

LIMITE : Wazuh ne remonte que les requêtes qui déclenchent une règle (statuts 4xx/5xx) : le
trafic normal (200) est absent. Cet export sert à rejouer une attaque, jamais à entraîner la
baseline.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..models import HttpRequestLog
from ..parsing import parse_line
from .base import LogSource

# Vérifications de santé internes de BunkerWeb (API bwapi) : bruit, pas du trafic client.
DEFAULT_EXCLUDED_HOSTS = frozenset({"bwapi"})


class WazuhJsonlSource(LogSource):
    def __init__(self, path: str | Path, excluded_hosts: frozenset[str] = DEFAULT_EXCLUDED_HOSTS):
        self.path = Path(path)
        self.excluded_hosts = excluded_hosts

    def fetch(self, start: datetime, end: datetime) -> list[HttpRequestLog]:
        if start.tzinfo is None:
            start, end = start.replace(tzinfo=timezone.utc), end.replace(tzinfo=timezone.utc)
        return [r for r in self.read_all() if start <= r.ts < end]

    def read_all(self) -> list[HttpRequestLog]:
        """Toutes les requêtes de l'export, triées par date (horodatage nginx, pas celui de Wazuh)."""
        out = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                rec = self._to_record(line)
                if rec is not None and rec.host not in self.excluded_hosts:
                    out.append(rec)
        return sorted(out, key=lambda r: r.ts)

    @staticmethod
    def _to_record(line: str) -> HttpRequestLog | None:
        line = line.strip()
        if not line:
            return None
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            return None
        alert = alert.get("_source", alert)   # export brut de l'indexeur (OpenSearch)
        if (alert.get("decoder") or {}).get("name") != "web-accesslog":
            return None
        return parse_line(alert.get("full_log") or "")
