"""Sources Loki (production, réseau `monitoring` de l'infra : http://loki:3100, sans authentification).

  - LokiSource : journaux d'accès de BunkerWeb ({service="bunkerweb"} : label posé par Alloy à
    partir du nom du service compose ; le guide d'intégration de l'infra parle encore de "waf",
    mais ses règles et son tableau de bord utilisent bien "bunkerweb") ;
  - LokiWazuhAlarmSource : alertes Wazuh ({service="wazuh"}, JSON reçu en syslog par Alloy) ;
  - LokiRemediationSource : actions du moteur de remédiation ({service="remediation"}, JSON).

API : GET /loki/api/v1/query_range, paginée (Loki tronque à `limit` lignes par requête). Les
lignes d'erreur et ModSecurity du même flux sont ignorées par parsing.parse_line.
Bibliothèque standard uniquement (pas de dépendance ajoutée à l'image).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

from ..alarms import Alarm, WazuhAlarmSource
from ..infra_actions import InfraAction
from ..infra_actions import parse_line as parse_action
from ..models import HttpRequestLog
from ..parsing import parse_line
from .base import LogSource


class LokiError(RuntimeError):
    """Loki injoignable ou réponse invalide."""


class LokiClient:
    def __init__(self, base_url: str = "http://loki:3100", page_size: int = 5000, timeout_s: float = 10.0,
                 max_pages: int = 50):
        self.base_url = base_url.rstrip("/")
        self.page_size, self.timeout_s, self.max_pages = page_size, timeout_s, max_pages
        self.truncated = False                    # dernière lecture coupée par max_pages

    def lines(self, query: str, start: datetime, end: datetime) -> list[str]:
        """Lignes de [start, end[ dans l'ordre chronologique, toutes pages confondues."""
        return [line for _, line in self.entries(query, start, end)]

    def entries(self, query: str, start: datetime, end: datetime) -> list[tuple[int, str]]:
        """(horodatage Loki en ns, ligne) de [start, end[, toutes pages confondues."""
        out: list[tuple[int, str]] = []
        self.truncated = False
        cursor = _ns(start)
        stop = _ns(end) - 1                       # Loki inclut `end` : on veut un intervalle semi-ouvert
        for _ in range(self.max_pages):
            entries = self._query(query, cursor, stop)
            out.extend(entries)
            if len(entries) < self.page_size:
                return out
            cursor = entries[-1][0] + 1           # page suivante, juste après la dernière ligne reçue
        self.truncated = True                     # garde-fou : volume anormal, on rend ce qu'on a (signalé)
        return out

    def _query(self, query: str, start_ns: int, end_ns: int) -> list[tuple[int, str]]:
        params = urllib.parse.urlencode({"query": query, "start": start_ns, "end": end_ns,
                                         "limit": self.page_size, "direction": "forward"})
        try:
            with urllib.request.urlopen(f"{self.base_url}/loki/api/v1/query_range?{params}",
                                        timeout=self.timeout_s) as response:
                body = json.loads(response.read().decode())
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise LokiError(f"Loki ({self.base_url}) : {exc}") from exc
        entries = [(int(ts), line) for stream in body.get("data", {}).get("result", [])
                   for ts, line in stream.get("values", [])]
        return sorted(entries)                    # plusieurs flux (conteneurs) : on fusionne par date


class LokiSource(LogSource):
    def __init__(self, base_url: str = "http://loki:3100", query: str = '{service="bunkerweb"}',
                 client: LokiClient | None = None):
        self.client = client or LokiClient(base_url)
        self.query = query

    def fetch(self, start: datetime, end: datetime) -> list[HttpRequestLog]:
        records = [r for r in map(parse_line, self.client.lines(self.query, start, end)) if r is not None]
        return sorted(records, key=lambda r: r.ts)

    @property
    def truncated(self) -> bool:
        return self.client.truncated


class LokiWazuhAlarmSource:
    """Alertes Wazuh reçues par Alloy en syslog : la ligne contient l'alerte JSON du manager,
    éventuellement précédée d'un en-tête syslog."""

    def __init__(self, base_url: str = "http://loki:3100", query: str = '{service="wazuh"}',
                 client: LokiClient | None = None, margin_s: float = 30.0):
        self.client = client or LokiClient(base_url)
        self.query = query
        self.margin = timedelta(seconds=margin_s)

    def fetch(self, start: datetime, end: datetime) -> list[Alarm]:
        # Une alerte Wazuh peut arriver quelques secondes après les faits : marge de lecture.
        alarms = []
        for line in self.client.lines(self.query, start - self.margin, end):
            first, last = line.find("{"), line.rfind("}")
            if first < 0 or last <= first:
                continue
            alarm = WazuhAlarmSource._to_alarm(line[first:last + 1])
            if alarm is not None and start <= alarm.ts < end:
                alarms.append(alarm)
        return sorted(alarms, key=lambda a: a.ts)


class LokiRemediationSource:
    def __init__(self, base_url: str = "http://loki:3100", query: str = '{service="remediation"}',
                 client: LokiClient | None = None):
        self.client = client or LokiClient(base_url)
        self.query = query

    def fetch(self, start: datetime, end: datetime) -> list[InfraAction]:
        actions = [a for a in map(parse_action, self.client.lines(self.query, start, end)) if a is not None]
        return sorted(actions, key=lambda a: a.ts)


def _ns(when: datetime) -> int:
    return int(when.timestamp() * 1_000_000_000)
