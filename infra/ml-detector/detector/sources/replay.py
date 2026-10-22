"""Rejeu « en direct » d'un scénario déjà constitué (trafic simulé, export Wazuh) : le service ne
voit que ce qui est « arrivé » jusqu'à l'instant courant, comme avec Loki. Une horloge accélérée
permet une démo de 20 minutes de trafic en 4 minutes (vitesse 5)."""
from __future__ import annotations

import bisect
import time
from datetime import datetime, timedelta

from ..alarms import Alarm
from ..models import HttpRequestLog
from .base import LogSource


class Clock:
    """Horloge réelle (production)."""

    def now(self) -> datetime:
        from datetime import timezone
        return datetime.now(timezone.utc)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class ReplayClock(Clock):
    """Temps du scénario : démarre à `start` et avance `speed` fois plus vite que le temps réel."""

    def __init__(self, start: datetime, speed: float = 1.0):
        self.start, self.speed = start, speed
        self._wall = time.monotonic()

    def now(self) -> datetime:
        return self.start + timedelta(seconds=(time.monotonic() - self._wall) * self.speed)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds / self.speed)


class ReplaySource(LogSource):
    def __init__(self, records: list[HttpRequestLog]):
        self.records = sorted(records, key=lambda r: r.ts)
        self._ts = [r.ts for r in self.records]

    def fetch(self, start: datetime, end: datetime) -> list[HttpRequestLog]:
        return self.records[bisect.bisect_left(self._ts, start):bisect.bisect_left(self._ts, end)]


class ReplayAlarmSource:
    def __init__(self, alarms: list[Alarm]):
        self.alarms = sorted(alarms, key=lambda a: a.ts)
        self._ts = [a.ts for a in self.alarms]

    def fetch(self, start: datetime, end: datetime) -> list[Alarm]:
        return self.alarms[bisect.bisect_left(self._ts, start):bisect.bisect_left(self._ts, end)]
