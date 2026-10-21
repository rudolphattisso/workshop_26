"""Surveillance intégrée (watchdog) : mesure la topologie toutes les 5 s et retient les changements d'état.

C'est le filet de sécurité du moteur de remédiation (ADR-DEV-0004) : il détecte une panne même si la chaîne
ML / Prometheus ne la voit pas. Pour l'instant, il observe et publie (dashboard, logs, métriques) ; les
remédiations s'y brancheront ensuite.
"""

import asyncio
import json
import logging
import threading
import time
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timezone

from prometheus_client import Gauge

from app.topology import DOWN, LABELS, UP

log = logging.getLogger(__name__)

COMPONENT_UP = Gauge(
    "remediation_component_up",
    "1 si le composant ou le lien est opérationnel au dernier passage du watchdog, 0 sinon",
    ["kind", "id"],
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Watchdog:
    def __init__(self, probe: Callable[[], dict], interval: float = 5.0, history: int = 50):
        self._probe = probe
        self.interval = interval
        self._lock = threading.Lock()
        self._snapshot: dict | None = None
        self._version = 0
        self._changes: deque[dict] = deque(maxlen=history)  # les plus récents d'abord
        self._states: dict[str, str] = {}

    def tick(self) -> None:
        """Un passage : mesure, détecte les changements, met à jour l'état publié."""
        snap = self._probe()
        items = [("node", n["name"], LABELS[n["name"]], n) for n in snap["nodes"]] + [
            ("link", f"{l['source']}->{l['target']}", f"{LABELS[l['source']]} → {LABELS[l['target']]}", l)
            for l in snap["links"]
        ]
        changes = []
        for kind, key, label, item in items:
            before = self._states.get(key)
            COMPONENT_UP.labels(kind, key).set(1 if item["state"] == UP else 0)
            if before is None or before == item["state"]:
                continue
            change = {"at": snap["checked_at"], "kind": kind, "id": key, "label": label,
                      "from": before, "to": item["state"], "detail": item["detail"]}
            changes.append(change)
            level = logging.WARNING if item["state"] == DOWN else logging.INFO
            log.log(level, "component_state_changed", extra={k: v for k, v in change.items() if k != "at"})

        with self._lock:
            self._states = {key: item["state"] for _, key, _, item in items}
            self._changes.extendleft(changes)
            self._snapshot = snap
            self._version += 1

    def current(self) -> tuple[int, dict | None]:
        with self._lock:
            if self._snapshot is None:
                return self._version, None
            return self._version, {**self._snapshot, "changes": list(self._changes)}

    def run_forever(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                self.tick()
            except Exception:  # noqa: BLE001 — le watchdog ne doit jamais s'arrêter
                log.exception("watchdog_tick_failed")
            stop.wait(self.interval)


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


async def event_stream(
    watchdog: Watchdog,
    is_disconnected: Callable[[], Awaitable[bool]],
    poll: float = 1.0,
    heartbeat: float = 15.0,
) -> AsyncIterator[str]:
    """Flux SSE : l'état complet à la connexion, puis à chaque passage du watchdog, et un battement toutes les
    15 s pour que les proxys ne coupent pas la connexion. On compare un numéro de version plutôt que de pousser
    depuis le thread du watchdog : simple, sans file partagée entre threads, ≤ 1 s de retard."""
    seen = -1
    last_sent = time.monotonic()
    while not await is_disconnected():
        version, snap = watchdog.current()
        if snap is not None and version != seen:
            seen = version
            last_sent = time.monotonic()
            yield _sse("services", snap)
        elif time.monotonic() - last_sent >= heartbeat:
            last_sent = time.monotonic()
            yield _sse("heartbeat", {"at": _now()})
        await asyncio.sleep(poll)
