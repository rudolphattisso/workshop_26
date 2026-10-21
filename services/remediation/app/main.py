"""remediation : moteur de remédiation (contrat : contracts/openapi-remediation.yaml).

v0 : surveillance intégrée (watchdog) et sa publication pour le dashboard. Réseau interne uniquement.
"""

import os
import threading
from contextlib import asynccontextmanager
from functools import lru_cache

from fastapi import Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from resilience_common import create_app

from app.security import CurrentUser, require_operator
from app.topology import endpoints_from_env, evaluate, measure, snapshot
from app.watchdog import Watchdog, event_stream


@lru_cache
def get_watchdog() -> Watchdog:
    endpoints = endpoints_from_env()
    stale_after = float(os.getenv("WATCH_SMOKE_STALE_SECONDS", "45"))
    return Watchdog(
        lambda: snapshot(*evaluate(measure(endpoints), stale_after)),
        interval=float(os.getenv("WATCHDOG_INTERVAL_SECONDS", "5")),
    )


@asynccontextmanager
async def lifespan(_app):
    watchdog = get_watchdog()
    stop = threading.Event()
    if watchdog.interval > 0:  # 0 = pas de boucle de fond (tests)
        threading.Thread(target=watchdog.run_forever, args=(stop,), name="watchdog", daemon=True).start()
    yield
    stop.set()


app = create_app("remediation", lifespan=lifespan, version="0.1.0")


@app.get("/services", tags=["incidents"])
def services(_: CurrentUser = Depends(require_operator), watchdog: Watchdog = Depends(get_watchdog)) -> dict:
    """État des composants et des liens au dernier passage du watchdog, avec les derniers changements."""
    _, snap = watchdog.current()
    if snap is None:
        raise HTTPException(503, "Premier passage du watchdog en cours")
    return snap


@app.get("/events", tags=["incidents"])
async def events(
    request: Request, _: CurrentUser = Depends(require_operator), watchdog: Watchdog = Depends(get_watchdog)
) -> StreamingResponse:
    return StreamingResponse(
        event_stream(watchdog, request.is_disconnected),
        media_type="text/event-stream",
        # no-transform / X-Accel-Buffering : aucun proxy (nginx) ne doit retenir le flux dans un tampon.
        headers={"Cache-Control": "no-store, no-transform", "X-Accel-Buffering": "no"},
    )
