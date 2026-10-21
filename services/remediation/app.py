"""Moteur de remédiation (référence).

Chaîne : Prometheus/Loki (règles) -> Alertmanager -> POST /webhook/alertmanager -> action -> vérification.

Garde-fous :
  - le webhook exige un jeton (secret Docker partagé avec Alertmanager uniquement) ;
  - l'action et la cible sont lues dans les labels de l'alerte, mais confrontées à une liste
    blanche (REMEDIATION_ALLOWED_TARGETS) : on ne peut pas faire redémarrer n'importe quoi ;
  - pas d'accès direct au socket Docker : on passe par un docker-socket-proxy qui n'autorise
    que la lecture des conteneurs et les start/stop/restart (pas de create/exec/volumes) ;
  - cooldown par cible pour éviter les boucles de redémarrage.
La reprise n'est déclarée réussie que lorsqu'une transaction synthétique aboutit.
"""
import asyncio
import collections
import json
import logging
import os
import time
import uuid

import httpx
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from prometheus_client import Counter, Gauge

from obs import instrument, log, read_secret

DOCKER_API = os.getenv("DOCKER_API", "http://docker-proxy:2375")
COMPOSE_PROJECT = os.getenv("COMPOSE_PROJECT", "resilience")
TXPROBE = os.getenv("TXPROBE_URL", "http://txprobe:8000")
ALLOWED_TARGETS = {t.strip() for t in os.getenv("REMEDIATION_ALLOWED_TARGETS", "").split(",") if t.strip()}
COOLDOWN = float(os.getenv("REMEDIATION_COOLDOWN_SECONDS", "60"))
VERIFY_TIMEOUT = float(os.getenv("REMEDIATION_VERIFY_TIMEOUT_SECONDS", "90"))
TOKEN = read_secret("remediation_token")

ACTIONS = Counter("remediation_actions_total", "Actions de remédiation", ["alertname", "action", "target", "result"])
RECOVERY = Gauge("remediation_last_recovery_seconds", "Durée de la dernière reprise (action -> transaction OK)", ["target"])
IN_PROGRESS = Gauge("remediation_in_progress", "Remédiations en cours", ["target"])

EVENTS: collections.deque = collections.deque(maxlen=200)
_last_action: dict[str, float] = {}
_locks: dict[str, asyncio.Lock] = collections.defaultdict(asyncio.Lock)

app = FastAPI(title="remediation-engine", version="1.0.0")
instrument(app)


def record(kind: str, **fields):
    event = {"id": uuid.uuid4().hex[:12], "ts": time.time(), "kind": kind, **fields}
    EVENTS.appendleft(event)
    log(logging.INFO if kind != "remediation_failed" else logging.ERROR, kind, **fields)
    return event


async def find_containers(client: httpx.AsyncClient, service: str) -> list[str]:
    filters = {"label": [f"com.docker.compose.service={service}", f"com.docker.compose.project={COMPOSE_PROJECT}"]}
    r = await client.get("/containers/json", params={"all": "1", "filters": json.dumps(filters)})
    r.raise_for_status()
    return [c["Id"] for c in r.json()]


async def action_restart(service: str):
    async with httpx.AsyncClient(base_url=DOCKER_API, timeout=30) as client:
        ids = await find_containers(client, service)
        if not ids:
            raise RuntimeError(f"aucun conteneur pour le service {service}")
        for cid in ids:
            r = await client.post(f"/containers/{cid}/restart", params={"t": "5"})
            r.raise_for_status()


ACTION_HANDLERS = {"restart": action_restart}


async def verify_business() -> dict:
    """Attend qu'une transaction synthétique de bout en bout réussisse."""
    deadline = time.monotonic() + VERIFY_TIMEOUT
    last = {}
    async with httpx.AsyncClient(timeout=15) as client:
        while time.monotonic() < deadline:
            try:
                last = (await client.get(f"{TXPROBE}/check")).json()
                if last.get("ok"):
                    return last
            except httpx.HTTPError as exc:
                last = {"ok": False, "error": str(exc)}
            await asyncio.sleep(3)
    return last


async def remediate(alertname: str, action: str, target: str):
    async with _locks[target]:
        if time.monotonic() - _last_action.get(target, -1e9) < COOLDOWN:
            ACTIONS.labels(alertname, action, target, "skipped_cooldown").inc()
            record("remediation_skipped", alertname=alertname, action=action, target=target, reason="cooldown")
            return
        _last_action[target] = time.monotonic()
        IN_PROGRESS.labels(target).set(1)
        start = time.perf_counter()
        record("remediation_started", alertname=alertname, action=action, target=target)
        try:
            await ACTION_HANDLERS[action](target)
            record("remediation_action_done", alertname=alertname, action=action, target=target)
            result = await verify_business()
            elapsed = round(time.perf_counter() - start, 2)
            if result.get("ok"):
                RECOVERY.labels(target).set(elapsed)
                ACTIONS.labels(alertname, action, target, "success").inc()
                record("remediation_succeeded", alertname=alertname, action=action, target=target,
                       recovery_seconds=elapsed, verification_tx=result.get("tx_id"))
            else:
                ACTIONS.labels(alertname, action, target, "verify_failed").inc()
                record("remediation_failed", alertname=alertname, action=action, target=target,
                       recovery_seconds=elapsed, verification=result)
        except Exception as exc:  # noqa: BLE001
            ACTIONS.labels(alertname, action, target, "error").inc()
            record("remediation_failed", alertname=alertname, action=action, target=target, error=str(exc)[:300])
        finally:
            IN_PROGRESS.labels(target).set(0)


@app.get("/health")
def health():
    return {"status": "ok", "allowed_targets": sorted(ALLOWED_TARGETS)}


@app.get("/events")
def events(limit: int = 50):
    return list(EVENTS)[: max(1, min(limit, 200))]


@app.post("/webhook/alertmanager", status_code=202)
async def alertmanager_webhook(request: Request, background: BackgroundTasks, authorization: str = Header(default="")):
    if not TOKEN or authorization != f"Bearer {TOKEN}":
        log(logging.WARNING, "webhook_unauthorized", client_ip=request.client.host if request.client else "")
        raise HTTPException(401, "unauthorized")
    payload = await request.json()
    accepted = []
    for alert in payload.get("alerts", []):
        labels = alert.get("labels", {})
        alertname = labels.get("alertname", "unknown")
        action, target = labels.get("remediation"), labels.get("target")
        record("alert_received", alertname=alertname, status=alert.get("status"), severity=labels.get("severity"),
               action=action, target=target, summary=alert.get("annotations", {}).get("summary"))
        if alert.get("status") != "firing" or not action or action == "none":
            continue
        if action not in ACTION_HANDLERS or target not in ALLOWED_TARGETS:
            ACTIONS.labels(alertname, action, str(target), "refused").inc()
            record("remediation_refused", alertname=alertname, action=action, target=target,
                   reason="action ou cible hors liste blanche")
            continue
        background.add_task(remediate, alertname, action, target)
        accepted.append({"alertname": alertname, "action": action, "target": target})
    return {"accepted": accepted}
