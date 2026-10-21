"""Sonde de transaction synthétique.

Rejoue en boucle le parcours métier réel (login -> paiement) en passant par le WAF,
comme un client. C'est la preuve « métier » de disponibilité : un conteneur démarré
ne suffit pas, il faut qu'une transaction aboutisse.

  - métriques exposées : synthetic_transaction_success, *_duration_seconds, *_total
  - GET /check : exécute une transaction à la demande (utilisé par la remédiation)
"""
import asyncio
import logging
import os
import time

import httpx
from fastapi import FastAPI
from prometheus_client import Counter, Gauge

from obs import instrument, log, read_secret

TARGET = os.getenv("PROBE_TARGET", "http://waf:8080")
INTERVAL = float(os.getenv("PROBE_INTERVAL_SECONDS", "10"))
USERNAME = os.getenv("PROBE_USERNAME", "synthetic-probe")
PASSWORD = read_secret("probe_user_password")

SUCCESS = Gauge("synthetic_transaction_success", "1 si la dernière transaction synthétique a réussi")
DURATION = Gauge("synthetic_transaction_duration_seconds", "Durée de la dernière transaction synthétique")
LAST_OK = Gauge("synthetic_transaction_last_success_timestamp", "Horodatage du dernier succès")
RUNS = Counter("synthetic_transactions_total", "Transactions synthétiques exécutées", ["result", "step"])

app = FastAPI(title="txprobe", version="1.0.0")
instrument(app)


async def run_transaction() -> dict:
    start = time.perf_counter()
    step = "login"
    headers = {"user-agent": "resilience-txprobe/1.0"}
    try:
        async with httpx.AsyncClient(base_url=TARGET, timeout=5.0, headers=headers) as client:
            r = await client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
            r.raise_for_status()
            token = r.json()["access_token"]
            step = "payment"
            r = await client.post(
                "/api/payments",
                json={"amount": "1.00", "currency": "EUR", "merchant": "SYNTHETIC-PROBE"},
                headers={"authorization": f"Bearer {token}"},
            )
            r.raise_for_status()
            tx = r.json()
            step = "readback"
            r = await client.get(f"/api/payments/{tx['id']}", headers={"authorization": f"Bearer {token}"})
            r.raise_for_status()
        elapsed = time.perf_counter() - start
        SUCCESS.set(1)
        DURATION.set(elapsed)
        LAST_OK.set(time.time())
        RUNS.labels("success", "done").inc()
        return {"ok": True, "tx_id": tx["id"], "duration_s": round(elapsed, 3)}
    except Exception as exc:  # noqa: BLE001
        elapsed = time.perf_counter() - start
        SUCCESS.set(0)
        DURATION.set(elapsed)
        RUNS.labels("failure", step).inc()
        detail = f"{exc.__class__.__name__}: {exc}"[:300]
        log(logging.WARNING, "synthetic_transaction_failed", step=step, error=detail)
        return {"ok": False, "step": step, "error": detail, "duration_s": round(elapsed, 3)}


async def _loop():
    while True:
        await run_transaction()
        await asyncio.sleep(INTERVAL)


@app.on_event("startup")
async def _startup():
    SUCCESS.set(0)
    asyncio.create_task(_loop())


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/check")
async def check():
    return await run_transaction()
