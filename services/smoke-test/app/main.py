"""smoke-test : transaction fictive de bout en bout, en continu et à la demande (GET /check).

Remplace le `txprobe` de l'Infra avec le même contrat. Réseau interne uniquement : /check déclenche un vrai
paiement et ne doit jamais être publié par le WAF.
"""

import os
import threading
from contextlib import asynccontextmanager
from functools import lru_cache

from fastapi import Depends
from fastapi.responses import JSONResponse
from resilience_common import create_app

from app.probe import TransactionProbe, config_from_env, run_forever


@lru_cache
def get_probe() -> TransactionProbe:
    return TransactionProbe(config_from_env())


@asynccontextmanager
async def lifespan(_app):
    probe = get_probe()  # mot de passe absent ⇒ le conteneur échoue au démarrage, pas à la première transaction
    stop = threading.Event()
    interval = float(os.getenv("PROBE_INTERVAL_SECONDS", "5"))
    if interval > 0:  # 0 = sonde à la demande seulement (tests)
        threading.Thread(target=run_forever, args=(probe, interval, stop), name="smoke-loop", daemon=True).start()
    yield
    stop.set()


app = create_app("smoke-test", lifespan=lifespan, version="0.1.0")


@app.get("/check", tags=["smoke"])
def check(probe: TransactionProbe = Depends(get_probe)) -> JSONResponse:
    """Exécute une transaction maintenant : 200 si elle réussit, 503 sinon (même corps JSON)."""
    result = probe.run()
    return JSONResponse(result, status_code=200 if result["ok"] else 503)


@app.get("/last", tags=["smoke"])
def last(probe: TransactionProbe = Depends(get_probe)) -> dict:
    """Résultat de la dernière transaction de la boucle de fond, sans en déclencher une (lu par le watchdog).
    `ok: null` tant qu'aucune transaction n'a eu lieu."""
    return probe.last()
