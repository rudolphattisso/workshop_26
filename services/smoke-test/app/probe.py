"""Transaction synthétique de bout en bout : la preuve « métier » que la plateforme fonctionne.

Un conteneur qui redémarre ne prouve rien. On rejoue donc le parcours d'un vrai client, à travers le WAF :
connexion → lecture de ses comptes → paiement de 1 centime → relecture du paiement.

- 1 centime par transaction : le compte `smoke-client` (1 000 €) tient ~100 000 transactions, soit ~5,8 jours
  à une toutes les 5 s. À 1 €, il serait vide en 83 minutes et la sonde échouerait en pleine démo.
- Connexion à chaque transaction, sans jeton en cache : on prouve que l'auth fonctionne, et un jeton révoqué
  (redémarrage de l'auth) ne fait jamais échouer la sonde à tort.
- Un trace_id par transaction, envoyé en `X-Trace-Id` et réutilisé comme `Idempotency-Key` : une transaction
  se retrouve dans les logs de tous les services (Loki) avec un seul identifiant.
- Le contrôle de cohérence des données n'est pas fait ici : il exige le rôle opérateur, et la sonde n'a que les
  droits d'un client. C'est le moteur de remédiation qui l'appelle (moindre privilège).

Contrat repris du `txprobe` de l'Infra : mêmes métriques et même réponse de `GET /check`, pour que ses alertes
(`SyntheticTransactionFailing`) et son dashboard Grafana restent valables.
"""

import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass

import httpx
from prometheus_client import Counter, Gauge
from resilience_common.config import secret
from resilience_common.identity import account_id
from resilience_common.logs import trace_id_var

log = logging.getLogger(__name__)

AMOUNT_CENTS = 1
MERCHANT = "smoke-merchant"

SUCCESS = Gauge("synthetic_transaction_success", "1 si la dernière transaction synthétique a réussi, 0 sinon")
DURATION = Gauge("synthetic_transaction_duration_seconds", "Durée de la dernière transaction synthétique")
LAST_OK = Gauge("synthetic_transaction_last_success_timestamp", "Horodatage Unix du dernier succès")
RUNS = Counter("synthetic_transactions_total", "Transactions synthétiques exécutées", ["result", "step"])
BALANCE = Gauge("synthetic_account_balance_cents", "Solde du compte du smoke test, pour alerter avant épuisement")


class StepFailed(Exception):
    """Une étape a répondu, mais pas ce qu'un client attend."""


@dataclass(frozen=True)
class ProbeConfig:
    target: str
    username: str
    password: str
    timeout: float


def config_from_env() -> ProbeConfig:
    return ProbeConfig(
        target=os.getenv("PROBE_TARGET", "http://bunkerweb:8080"),
        username=os.getenv("PROBE_USERNAME", "smoke-client"),
        password=secret("PROBE_PASSWORD"),  # PROBE_PASSWORD_FILE en déploiement
        timeout=float(os.getenv("PROBE_HTTP_TIMEOUT_SECONDS", "5")),
    )


def _expect(response: httpx.Response, status: int) -> dict | list:
    if response.status_code != status:
        raise StepFailed(f"HTTP {response.status_code} (attendu {status})")
    return response.json()


class TransactionProbe:
    def __init__(self, config: ProbeConfig, transport: httpx.BaseTransport | None = None):
        self.config = config
        self._transport = transport  # injecté par les tests ; None = vrai réseau
        # Une transaction à la fois : la boucle de fond et /check ne se chevauchent pas.
        self._lock = threading.Lock()

    def run(self) -> dict:
        with self._lock:
            trace_id = uuid.uuid4().hex
            token = trace_id_var.set(trace_id)  # les logs de la transaction portent son trace_id
            try:
                return self._run(trace_id)
            finally:
                trace_id_var.reset(token)

    def _run(self, trace_id: str) -> dict:
        start = time.perf_counter()
        step = "login"
        headers = {"X-Trace-Id": trace_id, "User-Agent": "resilience-smoke-test/1.0"}
        try:
            with httpx.Client(
                base_url=self.config.target, timeout=self.config.timeout, headers=headers, transport=self._transport
            ) as client:
                body = {"username": self.config.username, "password": self.config.password}
                auth = {"Authorization": f"Bearer {_expect(client.post('/api/auth/login', json=body), 200)['access_token']}"}

                step = "accounts"
                own_id = str(account_id(self.config.username))
                source = next((a for a in _expect(client.get("/api/accounts", headers=auth), 200) if a["id"] == own_id), None)
                if source is None:
                    raise StepFailed("compte du smoke test introuvable")
                BALANCE.set(source["balance_cents"])

                step = "payment"
                order = {"from_account_id": own_id, "to_account_id": str(account_id(MERCHANT)),
                         "amount_cents": AMOUNT_CENTS, "label": "smoke-test"}
                payment = _expect(client.post("/api/payments", json=order, headers={**auth, "Idempotency-Key": trace_id}), 201)
                if payment["status"] != "CAPTURED":
                    raise StepFailed(f"paiement {payment['status']} ({payment.get('rejection_reason')})")

                step = "readback"
                stored = _expect(client.get(f"/api/payments/{payment['id']}", headers=auth), 200)
                if (stored["status"], stored["amount_cents"]) != ("CAPTURED", AMOUNT_CENTS):
                    raise StepFailed("le paiement relu ne correspond pas au paiement créé")
        # Toute erreur (réseau, HTTP, JSON inattendu) est un échec de la sonde, jamais un plantage du service.
        except Exception as exc:  # noqa: BLE001
            elapsed = time.perf_counter() - start
            error = str(exc) if isinstance(exc, StepFailed) else f"{type(exc).__name__}: {exc}"
            SUCCESS.set(0)
            DURATION.set(elapsed)
            RUNS.labels("failure", step).inc()
            log.warning("synthetic_transaction_failed", extra={"step": step, "error": error[:300]})
            return {"ok": False, "step": step, "error": error[:300], "duration_s": round(elapsed, 3), "trace_id": trace_id}

        elapsed = time.perf_counter() - start
        SUCCESS.set(1)
        DURATION.set(elapsed)
        LAST_OK.set(time.time())
        RUNS.labels("success", "done").inc()
        log.info("synthetic_transaction_succeeded", extra={"tx_id": payment["id"], "duration_ms": round(elapsed * 1000, 1)})
        return {"ok": True, "tx_id": payment["id"], "duration_s": round(elapsed, 3), "trace_id": trace_id}


def run_forever(probe: TransactionProbe, interval: float, stop: threading.Event) -> None:
    """Boucle de fond : alimente les métriques que Prometheus lit toutes les 5 s."""
    while not stop.is_set():
        probe.run()
        stop.wait(interval)
