"""payment-api : comptes et paiements fictifs (contrat : contracts/openapi-payment.yaml)."""

from resilience_common import create_app

from app.db import ping_database
from app.routes import router

app = create_app("payment-api", ready_checks={"database": ping_database}, version="0.1.0")
app.include_router(router)
