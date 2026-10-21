"""payment-api : comptes et paiements fictifs (contrat : contracts/openapi-payment.yaml)."""

from resilience_common import create_app

from app.db import ping_database
from app.routes import router
from app.security import ping_auth_jwks

# L'auth n'est pas une condition de /ready : payment-api vérifie les jetons avec les clés en cache, même auth
# tombée. Son état est seulement rapporté (« info ») pour la supervision du lien payment-api → auth.
app = create_app(
    "payment-api",
    ready_checks={"database": ping_database},
    info_checks={"auth_jwks": ping_auth_jwks},
    public_prefix="/api/payments",
    version="0.1.0",
)
app.include_router(router)
