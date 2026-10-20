"""auth : connexion et émission des jetons d'accès (contrat : contracts/openapi-payment.yaml, tag auth)."""

from resilience_common import create_app

from app.db import ping_database
from app.keys import get_signing_key
from app.routes import router

app = create_app("auth", ready_checks={"database": ping_database}, version="0.1.0")
app.include_router(router)

# Clé chargée dès le démarrage (après create_app, qui configure les logs) : un fichier de clé invalide
# fait échouer le conteneur tout de suite, pas à la première connexion.
get_signing_key()
