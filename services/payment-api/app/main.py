"""payment-api : comptes et paiements fictifs (contrat : contracts/openapi-payment.yaml).

Squelette : le socle commun fournit /health, /ready, /metrics, les logs JSON et les erreurs.
La vérification de la base de données s'ajoutera dans ready_checks avec la couche SQLAlchemy.
"""

from resilience_common import create_app

app = create_app("payment-api", version="0.1.0")
