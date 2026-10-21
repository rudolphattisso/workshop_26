"""Comptes fictifs de démonstration. Idempotent : peut être relancé à chaque démarrage.

Les identifiants des utilisateurs sont déterministes (`resilience_common.identity.user_id`), pour que
le service d'auth et payment-api s'accordent sans partager de base.

Usage : python -m app.seed
"""

import logging

from resilience_common.identity import account_id, user_id
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_sessionmaker
from app.models import Account, AccountKind, EntryKind, LedgerEntry

log = logging.getLogger(__name__)


# (propriétaire, type, libellé, solde d'ouverture en centimes). L'opérateur n'a pas de compte.
DEMO_ACCOUNTS = [
    ("alice", AccountKind.CUSTOMER, "Compte courant Alice (fictif)", 150_000),
    ("bob", AccountKind.CUSTOMER, "Compte courant Bob (fictif)", 80_000),
    ("cafe-demo", AccountKind.MERCHANT, "Café Démo (marchand fictif)", 0),
    # Réservés au smoke test : 1 centime par transaction, soit ~100 000 transactions (~5,8 jours à une toutes les 5 s).
    ("smoke-client", AccountKind.CUSTOMER, "Smoke test — client", 100_000),
    ("smoke-merchant", AccountKind.MERCHANT, "Smoke test — marchand", 0),
]


def seed(session: Session) -> int:
    """Crée les comptes manquants avec leur écriture d'ouverture. Renvoie le nombre de comptes créés."""
    created = 0
    for username, kind, label, opening_cents in DEMO_ACCOUNTS:
        acc_id = account_id(username)
        if session.scalar(select(Account.id).where(Account.id == acc_id)):
            continue
        session.add(
            Account(
                id=acc_id,
                owner_id=user_id(username),
                kind=kind,
                label=label,
                balance_cents=opening_cents,
            )
        )
        # Flush avant l'écriture : la clé étrangère ledger_entries → accounts doit trouver le compte.
        session.flush()
        session.add(LedgerEntry(account_id=acc_id, kind=EntryKind.OPENING, amount_cents=opening_cents))
        created += 1
    session.commit()
    return created


if __name__ == "__main__":
    from resilience_common.logs import configure_logging

    configure_logging("payment-api")
    with get_sessionmaker()() as session:
        log.info("seed_done", extra={"accounts_created": seed(session)})
