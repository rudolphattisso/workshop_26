"""Utilisateurs fictifs de démonstration. Idempotent : peut être relancé à chaque démarrage.

Les mots de passe ne sont jamais dans le code : ils arrivent par variables d'environnement (fournies par
Vault/SOPS) et ne sont stockés que hachés. Si une variable change, le haché est mis à jour au démarrage
suivant : c'est ainsi qu'on fait tourner un mot de passe.

Usage : python -m app.seed
"""

import logging
import os
import sys

from resilience_common.identity import user_id
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_sessionmaker
from app.models import Role, User
from app.passwords import hash_password, needs_rehash, verify_password

log = logging.getLogger(__name__)

MIN_PASSWORD_LENGTH = 12

# (nom, rôle, variable d'environnement du mot de passe). Mêmes noms que les comptes de payment-api.
DEMO_USERS = [
    ("alice", Role.client, "DEMO_CLIENT_PASSWORD"),
    ("bob", Role.client, "DEMO_CLIENT_PASSWORD"),
    ("cafe-demo", Role.client, "DEMO_CLIENT_PASSWORD"),
    # Compte du smoke test, utilisé par la remédiation pour prouver la reprise : mot de passe à part.
    ("smoke-client", Role.client, "SMOKE_CLIENT_PASSWORD"),
    ("operator", Role.operator, "OPERATOR_PASSWORD"),
]


class SeedConfigError(Exception):
    pass


def passwords_from_env() -> dict[str, str]:
    """Lit les mots de passe requis ; refuse une variable absente ou trop courte (ex. « change-me »)."""
    passwords = {}
    for var in sorted({var for _, _, var in DEMO_USERS}):
        value = os.environ.get(var, "")
        if len(value) < MIN_PASSWORD_LENGTH:
            raise SeedConfigError(f"{var} absente ou plus courte que {MIN_PASSWORD_LENGTH} caractères")
        passwords[var] = value
    return passwords


def seed(session: Session, passwords: dict[str, str]) -> dict[str, int]:
    """Crée les utilisateurs manquants et met à jour les mots de passe modifiés."""
    created = updated = 0
    for username, role, var in DEMO_USERS:
        password = passwords[var]
        user = session.scalar(select(User).where(User.username == username))
        if user is None:
            session.add(User(id=user_id(username), username=username, password_hash=hash_password(password), role=role))
            created += 1
        elif not verify_password(user.password_hash, password) or needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
            updated += 1
    session.commit()
    return {"users_created": created, "passwords_updated": updated}


if __name__ == "__main__":
    from resilience_common.logs import configure_logging

    configure_logging("auth")
    try:
        passwords = passwords_from_env()
    except SeedConfigError as exc:
        log.error("seed_config_invalid", extra={"error": str(exc)})
        sys.exit(1)
    with get_sessionmaker()() as session:
        log.info("seed_done", extra=seed(session, passwords))
