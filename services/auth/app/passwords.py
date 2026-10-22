"""Hachage des mots de passe (argon2id).

Paramètres OWASP (m = 19 Mio, t = 2, p = 1) : coûteux pour un attaquant qui aurait volé la base, mais
assez sobres en mémoire pour qu'une rafale de tentatives de connexion ne sature pas le PC Hôte.
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

hasher = PasswordHasher(time_cost=2, memory_cost=19 * 1024, parallelism=1)

# Haché de référence pour les identifiants inconnus : la réponse prend le même temps qu'un mauvais
# mot de passe, ce qui empêche de deviner quels comptes existent en mesurant la durée.
_DUMMY_HASH = hasher.hash("resilience-alpha-timing-equalizer")


def hash_password(password: str) -> str:
    return hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        hasher.verify(password_hash or _DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        return False
    return password_hash is not None


def needs_rehash(password_hash: str) -> bool:
    return hasher.check_needs_rehash(password_hash)
