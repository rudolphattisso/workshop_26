"""Identifiants partagés entre services.

Les identifiants sont déterministes : le service d'auth (qui possède les utilisateurs), payment-api (qui possède
leurs comptes) et le smoke test (qui paie un compte qu'il ne peut pas lister) calculent le même UUID sans
partager de base.
"""

import uuid


def user_id(username: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"resilience-alpha:user:{username}")


def account_id(username: str) -> uuid.UUID:
    """Compte principal de `username` (un compte par propriétaire dans les données de démo)."""
    return uuid.uuid5(uuid.NAMESPACE_URL, f"resilience-alpha:account:{username}")
