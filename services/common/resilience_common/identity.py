"""Identifiants partagés entre services.

Les identifiants des utilisateurs sont déterministes : le service d'auth (qui possède les utilisateurs)
et payment-api (qui possède leurs comptes) calculent le même UUID sans partager de base.
"""

import uuid


def user_id(username: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"resilience-alpha:user:{username}")
