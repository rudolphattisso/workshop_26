"""Identité de l'appelant pour /auth/me : le service d'auth vérifie ses propres jetons avec sa clé locale,
sans passer par le réseau. La logique de vérification est celle des autres services (resilience_common)."""

from resilience_common.jwt_auth import CurrentUser, InvalidToken, bearer_user

from app.keys import get_signing_key

__all__ = ["CurrentUser", "get_current_user"]


def _resolve_key(kid: str):
    key = get_signing_key()
    if kid != key.kid:
        raise InvalidToken("kid inconnu")
    return key.private_key.public_key()


get_current_user = bearer_user(_resolve_key)
