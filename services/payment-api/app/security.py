"""Identité de l'appelant.

`get_current_user` est le point unique d'authentification de payment-api : toutes les routes métier en
dépendent. Il vérifie le JWT RS256 avec les clés publiques du service d'auth (AUTH_JWKS_URL).
Les tests le substituent par un utilisateur fixe.
"""

import os
import urllib.request
from functools import lru_cache

from resilience_common.jwt_auth import CurrentUser, JwksKeyStore, bearer_user, require_role

__all__ = ["CurrentUser", "get_current_user", "require_operator"]


@lru_cache
def _jwks() -> JwksKeyStore:
    # Créé au premier appel : l'URL n'est requise que lorsqu'un jeton doit vraiment être vérifié.
    return JwksKeyStore(os.environ["AUTH_JWKS_URL"])


get_current_user = bearer_user(lambda kid: _jwks().get_key(kid))
require_operator = require_role(get_current_user, "operator")


def ping_auth_jwks() -> None:
    """Information pour /ready : l'auth publie-t-elle ses clés ? Non bloquant (clés en cache), voir app/main.py."""
    urllib.request.urlopen(os.environ["AUTH_JWKS_URL"], timeout=2).close()
