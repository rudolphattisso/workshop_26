"""Accès opérateur : JWT RS256 de l'auth, vérifié avec ses clés publiques (AUTH_JWKS_URL), rôle `operator` exigé.

Le dashboard est la seule interface du moteur et il est en lecture seule : aucun endpoint ne permet de
déclencher une action à la main (ADR-DEV-0004).
"""

import os
from functools import lru_cache

from resilience_common.jwt_auth import CurrentUser, JwksKeyStore, bearer_user, require_role

__all__ = ["CurrentUser", "get_current_user", "require_operator"]


@lru_cache
def _jwks() -> JwksKeyStore:
    return JwksKeyStore(os.environ["AUTH_JWKS_URL"])


get_current_user = bearer_user(lambda kid: _jwks().get_key(kid))
require_operator = require_role(get_current_user, "operator")
