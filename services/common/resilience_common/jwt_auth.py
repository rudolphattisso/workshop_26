"""Vérification des jetons d'accès (JWT RS256) émis par le service d'auth.

Le service d'auth signe avec sa clé privée ; les autres services vérifient avec la clé publique publiée en
JWKS. Aucun secret n'est partagé : compromettre payment-api ne permet pas de fabriquer des jetons.

Résilience : les clés publiques sont gardées en mémoire. Si le service d'auth tombe, les jetons déjà
émis restent vérifiables. On ne recontacte l'auth que pour un `kid` inconnu (nouvelle clé après un
redémarrage ou une rotation), au plus une fois toutes les quelques secondes pour qu'un attaquant
n'en fasse pas un levier de saturation.
"""

import json
import logging
import threading
import time
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

log = logging.getLogger("resilience.auth")

ALGORITHM = "RS256"
ISSUER = "resilience-alpha-auth"
AUDIENCE = "resilience-alpha"
ROLES = ("client", "operator")


@dataclass(frozen=True)
class CurrentUser:
    id: uuid.UUID
    role: Literal["client", "operator"]


class InvalidToken(Exception):
    """Jeton absent, mal formé, mal signé, expiré ou destiné à un autre émetteur/public."""


class KeysUnavailable(Exception):
    """Clé de vérification inconnue et service d'auth injoignable."""


def decode_access_token(token: str, key: Any) -> CurrentUser:
    try:
        # algorithms=[RS256] imposé : refuse « alg: none » et la confusion RS256/HS256.
        claims = jwt.decode(
            token,
            key,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "jti", "role"]},
        )
        role = claims["role"]
        if role not in ROLES:
            raise InvalidToken("rôle inconnu")
        return CurrentUser(id=uuid.UUID(claims["sub"]), role=role)
    except (jwt.PyJWTError, ValueError) as exc:
        raise InvalidToken(type(exc).__name__) from exc


def token_kid(token: str) -> str:
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except jwt.PyJWTError as exc:
        raise InvalidToken(type(exc).__name__) from exc
    if not isinstance(kid, str):
        raise InvalidToken("kid absent")
    return kid


def _fetch_json(url: str, timeout: float) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.load(response)


class JwksKeyStore:
    """Cache des clés publiques du service d'auth, indexées par `kid`."""

    def __init__(
        self,
        url: str,
        timeout: float = 2.0,
        min_refresh_interval: float = 5.0,
        fetch: Callable[[], dict] | None = None,
    ):
        self._fetch = fetch or (lambda: _fetch_json(url, timeout))
        self._min_refresh_interval = min_refresh_interval
        self._keys: dict[str, Any] = {}
        self._last_refresh = float("-inf")
        self._lock = threading.Lock()

    def get_key(self, kid: str) -> Any:
        if kid in self._keys:
            return self._keys[kid]
        with self._lock:
            if kid not in self._keys and time.monotonic() - self._last_refresh >= self._min_refresh_interval:
                self._refresh()
        if kid in self._keys:
            return self._keys[kid]
        if not self._keys:
            raise KeysUnavailable()
        raise InvalidToken("kid inconnu")

    def _refresh(self) -> None:
        self._last_refresh = time.monotonic()
        try:
            jwks = jwt.PyJWKSet.from_dict(self._fetch())
        except Exception as exc:
            # On garde les clés connues : une panne de l'auth ne doit pas invalider les jetons en cours.
            log.warning("jwks_refresh_failed", extra={"error": type(exc).__name__})
            return
        # Remplacement complet : une clé retirée par l'auth (rotation) cesse d'être acceptée.
        self._keys = {key.key_id: key.key for key in jwks.keys if key.key_id}
        log.info("jwks_refreshed", extra={"kids": sorted(self._keys)})


_bearer = HTTPBearer(auto_error=False)


def bearer_user(resolve_key: Callable[[str], Any]) -> Callable[..., CurrentUser]:
    """Fabrique la dépendance FastAPI qui authentifie l'appelant.

    `resolve_key(kid)` renvoie la clé publique à utiliser (JwksKeyStore.get_key, ou la clé locale de l'auth).
    """

    def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> CurrentUser:
        unauthorized = HTTPException(401, "Authentification requise", headers={"WWW-Authenticate": "Bearer"})
        if credentials is None:
            raise unauthorized
        try:
            token = credentials.credentials
            return decode_access_token(token, resolve_key(token_kid(token)))
        except InvalidToken as exc:
            log.info("token_rejected", extra={"reason": str(exc)})
            raise unauthorized
        except KeysUnavailable:
            log.warning("token_unverifiable", extra={"reason": "jwks_unavailable"})
            raise HTTPException(503, "Service d'authentification indisponible", headers={"Retry-After": "5"})

    return current_user


def require_role(dependency: Callable[..., CurrentUser], role: str) -> Callable[..., CurrentUser]:
    def checked(user: CurrentUser = Depends(dependency)) -> CurrentUser:
        if user.role != role:
            raise HTTPException(403, "Réservé aux opérateurs" if role == "operator" else "Rôle insuffisant")
        return user

    return checked
