"""Clé de signature RS256 du service d'auth, émission des jetons et publication JWKS.

Origine de la clé privée :
  - JWT_PRIVATE_KEY_FILE défini → fichier PEM monté dans le conteneur (fourni par Vault/SOPS) ;
  - sinon → clé éphémère générée au démarrage, jamais écrite sur disque.

Avec une clé éphémère, redémarrer l'auth invalide tous les jetons en cours (ils durent 15 min) :
c'est aussi une révocation globale à la disposition du moteur de remédiation en cas de compromission.
"""

import base64
import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from resilience_common.jwt_auth import ALGORITHM, AUDIENCE, ISSUER

from app.models import User

log = logging.getLogger(__name__)

ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "900"))
MIN_KEY_BITS = 2048


@dataclass(frozen=True)
class SigningKey:
    private_key: rsa.RSAPrivateKey
    kid: str
    public_jwk: dict


def _thumbprint(jwk: dict) -> str:
    """Identifiant de clé RFC 7638 : empreinte SHA-256 des membres publics, stable pour une même clé."""
    canonical = json.dumps({k: jwk[k] for k in ("e", "kty", "n")}, sort_keys=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()


def build_signing_key(private_key: rsa.RSAPrivateKey) -> SigningKey:
    jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    kid = _thumbprint(jwk)
    jwk.update({"kid": kid, "use": "sig", "alg": ALGORITHM})
    return SigningKey(private_key=private_key, kid=kid, public_jwk=jwk)


def load_signing_key() -> SigningKey:
    path = os.getenv("JWT_PRIVATE_KEY_FILE")
    if path:
        with open(path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size < MIN_KEY_BITS:
            raise ValueError(f"JWT_PRIVATE_KEY_FILE doit contenir une clé RSA d'au moins {MIN_KEY_BITS} bits")
        source = "file"
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=MIN_KEY_BITS)
        source = "ephemeral"
    key = build_signing_key(private_key)
    log.info("signing_key_loaded", extra={"kid": key.kid, "source": source})
    return key


@lru_cache
def get_signing_key() -> SigningKey:
    return load_signing_key()


def issue_access_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": str(user.id),
        "role": user.role.value,
        "jti": str(uuid.uuid4()),  # identifiant unique : permet de tracer un jeton précis dans les logs
        "iat": now,
        "exp": now + timedelta(seconds=ACCESS_TOKEN_TTL_SECONDS),
    }
    key = get_signing_key()
    return jwt.encode(claims, key.private_key, algorithm=ALGORITHM, headers={"kid": key.kid})


def jwks() -> dict:
    return {"keys": [get_signing_key().public_jwk]}
