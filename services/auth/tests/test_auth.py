import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from conftest import TEST_PASSWORDS
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from resilience_common.identity import user_id
from resilience_common.jwt_auth import AUDIENCE, ISSUER, JwksKeyStore, decode_access_token, token_kid
from sqlalchemy import select

from app.db import get_sessionmaker
from app.keys import get_signing_key
from app.main import app
from app.models import User
from app.seed import SeedConfigError, passwords_from_env, seed

client = TestClient(app)


def login(username="alice", password=TEST_PASSWORDS["DEMO_CLIENT_PASSWORD"]):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def forge(key: rsa.RSAPrivateKey, kid: str, **overrides) -> str:
    now = datetime.now(timezone.utc)
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": str(user_id("alice")), "role": "operator",
              "jti": "x", "iat": now, "exp": now + timedelta(minutes=5)}
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


# ------------------------------------------------------------------ login


def test_login_returns_short_lived_rs256_token():
    response = login()
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "Bearer" and body["expires_in"] == 900
    assert response.headers["Cache-Control"] == "no-store"

    token = body["access_token"]
    assert jwt.get_unverified_header(token)["alg"] == "RS256"
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["sub"] == str(user_id("alice"))
    assert claims["role"] == "client"
    assert claims["exp"] - claims["iat"] == 900


def test_operator_gets_operator_role():
    token = login("operator", TEST_PASSWORDS["OPERATOR_PASSWORD"]).json()["access_token"]
    assert jwt.decode(token, options={"verify_signature": False})["role"] == "operator"


def test_wrong_password_and_unknown_user_are_indistinguishable():
    wrong = login(password="not-the-password")
    unknown = login(username="mallory")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["title"] == unknown.json()["title"] == "Identifiants invalides"


def test_failed_logins_are_counted():
    login(password="not-the-password")
    assert 'auth_logins_total{outcome="invalid_credentials"}' in client.get("/metrics").text


@pytest.mark.parametrize(
    "body",
    [
        {"username": "alice"},  # mot de passe absent
        {"username": "", "password": "x"},
        {"username": "a" * 65, "password": "x"},
        {"username": "alice", "password": "x", "role": "operator"},  # champ inattendu
    ],
)
def test_invalid_login_payload_is_400(body):
    assert client.post("/api/auth/login", json=body).status_code == 400


# ------------------------------------------------------------------ /auth/me


def test_me_returns_identity_from_token():
    token = login().json()["access_token"]
    response = client.get("/api/auth/me", headers=bearer(token))
    assert response.status_code == 200
    assert response.json() == {"id": str(user_id("alice")), "username": "alice", "role": "client"}


def test_me_without_token_is_401():
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_tampered_token_is_401():
    header, payload, signature = login().json()["access_token"].split(".")
    # On remplace la charge utile par celle d'un opérateur : la signature ne correspond plus.
    forged_payload = jwt.utils.base64url_encode(b'{"role":"operator"}').decode()
    assert client.get("/api/auth/me", headers=bearer(f"{header}.{forged_payload}.{signature}")).status_code == 401


def test_token_signed_with_another_key_is_401_even_with_right_kid():
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = forge(attacker_key, kid=get_signing_key().kid)
    assert client.get("/api/auth/me", headers=bearer(token)).status_code == 401


def test_expired_token_is_401():
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    token = forge(get_signing_key().private_key, get_signing_key().kid, iat=past, exp=past + timedelta(minutes=15))
    assert client.get("/api/auth/me", headers=bearer(token)).status_code == 401


# ------------------------------------------------------------------ JWKS


def test_jwks_publishes_only_the_public_key():
    keys = client.get("/api/auth/.well-known/jwks.json").json()["keys"]
    assert len(keys) == 1
    assert keys[0]["kid"] == get_signing_key().kid
    assert keys[0]["alg"] == "RS256" and keys[0]["use"] == "sig"
    assert not {"d", "p", "q", "dp", "dq", "qi"} & keys[0].keys()  # aucun élément de la clé privée


def test_other_services_can_verify_tokens_through_jwks():
    """Le contrat entre auth et payment-api : un jeton émis ici se vérifie avec la seule clé publique JWKS."""
    store = JwksKeyStore("unused", fetch=lambda: client.get("/api/auth/.well-known/jwks.json").json())
    token = login().json()["access_token"]
    user = decode_access_token(token, store.get_key(token_kid(token)))
    assert user.id == user_id("alice") and user.role == "client"


# ------------------------------------------------------------------ seed


def test_passwords_are_stored_as_argon2id_hashes():
    with get_sessionmaker()() as session:
        hashes = session.scalars(select(User.password_hash)).all()
    assert len(hashes) == 5
    assert all(h.startswith("$argon2id$") for h in hashes)
    assert not any(p in h for h in hashes for p in TEST_PASSWORDS.values())


def test_seed_is_idempotent_and_rotates_changed_passwords():
    with get_sessionmaker()() as session:
        assert seed(session, TEST_PASSWORDS) == {"users_created": 0, "passwords_updated": 0}
        rotated = {**TEST_PASSWORDS, "DEMO_CLIENT_PASSWORD": "rotated-client-password"}
        assert seed(session, rotated) == {"users_created": 0, "passwords_updated": 3}
    assert login().status_code == 401
    assert login(password="rotated-client-password").status_code == 200


def test_user_ids_match_payment_api_owners():
    with get_sessionmaker()() as session:
        user = session.scalar(select(User).where(User.username == "smoke-client"))
    assert user.id == uuid.uuid5(uuid.NAMESPACE_URL, "resilience-alpha:user:smoke-client")


def test_seed_refuses_missing_or_weak_passwords(monkeypatch):
    for var, value in TEST_PASSWORDS.items():
        monkeypatch.setenv(var, value)
    assert passwords_from_env() == TEST_PASSWORDS
    monkeypatch.setenv("OPERATOR_PASSWORD", "change-me")
    with pytest.raises(SeedConfigError, match="OPERATOR_PASSWORD"):
        passwords_from_env()
    monkeypatch.delenv("OPERATOR_PASSWORD")
    with pytest.raises(SeedConfigError):
        passwords_from_env()


# ------------------------------------------------------------------ socle


def test_auth_exposes_common_probes():
    assert client.get("/health").json() == {"status": "ok", "service": "auth"}
    assert client.get("/ready").json()["checks"] == {"database": "ok"}
    assert client.get("/api/auth/ready").json()["checks"] == {"database": "ok"}  # sonde via le WAF


def test_login_takes_comparable_time_for_unknown_user():
    """Pas de raccourci pour un utilisateur inconnu : argon2 est calculé dans les deux cas."""
    def duration(username):
        start = time.perf_counter()
        login(username=username, password="not-the-password")
        return time.perf_counter() - start

    known = min(duration("alice") for _ in range(3))
    unknown = min(duration("mallory") for _ in range(3))
    assert unknown > known * 0.5
