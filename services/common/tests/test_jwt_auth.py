import json
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from resilience_common import create_app
from resilience_common.jwt_auth import (
    AUDIENCE,
    ISSUER,
    CurrentUser,
    InvalidToken,
    JwksKeyStore,
    KeysUnavailable,
    bearer_user,
    decode_access_token,
    require_role,
)

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
USER_ID = uuid.uuid4()


def jwk(key, kid):
    return {**json.loads(RSAAlgorithm.to_jwk(key.public_key())), "kid": kid, "alg": "RS256", "use": "sig"}


def token(key=KEY, kid="k1", algorithm="RS256", **overrides):
    now = datetime.now(timezone.utc)
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": str(USER_ID), "role": "client",
              "jti": "j", "iat": now, "exp": now + timedelta(minutes=5)}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=algorithm, headers={"kid": kid})


class FakeJwks:
    """Service d'auth simulé : compte les appels et peut tomber en panne."""

    def __init__(self, *keys):
        self.keys = list(keys)
        self.calls = 0
        self.down = False

    def __call__(self):
        self.calls += 1
        if self.down:
            raise ConnectionError("auth injoignable")
        return {"keys": self.keys}


# ------------------------------------------------------------------ décodage


def test_valid_token_gives_user():
    assert decode_access_token(token(), KEY.public_key()) == CurrentUser(id=USER_ID, role="client")


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "someone-else"},
        {"aud": "other-app"},
        {"role": "admin"},
        {"role": None},  # claim requis absent
        {"jti": None},
        {"sub": "not-a-uuid"},
        {"exp": datetime.now(timezone.utc) - timedelta(seconds=1)},
    ],
)
def test_invalid_claims_are_rejected(overrides):
    with pytest.raises(InvalidToken):
        decode_access_token(token(**overrides), KEY.public_key())


def test_signature_from_another_key_is_rejected():
    with pytest.raises(InvalidToken):
        decode_access_token(token(key=OTHER_KEY), KEY.public_key())


def test_alg_none_is_rejected():
    unsigned = jwt.encode({"sub": str(USER_ID), "role": "operator"}, None, algorithm="none")
    with pytest.raises(InvalidToken):
        decode_access_token(unsigned, KEY.public_key())


# ------------------------------------------------------------------ cache JWKS


def test_keys_are_fetched_once_then_cached():
    fake = FakeJwks(jwk(KEY, "k1"))
    store = JwksKeyStore("unused", fetch=fake)
    store.get_key("k1")
    store.get_key("k1")
    assert fake.calls == 1


def test_known_keys_survive_an_auth_outage():
    fake = FakeJwks(jwk(KEY, "k1"))
    store = JwksKeyStore("unused", fetch=fake, min_refresh_interval=0)
    store.get_key("k1")
    fake.down = True
    with pytest.raises(InvalidToken):
        store.get_key("unknown")  # tentative de rafraîchissement, en échec
    assert store.get_key("k1") is not None  # la clé connue reste utilisable


def test_new_key_is_fetched_and_removed_key_is_dropped():
    fake = FakeJwks(jwk(KEY, "k1"))
    store = JwksKeyStore("unused", fetch=fake, min_refresh_interval=0)
    store.get_key("k1")
    fake.keys = [jwk(OTHER_KEY, "k2")]  # rotation côté auth
    store.get_key("k2")
    with pytest.raises(InvalidToken):
        store.get_key("k1")


def test_unknown_kids_cannot_flood_the_auth_service():
    fake = FakeJwks(jwk(KEY, "k1"))
    store = JwksKeyStore("unused", fetch=fake, min_refresh_interval=60)
    store.get_key("k1")
    for i in range(50):
        with pytest.raises(InvalidToken):
            store.get_key(f"random-{i}")
    assert fake.calls == 1


def test_no_keys_and_auth_down_is_unavailable():
    fake = FakeJwks()
    fake.down = True
    with pytest.raises(KeysUnavailable):
        JwksKeyStore("unused", fetch=fake).get_key("k1")


# ------------------------------------------------------------------ dépendance FastAPI


def make_client(fake: FakeJwks) -> TestClient:
    store = JwksKeyStore("unused", fetch=fake)
    current_user = bearer_user(store.get_key)
    app: FastAPI = create_app("test-svc")

    @app.get("/whoami")
    def whoami(user: CurrentUser = Depends(current_user)) -> dict:
        return {"id": str(user.id), "role": user.role}

    @app.get("/admin")
    def admin(user: CurrentUser = Depends(require_role(current_user, "operator"))) -> dict:
        return {"ok": True}

    return TestClient(app)


def test_bearer_token_authenticates():
    client = make_client(FakeJwks(jwk(KEY, "k1")))
    response = client.get("/whoami", headers={"Authorization": f"Bearer {token()}"})
    assert response.json() == {"id": str(USER_ID), "role": "client"}


@pytest.mark.parametrize("header", [None, "Bearer", "Bearer not.a.jwt", "Basic YWxpY2U6eA=="])
def test_missing_or_malformed_token_is_401(header):
    client = make_client(FakeJwks(jwk(KEY, "k1")))
    response = client.get("/whoami", headers={"Authorization": header} if header else {})
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert response.headers["content-type"] == "application/problem+json"


def test_unverifiable_token_is_503_not_401():
    fake = FakeJwks()
    fake.down = True
    response = make_client(fake).get("/whoami", headers={"Authorization": f"Bearer {token()}"})
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"


def test_role_is_enforced():
    client = make_client(FakeJwks(jwk(KEY, "k1")))
    assert client.get("/admin", headers={"Authorization": f"Bearer {token()}"}).status_code == 403
    assert client.get("/admin", headers={"Authorization": f"Bearer {token(role='operator')}"}).status_code == 200
