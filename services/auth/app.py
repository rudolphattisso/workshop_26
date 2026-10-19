"""Service d'authentification (référence) : émet des JWT pour les utilisateurs fictifs."""
import logging
import os
import time

import bcrypt
import jwt
from fastapi import FastAPI, HTTPException
from prometheus_client import Counter
from psycopg_pool import ConnectionPool
from pydantic import BaseModel

from obs import instrument, log, read_secret

DB_DSN = (
    f"host={os.getenv('DB_HOST', 'postgres')} dbname={os.getenv('DB_NAME', 'payments')} "
    f"user={os.getenv('DB_USER', 'auth_svc')} password={read_secret('auth_db_password')}"
)
JWT_SECRET = read_secret("jwt_secret")
TOKEN_TTL = int(os.getenv("TOKEN_TTL_SECONDS", "900"))

LOGINS = Counter("auth_logins_total", "Tentatives de connexion", ["result"])

pool = ConnectionPool(DB_DSN, min_size=1, max_size=5, open=False, timeout=5)
app = FastAPI(title="auth-service", version="1.0.0")
instrument(app)


@app.on_event("startup")
def _startup():
    pool.open(wait=False)


class Credentials(BaseModel):
    username: str
    password: str


def verify_password(password: str, stored: str) -> bool:
    # Hash bcrypt ($2a$...) produit par pgcrypto à l'initialisation de la base.
    try:
        return bcrypt.checkpw(password.encode(), stored.encode())
    except ValueError:
        return False


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/ready")
def ready():
    try:
        with pool.connection() as conn:
            conn.execute("SELECT 1")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(503, f"database unavailable: {exc.__class__.__name__}")
    return {"status": "ready"}


@app.get("/api/auth/ready")
def api_ready():
    return ready()


@app.post("/api/auth/login")
def login(creds: Credentials):
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT id, password_hash, role FROM users WHERE username = %s AND active", (creds.username,)
        ).fetchone()
    if not row or not verify_password(creds.password, row[1]):
        LOGINS.labels("failure").inc()
        log(logging.WARNING, "login_failed", username=creds.username)
        raise HTTPException(401, "invalid credentials")
    LOGINS.labels("success").inc()
    now = int(time.time())
    token = jwt.encode(
        {"sub": creds.username, "uid": row[0], "role": row[2], "iat": now, "exp": now + TOKEN_TTL},
        JWT_SECRET, algorithm="HS256",
    )
    log(logging.INFO, "login_success", username=creds.username)
    return {"access_token": token, "token_type": "bearer", "expires_in": TOKEN_TTL}
