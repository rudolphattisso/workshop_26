"""API métier de paiement (référence) : création et consultation de transactions fictives."""
import logging
import os
import uuid
from decimal import Decimal

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException
from prometheus_client import Counter, Gauge
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field

from obs import instrument, log, read_secret

DB_DSN = (
    f"host={os.getenv('DB_HOST', 'postgres')} dbname={os.getenv('DB_NAME', 'payments')} "
    f"user={os.getenv('DB_USER', 'payment_svc')} password={read_secret('payment_db_password')}"
)
JWT_SECRET = read_secret("jwt_secret")
MAX_AMOUNT = Decimal(os.getenv("MAX_AMOUNT", "10000"))

PAYMENTS = Counter("payments_total", "Transactions traitées", ["status"])
PAYMENT_AMOUNT = Counter("payments_amount_total", "Montant cumulé des transactions acceptées")
DB_UP = Gauge("payment_db_up", "1 si la base répond au dernier contrôle /ready")

pool = ConnectionPool(DB_DSN, min_size=1, max_size=10, open=False, timeout=5)
app = FastAPI(title="payment-api", version="1.0.0")
instrument(app)


@app.on_event("startup")
def _startup():
    pool.open(wait=False)


class PaymentIn(BaseModel):
    amount: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    currency: str = Field(default="EUR", pattern="^[A-Z]{3}$")
    merchant: str = Field(min_length=1, max_length=64)
    reference: str | None = Field(default=None, max_length=64)


def current_user(authorization: str = Header(default="")):
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    try:
        return jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "invalid token")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/ready")
def ready():
    try:
        with pool.connection() as conn:
            conn.execute("SELECT 1")
        DB_UP.set(1)
    except Exception as exc:  # noqa: BLE001
        DB_UP.set(0)
        raise HTTPException(503, f"database unavailable: {exc.__class__.__name__}")
    return {"status": "ready"}


@app.get("/api/payments/ready")
def api_ready():
    return ready()


@app.post("/api/payments", status_code=201)
def create_payment(body: PaymentIn, user=Depends(current_user)):
    status = "ACCEPTED" if body.amount <= MAX_AMOUNT else "REJECTED"
    tx_id = str(uuid.uuid4())
    with pool.connection() as conn:
        conn.execute(
            "INSERT INTO transactions (id, user_id, amount, currency, merchant, reference, status) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (tx_id, user["uid"], body.amount, body.currency, body.merchant, body.reference, status),
        )
    PAYMENTS.labels(status).inc()
    if status == "ACCEPTED":
        PAYMENT_AMOUNT.inc(float(body.amount))
    log(logging.INFO, "payment_processed", tx_id=tx_id, user=user["sub"], amount=str(body.amount),
        currency=body.currency, merchant=body.merchant, status=status)
    return {"id": tx_id, "status": status, "amount": str(body.amount), "currency": body.currency}


@app.get("/api/payments")
def list_payments(limit: int = 20, user=Depends(current_user)):
    limit = max(1, min(limit, 100))
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT id, amount, currency, merchant, status, created_at FROM transactions "
            "WHERE user_id = %s ORDER BY created_at DESC LIMIT %s",
            (user["uid"], limit),
        ).fetchall()
    return [
        {"id": str(r[0]), "amount": str(r[1]), "currency": r[2], "merchant": r[3], "status": r[4],
         "created_at": r[5].isoformat()}
        for r in rows
    ]


@app.get("/api/payments/{tx_id}")
def get_payment(tx_id: uuid.UUID, user=Depends(current_user)):
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT id, amount, currency, merchant, status, created_at FROM transactions "
            "WHERE id = %s AND user_id = %s",
            (str(tx_id), user["uid"]),
        ).fetchone()
    if not row:
        raise HTTPException(404, "not found")
    return {"id": str(row[0]), "amount": str(row[1]), "currency": row[2], "merchant": row[3],
            "status": row[4], "created_at": row[5].isoformat()}
