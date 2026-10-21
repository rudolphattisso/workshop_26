"""Routes HTTP de payment-api : traduction HTTP ↔ logique métier (app/payments.py), et contrôle d'accès.

Règle de visibilité : un client ne voit que ses comptes et les paiements qui les concernent ;
une ressource non visible renvoie 404 (et non 403) pour ne pas révéler son existence.
"""

import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import Account, Payment, PaymentStatus
from app.payments import (
    ForbiddenSourceAccount,
    IdempotencyConflict,
    check_consistency,
    create_payment,
    payment_visibility_filter,
)
from app.schemas import AccountOut, ConsistencyReport, PaymentOut, PaymentRequest
from app.security import CurrentUser, get_current_user, require_operator

# Préfixe /api : le WAF transmet l'URI telle quelle (/api/payments*, /api/accounts*) sans réécriture.
# /api/operations/* n'est pas publié par le WAF : réservé au réseau interne (moteur de remédiation).
router = APIRouter(prefix="/api")


def _account_query(user: CurrentUser):
    query = select(Account)
    return query if user.role == "operator" else query.where(Account.owner_id == user.id)


@router.get("/accounts", tags=["accounts"])
def list_accounts(
    user: CurrentUser = Depends(get_current_user), session: Session = Depends(get_session)
) -> list[AccountOut]:
    return list(session.scalars(_account_query(user).order_by(Account.label)))


@router.get("/accounts/{account_id}", tags=["accounts"])
def get_account(
    account_id: uuid.UUID, user: CurrentUser = Depends(get_current_user), session: Session = Depends(get_session)
) -> AccountOut:
    account = session.scalar(_account_query(user).where(Account.id == account_id))
    if account is None:
        raise HTTPException(404, "Compte introuvable")
    return account


@router.post("/payments", status_code=201, tags=["payments"])
def post_payment(
    body: PaymentRequest,
    response: Response,
    idempotency_key: str = Header(alias="Idempotency-Key", min_length=8, max_length=64),
    user: CurrentUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> PaymentOut:
    try:
        payment, created = create_payment(session, user, idempotency_key, body)
    except ForbiddenSourceAccount:
        raise HTTPException(403, "Le compte à débiter n'appartient pas à l'appelant")
    except IdempotencyConflict:
        raise HTTPException(409, "Idempotency-Key déjà utilisée avec une requête différente")

    if not created:
        response.status_code = 200
    elif payment.status == PaymentStatus.REJECTED:
        response.status_code = 422
    return payment


@router.get("/payments", tags=["payments"])
def list_payments(
    limit: int = Query(default=20, ge=1, le=100),
    user: CurrentUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> list[PaymentOut]:
    return list(session.scalars(
        select(Payment).where(payment_visibility_filter(user)).order_by(Payment.created_at.desc()).limit(limit)
    ))


@router.get("/payments/{payment_id}", tags=["payments"])
def get_payment(
    payment_id: uuid.UUID, user: CurrentUser = Depends(get_current_user), session: Session = Depends(get_session)
) -> PaymentOut:
    payment = session.scalar(select(Payment).where(Payment.id == payment_id, payment_visibility_filter(user)))
    if payment is None:
        raise HTTPException(404, "Paiement introuvable")
    return payment


@router.get("/operations/consistency", tags=["operations"])
def get_consistency(
    _: CurrentUser = Depends(require_operator), session: Session = Depends(get_session)
) -> ConsistencyReport:
    return check_consistency(session)
