"""Logique métier des paiements (ADR-DEV-0002) : synchrone, atomique, idempotent.

Un paiement se fait en une seule transaction SQL :
  1. rejeu ? même Idempotency-Key + même corps => on renvoie le paiement d'origine, sans nouveau débit
  2. verrouillage des deux comptes (SELECT ... FOR UPDATE), toujours dans le même ordre
  3. décision : CAPTURED, ou REJECTED avec un motif
  4. si CAPTURED : débit, crédit et deux écritures au grand livre
  5. COMMIT : tout est écrit, ou rien
"""

import hashlib
import json
import logging
from datetime import datetime, timezone

from prometheus_client import Counter
from sqlalchemy import case, func, literal_column, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Account, EntryKind, LedgerEntry, Payment, PaymentStatus, RejectionReason
from app.schemas import ConsistencyReport, PaymentRequest, Violation
from app.security import CurrentUser

log = logging.getLogger(__name__)

PAYMENTS = Counter(
    "payments_total",
    "Paiements traités (hors rejeux idempotents)",
    ["status", "reason"],
)
PAYMENT_REPLAYS = Counter("payment_idempotent_replays_total", "Rejeux d'une Idempotency-Key déjà traitée")


class ForbiddenSourceAccount(Exception):
    """Le compte à débiter n'existe pas ou n'appartient pas à l'appelant."""


class IdempotencyConflict(Exception):
    """Idempotency-Key déjà utilisée avec un corps de requête différent."""


def request_fingerprint(body: PaymentRequest) -> str:
    canonical = json.dumps(body.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _find_replay(session: Session, user: CurrentUser, key: str, fingerprint: str) -> Payment | None:
    existing = session.scalar(
        select(Payment).where(Payment.requester_id == user.id, Payment.idempotency_key == key)
    )
    if existing is not None and existing.request_hash != fingerprint:
        raise IdempotencyConflict()
    return existing


def create_payment(session: Session, user: CurrentUser, key: str, body: PaymentRequest) -> tuple[Payment, bool]:
    """Renvoie (paiement, créé). `créé` est False pour un rejeu idempotent."""
    fingerprint = request_fingerprint(body)

    if (replay := _find_replay(session, user, key, fingerprint)) is not None:
        PAYMENT_REPLAYS.inc()
        log.info("payment_replayed", extra={"payment_id": str(replay.id)})
        return replay, False

    # Verrou sur les deux comptes, triés par id : deux paiements croisés (A→B et B→A) prennent les verrous
    # dans le même ordre et ne peuvent pas s'interbloquer. Le second paiement sur un même compte attend
    # la fin du premier et voit donc le solde à jour : pas de double dépense.
    locked = {
        account.id: account
        for account in session.scalars(
            select(Account)
            .where(Account.id.in_({body.from_account_id, body.to_account_id}))
            .order_by(Account.id)
            .with_for_update()
        )
    }
    source = locked.get(body.from_account_id)
    if source is None or source.owner_id != user.id:
        session.rollback()
        raise ForbiddenSourceAccount()
    destination = locked.get(body.to_account_id)

    if body.from_account_id == body.to_account_id:
        reason = RejectionReason.SAME_ACCOUNT
    elif destination is None:
        reason = RejectionReason.UNKNOWN_DESTINATION
    elif source.balance_cents < body.amount_cents:
        reason = RejectionReason.INSUFFICIENT_FUNDS
    else:
        reason = None

    payment = Payment(
        requester_id=user.id,
        idempotency_key=key,
        request_hash=fingerprint,
        from_account_id=body.from_account_id,
        to_account_id=body.to_account_id,
        amount_cents=body.amount_cents,
        label=body.label,
        status=PaymentStatus.CAPTURED if reason is None else PaymentStatus.REJECTED,
        rejection_reason=reason,
    )
    session.add(payment)

    # Toute la phase d'écriture est protégée : la contrainte unique peut sauter dès le flush.
    try:
        if reason is None:
            source.balance_cents -= body.amount_cents
            destination.balance_cents += body.amount_cents
            session.flush()  # insère le paiement : les écritures y font référence
            session.add_all([
                LedgerEntry(account_id=source.id, payment_id=payment.id, kind=EntryKind.DEBIT, amount_cents=-body.amount_cents),
                LedgerEntry(account_id=destination.id, payment_id=payment.id, kind=EntryKind.CREDIT, amount_cents=body.amount_cents),
            ])
        session.commit()
    except IntegrityError as exc:
        # Deux requêtes simultanées avec la même clé : la base n'en accepte qu'une (contrainte unique).
        # La perdante annule tout (y compris ses modifications de solde) et renvoie le paiement de la gagnante.
        session.rollback()
        if getattr(getattr(exc.orig, "diag", None), "constraint_name", None) != "uq_payment_idempotency":
            raise
        replay = _find_replay(session, user, key, fingerprint)
        PAYMENT_REPLAYS.inc()
        return replay, False

    PAYMENTS.labels(payment.status.value, reason.value if reason else "").inc()
    log.info(
        "payment_captured" if reason is None else "payment_rejected",
        extra={"payment_id": str(payment.id), "amount_cents": payment.amount_cents, "reason": reason and reason.value},
    )
    return payment, True


def visible_account_ids(user: CurrentUser):
    """Sous-requête des comptes de l'appelant (utilisée pour filtrer ce qu'un client a le droit de voir)."""
    return select(Account.id).where(Account.owner_id == user.id)


def payment_visibility_filter(user: CurrentUser):
    if user.role == "operator":
        return literal_column("TRUE")
    mine = visible_account_ids(user)
    return or_(Payment.from_account_id.in_(mine), Payment.to_account_id.in_(mine))


MAX_VIOLATIONS_PER_RULE = 20


def check_consistency(session: Session) -> ConsistencyReport:
    """Vérifie les invariants comptables, la preuve de « données cohérentes » après une remédiation."""
    # Instantané cohérent : toutes les requêtes ci-dessous voient la base au même instant,
    # même si des paiements arrivent pendant le contrôle.
    session.connection(execution_options={"isolation_level": "REPEATABLE READ"})
    violations: list[Violation] = []

    total_balance = session.scalar(select(func.coalesce(func.sum(Account.balance_cents), 0)))
    expected_total = session.scalar(
        select(func.coalesce(func.sum(LedgerEntry.amount_cents), 0)).where(LedgerEntry.kind == EntryKind.OPENING)
    )
    if total_balance != expected_total:
        violations.append(Violation(
            rule="TOTAL_MISMATCH",
            detail=f"Somme des soldes {total_balance} ≠ total d'ouverture {expected_total}",
        ))

    # Solde stocké ≠ somme des écritures : modification directe de la base.
    ledger_sum = func.coalesce(func.sum(LedgerEntry.amount_cents), 0)
    for account_id, balance, ledger in session.execute(
        select(Account.id, Account.balance_cents, ledger_sum)
        .outerjoin(LedgerEntry, LedgerEntry.account_id == Account.id)
        .group_by(Account.id)
        .having(Account.balance_cents != ledger_sum)
        .limit(MAX_VIOLATIONS_PER_RULE)
    ):
        violations.append(Violation(
            rule="BALANCE_LEDGER_MISMATCH",
            detail=f"Compte {account_id} : solde {balance} ≠ écritures {ledger}",
        ))

    for (account_id,) in session.execute(
        select(Account.id).where(Account.balance_cents < 0).limit(MAX_VIOLATIONS_PER_RULE)
    ):
        violations.append(Violation(rule="NEGATIVE_BALANCE", detail=f"Compte {account_id} en solde négatif"))

    # Un paiement capturé = exactement un débit de -montant et un crédit de +montant ; un refus = aucune écriture.
    entry_count = func.count(LedgerEntry.id)
    debit_sum = func.coalesce(func.sum(case((LedgerEntry.kind == EntryKind.DEBIT, LedgerEntry.amount_cents))), 0)
    credit_sum = func.coalesce(func.sum(case((LedgerEntry.kind == EntryKind.CREDIT, LedgerEntry.amount_cents))), 0)
    for payment_id, status in session.execute(
        select(Payment.id, Payment.status)
        .outerjoin(LedgerEntry, LedgerEntry.payment_id == Payment.id)
        .group_by(Payment.id)
        .having(or_(
            (Payment.status == PaymentStatus.CAPTURED)
            & ((entry_count != 2) | (debit_sum != -Payment.amount_cents) | (credit_sum != Payment.amount_cents)),
            (Payment.status == PaymentStatus.REJECTED) & (entry_count != 0),
        ))
        .limit(MAX_VIOLATIONS_PER_RULE)
    ):
        violations.append(Violation(
            rule="UNBALANCED_PAYMENT",
            detail=f"Paiement {payment_id} ({status.value}) : écritures incohérentes",
        ))

    session.rollback()  # lecture seule : on libère l'instantané
    return ConsistencyReport(
        consistent=not violations,
        checked_at=datetime.now(timezone.utc),
        total_balance_cents=total_balance,
        expected_total_cents=expected_total,
        violations=violations,
    )
