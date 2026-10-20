import uuid

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.models import Account, EntryKind, LedgerEntry, Payment, PaymentStatus, RejectionReason
from app.seed import DEMO_ACCOUNTS, account_id, seed, user_id


def make_payment(**overrides) -> Payment:
    values = dict(
        requester_id=user_id("alice"),
        idempotency_key="key-00000001",
        request_hash="h" * 64,
        from_account_id=account_id("alice"),
        to_account_id=account_id("cafe-demo"),
        amount_cents=2_500,
        status=PaymentStatus.CAPTURED,
    )
    values.update(overrides)
    return Payment(**values)


def test_seed_creates_demo_accounts(session):
    assert session.scalar(select(func.count()).select_from(Account)) == len(DEMO_ACCOUNTS)


def test_seed_is_idempotent(session):
    assert seed(session) == 0
    assert session.scalar(select(func.count()).select_from(Account)) == len(DEMO_ACCOUNTS)


def test_seeded_balances_match_ledger(session):
    for account in session.scalars(select(Account)):
        ledger_sum = session.scalar(
            select(func.coalesce(func.sum(LedgerEntry.amount_cents), 0)).where(LedgerEntry.account_id == account.id)
        )
        assert account.balance_cents == ledger_sum


def test_ids_are_deterministic_for_auth_service():
    # Le service d'auth recalcule les mêmes UUID : cette valeur ne doit jamais changer.
    assert user_id("alice") == uuid.UUID("51161924-207e-5e0d-a60f-7920cea65efb")
    assert user_id("alice") != user_id("bob")
    assert account_id("alice") != user_id("alice")


def test_database_refuses_negative_balance(session):
    alice = session.get(Account, account_id("alice"))
    alice.balance_cents = -1
    with pytest.raises(IntegrityError, match="balance_non_negative"):
        session.commit()


def test_database_refuses_non_positive_payment(session):
    session.add(make_payment(amount_cents=0))
    with pytest.raises(IntegrityError, match="amount_positive"):
        session.commit()


def test_database_enforces_idempotency_key_per_requester(session):
    session.add(make_payment())
    session.commit()
    session.add(make_payment())
    with pytest.raises(IntegrityError, match="uq_payment_idempotency"):
        session.commit()


def test_same_key_allowed_for_different_requesters(session):
    session.add(make_payment())
    session.add(make_payment(requester_id=user_id("bob"), from_account_id=account_id("bob")))
    session.commit()


def test_rejected_payment_requires_reason(session):
    session.add(make_payment(status=PaymentStatus.REJECTED))
    with pytest.raises(IntegrityError, match="rejection_reason_matches_status"):
        session.commit()


def test_rejected_payment_with_reason_is_accepted(session):
    session.add(make_payment(status=PaymentStatus.REJECTED, rejection_reason=RejectionReason.INSUFFICIENT_FUNDS))
    session.commit()


def test_debit_entry_must_be_negative_and_linked_to_payment(session):
    payment = make_payment()
    session.add(payment)
    session.flush()
    session.add(LedgerEntry(account_id=account_id("alice"), payment_id=payment.id, kind=EntryKind.DEBIT, amount_cents=2_500))
    with pytest.raises(IntegrityError, match="entry_kind_consistent"):
        session.commit()


def test_opening_entry_cannot_reference_payment(session):
    payment = make_payment()
    session.add(payment)
    session.flush()
    session.add(LedgerEntry(account_id=account_id("alice"), payment_id=payment.id, kind=EntryKind.OPENING, amount_cents=10))
    with pytest.raises(IntegrityError, match="entry_kind_consistent"):
        session.commit()
