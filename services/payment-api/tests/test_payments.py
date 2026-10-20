import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text

from app.db import get_engine, get_sessionmaker
from app.main import app
from app.models import Account, LedgerEntry, Payment, PaymentStatus
from app.payments import create_payment
from app.schemas import PaymentRequest
from app.security import CurrentUser, get_current_user
from app.seed import account_id, user_id

ALICE = CurrentUser(id=user_id("alice"), role="client")
BOB = CurrentUser(id=user_id("bob"), role="client")
CAFE = CurrentUser(id=user_id("cafe-demo"), role="client")
OPERATOR = CurrentUser(id=user_id("operator"), role="operator")


@pytest.fixture
def as_user():
    """as_user(ALICE) renvoie un client HTTP authentifié comme ALICE."""

    def _client(user: CurrentUser) -> TestClient:
        app.dependency_overrides[get_current_user] = lambda: user
        return TestClient(app)

    yield _client
    app.dependency_overrides.clear()


def pay(client: TestClient, amount=2_500, key=None, src="alice", dst="cafe-demo", **extra):
    body = {"from_account_id": str(account_id(src)), "to_account_id": str(account_id(dst)), "amount_cents": amount}
    body.update(extra)
    return client.post("/payments", json=body, headers={"Idempotency-Key": key or uuid.uuid4().hex})


def balance(name: str) -> int:
    with get_sessionmaker()() as session:
        return session.get(Account, account_id(name)).balance_cents


# ------------------------------------------------------------------ paiement


def test_captured_payment_moves_money_and_writes_ledger(as_user):
    response = pay(as_user(ALICE), amount=2_500)
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "CAPTURED" and body["rejection_reason"] is None
    assert balance("alice") == 147_500
    assert balance("cafe-demo") == 2_500
    with get_sessionmaker()() as session:
        entries = session.scalars(select(LedgerEntry.amount_cents).where(LedgerEntry.payment_id == uuid.UUID(body["id"])))
        assert sorted(entries) == [-2_500, 2_500]


def test_replay_with_same_key_returns_original_without_new_debit(as_user):
    client = as_user(ALICE)
    first = pay(client, key="replay-key-1")
    second = pay(client, key="replay-key-1")
    assert second.status_code == 200
    assert second.json()["id"] == first.json()["id"]
    assert balance("alice") == 147_500


def test_same_key_with_different_body_is_conflict(as_user):
    client = as_user(ALICE)
    pay(client, amount=2_500, key="conflict-key")
    response = pay(client, amount=9_999, key="conflict-key")
    assert response.status_code == 409
    assert balance("alice") == 147_500


def test_insufficient_funds_is_rejected_and_recorded(as_user):
    response = pay(as_user(ALICE), amount=1_000_000)  # 10 000 € > 1 500 €
    assert response.status_code == 422
    assert response.json()["status"] == "REJECTED"
    assert response.json()["rejection_reason"] == "INSUFFICIENT_FUNDS"
    assert balance("alice") == 150_000


def test_unknown_destination_is_rejected(as_user):
    client = as_user(ALICE)
    body = {"from_account_id": str(account_id("alice")), "to_account_id": str(uuid.uuid4()), "amount_cents": 100}
    response = client.post("/payments", json=body, headers={"Idempotency-Key": "unknown-dest-1"})
    assert response.status_code == 422
    assert response.json()["rejection_reason"] == "UNKNOWN_DESTINATION"


def test_same_account_is_rejected(as_user):
    response = pay(as_user(ALICE), dst="alice")
    assert response.status_code == 422
    assert response.json()["rejection_reason"] == "SAME_ACCOUNT"


def test_cannot_debit_someone_elses_account(as_user):
    response = pay(as_user(BOB), src="alice")
    assert response.status_code == 403
    assert balance("alice") == 150_000


@pytest.mark.parametrize(
    "amount, extra, headers",
    [
        (0, {}, None),  # montant nul
        (1_000_001, {}, None),  # au-delà du plafond
        (100, {"status": "CAPTURED"}, None),  # champ inattendu
        (100, {}, {}),  # Idempotency-Key absente
        (100, {}, {"Idempotency-Key": "short"}),  # clé trop courte
    ],
)
def test_invalid_requests_are_400(as_user, amount, extra, headers):
    body = {"from_account_id": str(account_id("alice")), "to_account_id": str(account_id("cafe-demo")), "amount_cents": amount}
    body.update(extra)
    response = as_user(ALICE).post("/payments", json=body, headers=headers if headers is not None else {"Idempotency-Key": uuid.uuid4().hex})
    assert response.status_code == 400
    assert balance("alice") == 150_000


def test_unauthenticated_request_is_401():
    response = TestClient(app).get("/accounts")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


# ------------------------------------------------------------------ concurrence


def test_concurrent_payments_never_overdraw():
    """Alice a 1 500 € ; 20 paiements simultanés de 100 € : exactement 15 passent, solde final 0."""
    def one(i):
        with get_sessionmaker()() as session:
            body = PaymentRequest(from_account_id=account_id("alice"), to_account_id=account_id("cafe-demo"), amount_cents=10_000)
            payment, _ = create_payment(session, ALICE, f"concurrent-{i:04d}", body)
            return payment.status

    with ThreadPoolExecutor(max_workers=10) as pool:
        statuses = list(pool.map(one, range(20)))

    assert statuses.count(PaymentStatus.CAPTURED) == 15
    assert statuses.count(PaymentStatus.REJECTED) == 5
    assert balance("alice") == 0
    assert balance("cafe-demo") == 150_000


def test_concurrent_requests_with_same_key_debit_once():
    def one(_):
        with get_sessionmaker()() as session:
            body = PaymentRequest(from_account_id=account_id("alice"), to_account_id=account_id("cafe-demo"), amount_cents=2_500)
            payment, _ = create_payment(session, ALICE, "same-key-race", body)
            return payment.id

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = set(pool.map(one, range(8)))

    assert len(ids) == 1
    assert balance("alice") == 147_500
    with get_sessionmaker()() as session:
        assert session.scalar(select(func.count()).select_from(Payment)) == 1


# ------------------------------------------------------------------ lectures


def test_client_sees_only_own_accounts(as_user):
    accounts = as_user(ALICE).get("/accounts").json()
    assert [a["id"] for a in accounts] == [str(account_id("alice"))]


def test_operator_sees_all_accounts(as_user):
    assert len(as_user(OPERATOR).get("/accounts").json()) == 5


def test_other_clients_account_is_404_not_403(as_user):
    assert as_user(BOB).get(f"/accounts/{account_id('alice')}").status_code == 404


def test_payment_visible_to_payer_and_merchant_only(as_user):
    payment_id = pay(as_user(ALICE)).json()["id"]
    assert as_user(ALICE).get(f"/payments/{payment_id}").status_code == 200
    assert as_user(CAFE).get(f"/payments/{payment_id}").status_code == 200
    assert as_user(BOB).get(f"/payments/{payment_id}").status_code == 404
    assert as_user(BOB).get("/payments").json() == []
    assert len(as_user(OPERATOR).get("/payments").json()) == 1


# ------------------------------------------------------------------ cohérence


def test_consistency_ok_after_payments(as_user):
    client = as_user(ALICE)
    pay(client, amount=2_500)
    pay(client, amount=1_000_000)  # refusé
    report = as_user(OPERATOR).get("/operations/consistency").json()
    assert report["consistent"] is True
    assert report["total_balance_cents"] == report["expected_total_cents"] == 330_000
    assert report["violations"] == []


def test_consistency_detects_direct_balance_tampering(as_user):
    # Simule une attaque qui modifie un solde directement en base (ex. injection SQL).
    with get_engine().begin() as conn:
        conn.execute(text("UPDATE accounts SET balance_cents = balance_cents + 99900 WHERE id = :id"), {"id": account_id("bob")})
    report = as_user(OPERATOR).get("/operations/consistency").json()
    assert report["consistent"] is False
    assert {v["rule"] for v in report["violations"]} == {"TOTAL_MISMATCH", "BALANCE_LEDGER_MISMATCH"}


def test_consistency_detects_deleted_ledger_entry(as_user):
    payment_id = pay(as_user(ALICE)).json()["id"]
    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM ledger_entries WHERE payment_id = :id AND kind = 'CREDIT'"), {"id": payment_id})
    rules = {v["rule"] for v in as_user(OPERATOR).get("/operations/consistency").json()["violations"]}
    assert "UNBALANCED_PAYMENT" in rules


def test_consistency_is_operator_only(as_user):
    assert as_user(ALICE).get("/operations/consistency").status_code == 403
