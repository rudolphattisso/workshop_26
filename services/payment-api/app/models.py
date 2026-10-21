"""Modèle de données de payment-api.

Principe du grand livre : tout mouvement d'argent est une écriture (`ledger_entries`).
Le solde stocké dans `accounts` est un cache qui doit toujours égaler la somme des écritures du compte ;
un écart révèle une modification directe de la base (voir /operations/consistency).

Les utilisateurs appartiennent au service d'auth : `owner_id` et `requester_id` sont des UUID
sans clé étrangère (deux services, deux bases).
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Enum, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class AccountKind(str, enum.Enum):
    CUSTOMER = "CUSTOMER"
    MERCHANT = "MERCHANT"


class PaymentStatus(str, enum.Enum):
    CAPTURED = "CAPTURED"
    REJECTED = "REJECTED"


class RejectionReason(str, enum.Enum):
    INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS"
    SAME_ACCOUNT = "SAME_ACCOUNT"
    UNKNOWN_DESTINATION = "UNKNOWN_DESTINATION"


class EntryKind(str, enum.Enum):
    OPENING = "OPENING"  # approvisionnement initial du compte (hors paiement)
    DEBIT = "DEBIT"  # sortie d'argent liée à un paiement (montant négatif)
    CREDIT = "CREDIT"  # entrée d'argent liée à un paiement (montant positif)


class Account(Base):
    __tablename__ = "accounts"
    __table_args__ = (
        # Dernier rempart : même en cas de bug applicatif, la base refuse un solde négatif.
        CheckConstraint("balance_cents >= 0", name="balance_non_negative"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(index=True)
    kind: Mapped[AccountKind] = mapped_column(Enum(AccountKind, name="account_kind"))
    label: Mapped[str] = mapped_column(String(64))
    balance_cents: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3), default="EUR")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Payment(Base):
    __tablename__ = "payments"
    __table_args__ = (
        CheckConstraint("amount_cents > 0", name="amount_positive"),
        # Idempotence : une même clé ne peut servir qu'une fois par demandeur (garanti par la base,
        # donc même si deux requêtes identiques arrivent en même temps).
        UniqueConstraint("requester_id", "idempotency_key", name="uq_payment_idempotency"),
        CheckConstraint(
            "(status = 'CAPTURED' AND rejection_reason IS NULL)"
            " OR (status = 'REJECTED' AND rejection_reason IS NOT NULL)",
            name="rejection_reason_matches_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    requester_id: Mapped[uuid.UUID]
    idempotency_key: Mapped[str] = mapped_column(String(64))
    # Empreinte du corps de la requête : même clé + corps différent => 409.
    request_hash: Mapped[str] = mapped_column(String(64))
    from_account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id"), index=True)
    # Pas de clé étrangère : un paiement vers un compte inconnu est enregistré comme REJECTED.
    to_account_id: Mapped[uuid.UUID] = mapped_column(index=True)
    amount_cents: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3), default="EUR")
    label: Mapped[str | None] = mapped_column(String(140))
    status: Mapped[PaymentStatus] = mapped_column(Enum(PaymentStatus, name="payment_status"))
    rejection_reason: Mapped[RejectionReason | None] = mapped_column(Enum(RejectionReason, name="rejection_reason"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class LedgerEntry(Base):
    __tablename__ = "ledger_entries"
    __table_args__ = (
        CheckConstraint(
            "(kind = 'OPENING' AND payment_id IS NULL AND amount_cents >= 0)"
            " OR (kind = 'DEBIT' AND payment_id IS NOT NULL AND amount_cents < 0)"
            " OR (kind = 'CREDIT' AND payment_id IS NOT NULL AND amount_cents > 0)",
            name="entry_kind_consistent",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    account_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("accounts.id"), index=True)
    payment_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("payments.id"), index=True)
    kind: Mapped[EntryKind] = mapped_column(Enum(EntryKind, name="entry_kind"))
    amount_cents: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
