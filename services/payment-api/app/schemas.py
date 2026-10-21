"""Schémas d'entrée/sortie de l'API, alignés sur contracts/openapi-payment.yaml."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class PaymentRequest(BaseModel):
    # extra="forbid" : un champ inattendu (ex. "status") est refusé au lieu d'être ignoré silencieusement.
    model_config = ConfigDict(extra="forbid")

    from_account_id: uuid.UUID
    to_account_id: uuid.UUID
    amount_cents: int = Field(ge=1, le=1_000_000, description="Plafond 10 000 € par paiement")
    label: str | None = Field(default=None, max_length=140)


class AccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    owner_id: uuid.UUID
    label: str
    balance_cents: int
    currency: str


class PaymentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    from_account_id: uuid.UUID
    to_account_id: uuid.UUID
    amount_cents: int
    currency: str
    label: str | None
    status: Literal["CAPTURED", "REJECTED"]
    rejection_reason: Literal["INSUFFICIENT_FUNDS", "SAME_ACCOUNT", "UNKNOWN_DESTINATION"] | None
    created_at: datetime


class Violation(BaseModel):
    rule: Literal["TOTAL_MISMATCH", "UNBALANCED_PAYMENT", "NEGATIVE_BALANCE", "BALANCE_LEDGER_MISMATCH"]
    detail: str


class ConsistencyReport(BaseModel):
    consistent: bool
    checked_at: datetime
    total_balance_cents: int
    expected_total_cents: int
    violations: list[Violation]
