"""Schéma initial : comptes, paiements et grand livre (ledger)

Revision ID: 7d0143bd1630
Revises: 
Create Date: 2026-10-20 11:51:04.072217

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7d0143bd1630'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('accounts',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('owner_id', sa.Uuid(), nullable=False),
    sa.Column('kind', sa.Enum('CUSTOMER', 'MERCHANT', name='account_kind'), nullable=False),
    sa.Column('label', sa.String(length=64), nullable=False),
    sa.Column('balance_cents', sa.BigInteger(), nullable=False),
    sa.Column('currency', sa.String(length=3), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('balance_cents >= 0', name='balance_non_negative'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_accounts_owner_id'), 'accounts', ['owner_id'], unique=False)
    op.create_table('payments',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('requester_id', sa.Uuid(), nullable=False),
    sa.Column('idempotency_key', sa.String(length=64), nullable=False),
    sa.Column('request_hash', sa.String(length=64), nullable=False),
    sa.Column('from_account_id', sa.Uuid(), nullable=False),
    sa.Column('to_account_id', sa.Uuid(), nullable=False),
    sa.Column('amount_cents', sa.BigInteger(), nullable=False),
    sa.Column('currency', sa.String(length=3), nullable=False),
    sa.Column('label', sa.String(length=140), nullable=True),
    sa.Column('status', sa.Enum('CAPTURED', 'REJECTED', name='payment_status'), nullable=False),
    sa.Column('rejection_reason', sa.Enum('INSUFFICIENT_FUNDS', 'SAME_ACCOUNT', 'UNKNOWN_DESTINATION', name='rejection_reason'), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(status = 'CAPTURED' AND rejection_reason IS NULL) OR (status = 'REJECTED' AND rejection_reason IS NOT NULL)", name='rejection_reason_matches_status'),
    sa.CheckConstraint('amount_cents > 0', name='amount_positive'),
    sa.ForeignKeyConstraint(['from_account_id'], ['accounts.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('requester_id', 'idempotency_key', name='uq_payment_idempotency')
    )
    op.create_index(op.f('ix_payments_created_at'), 'payments', ['created_at'], unique=False)
    op.create_index(op.f('ix_payments_from_account_id'), 'payments', ['from_account_id'], unique=False)
    op.create_index(op.f('ix_payments_to_account_id'), 'payments', ['to_account_id'], unique=False)
    op.create_table('ledger_entries',
    sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
    sa.Column('account_id', sa.Uuid(), nullable=False),
    sa.Column('payment_id', sa.Uuid(), nullable=True),
    sa.Column('kind', sa.Enum('OPENING', 'DEBIT', 'CREDIT', name='entry_kind'), nullable=False),
    sa.Column('amount_cents', sa.BigInteger(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("(kind = 'OPENING' AND payment_id IS NULL AND amount_cents >= 0) OR (kind = 'DEBIT' AND payment_id IS NOT NULL AND amount_cents < 0) OR (kind = 'CREDIT' AND payment_id IS NOT NULL AND amount_cents > 0)", name='entry_kind_consistent'),
    sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ),
    sa.ForeignKeyConstraint(['payment_id'], ['payments.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ledger_entries_account_id'), 'ledger_entries', ['account_id'], unique=False)
    op.create_index(op.f('ix_ledger_entries_payment_id'), 'ledger_entries', ['payment_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_ledger_entries_payment_id'), table_name='ledger_entries')
    op.drop_index(op.f('ix_ledger_entries_account_id'), table_name='ledger_entries')
    op.drop_table('ledger_entries')
    op.drop_index(op.f('ix_payments_to_account_id'), table_name='payments')
    op.drop_index(op.f('ix_payments_from_account_id'), table_name='payments')
    op.drop_index(op.f('ix_payments_created_at'), table_name='payments')
    op.drop_table('payments')
    op.drop_index(op.f('ix_accounts_owner_id'), table_name='accounts')
    op.drop_table('accounts')
    # drop_table ne supprime pas les types ENUM de PostgreSQL : sans ça, un upgrade après downgrade échoue.
    for enum_name in ('entry_kind', 'rejection_reason', 'payment_status', 'account_kind'):
        sa.Enum(name=enum_name).drop(op.get_bind(), checkfirst=True)
