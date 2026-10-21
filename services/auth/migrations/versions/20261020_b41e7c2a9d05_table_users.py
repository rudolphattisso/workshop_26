"""Table users (identifiant déterministe, haché argon2id, rôle)

Revision ID: b41e7c2a9d05
Revises:
Create Date: 2026-10-20 16:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b41e7c2a9d05'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('users',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('role', sa.Enum('client', 'operator', name='user_role'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )


def downgrade() -> None:
    op.drop_table('users')
    # Le type ENUM survit à la table : sans ce DROP, un nouvel upgrade échouerait (« type already exists »).
    sa.Enum(name='user_role').drop(op.get_bind(), checkfirst=True)
