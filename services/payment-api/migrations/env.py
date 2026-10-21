"""Configuration Alembic : URL fournie par resilience_common.config.database_url, schéma cible issu de app.models."""

from alembic import context
from resilience_common.config import database_url
from sqlalchemy import create_engine

from app.models import Base

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Génère le SQL sans se connecter (alembic upgrade head --sql), utile pour relecture."""
    context.configure(url=database_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(database_url())
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
