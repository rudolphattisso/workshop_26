"""Les tests de payment-api tournent contre un vrai PostgreSQL (services/compose.dev.yml) :
les contraintes CHECK, les ENUM et l'unicité doivent être testés là où ils s'appliquent.

Ces tests VIDENT la base pointée par DATABASE_URL : ne jamais la faire pointer vers une base de démo.
"""

import os

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.db import get_engine, get_sessionmaker, ping_database
from app.seed import seed

PAYMENT_API_DIR = os.path.dirname(os.path.dirname(__file__))


@pytest.fixture(scope="session", autouse=True)
def database():
    if "DATABASE_URL" not in os.environ:
        pytest.skip("DATABASE_URL absent : lancer services/compose.dev.yml et charger services/.env")
    try:
        ping_database()
    except OperationalError:
        pytest.skip("PostgreSQL injoignable : docker compose -f services/compose.dev.yml --env-file services/.env up -d")
    config = Config(os.path.join(PAYMENT_API_DIR, "alembic.ini"))
    config.set_main_option("script_location", os.path.join(PAYMENT_API_DIR, "migrations"))
    command.downgrade(config, "base")
    command.upgrade(config, "head")


@pytest.fixture(autouse=True)
def clean_seeded_db(database):
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE ledger_entries, payments, accounts"))
    with get_sessionmaker()() as session:
        seed(session)


@pytest.fixture
def session():
    with get_sessionmaker()() as session:
        yield session
