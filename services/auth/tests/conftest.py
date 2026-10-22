"""Les tests du service d'auth tournent contre un vrai PostgreSQL (base `auth` de services/compose.dev.yml).

La base est désignée par AUTH_DATABASE_URL (DATABASE_URL désigne celle de payment-api dans services/.env).
Ces tests VIDENT cette base : ne jamais la faire pointer vers une base de démo.
"""

import os

import pytest

if "AUTH_DATABASE_URL" in os.environ:
    os.environ["DATABASE_URL"] = os.environ["AUTH_DATABASE_URL"]

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.exc import OperationalError  # noqa: E402

from app.db import get_engine, get_sessionmaker, ping_database  # noqa: E402
from app.seed import seed  # noqa: E402

AUTH_DIR = os.path.dirname(os.path.dirname(__file__))

# Mots de passe propres aux tests (jamais ceux de la démo).
TEST_PASSWORDS = {
    "DEMO_CLIENT_PASSWORD": "test-client-password",
    "SMOKE_CLIENT_PASSWORD": "test-smoke-password",
    "OPERATOR_PASSWORD": "test-operator-password",
}


@pytest.fixture(scope="session", autouse=True)
def database():
    if "AUTH_DATABASE_URL" not in os.environ:
        pytest.skip("AUTH_DATABASE_URL absent : lancer services/compose.dev.yml et charger services/.env")
    try:
        ping_database()
    except OperationalError:
        pytest.skip("PostgreSQL injoignable : docker compose -f services/compose.dev.yml --env-file services/.env up -d")
    config = Config(os.path.join(AUTH_DIR, "alembic.ini"))
    config.set_main_option("script_location", os.path.join(AUTH_DIR, "migrations"))
    command.downgrade(config, "base")
    command.upgrade(config, "head")


@pytest.fixture(autouse=True)
def clean_seeded_db(database):
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE users"))
    with get_sessionmaker()() as session:
        seed(session, TEST_PASSWORDS)
