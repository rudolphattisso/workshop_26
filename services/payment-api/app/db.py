"""Connexion PostgreSQL : moteur SQLAlchemy, sessions et sonde de disponibilité."""

from collections.abc import Iterator
from functools import lru_cache

from resilience_common.config import database_url
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker


@lru_cache
def get_engine() -> Engine:
    return create_engine(
        database_url(),
        # Teste la connexion avant de la réutiliser : après un redémarrage de PostgreSQL (remédiation),
        # les connexions mortes du pool sont remplacées au lieu de faire échouer les requêtes.
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        # Échouer vite plutôt que bloquer : /ready doit répondre même si la base ne répond plus.
        connect_args={"connect_timeout": 2},
    )


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_session() -> Iterator[Session]:
    """Dépendance FastAPI : une session par requête, toujours refermée."""
    with get_sessionmaker()() as session:
        yield session


def ping_database() -> None:
    """Sonde pour /ready : lève une exception si la base est injoignable."""
    with get_engine().connect() as conn:
        conn.execute(text("SELECT 1"))
