"""Modèle de données du service d'auth : les utilisateurs et leur rôle.

L'identifiant est calculé à partir du nom (`resilience_common.identity.user_id`) : payment-api retrouve
le propriétaire d'un compte sans interroger cette base.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Role(str, enum.Enum):
    # Noms en minuscules : ce sont aussi les valeurs du claim `role` des jetons.
    client = "client"
    operator = "operator"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    # Haché argon2id uniquement : le mot de passe n'est jamais stocké.
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role, name="user_role"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
