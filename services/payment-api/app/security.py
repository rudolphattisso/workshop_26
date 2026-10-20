"""Identité de l'appelant.

`get_current_user` est le point unique d'authentification de payment-api : toutes les routes métier en
dépendent. En attendant le service d'auth, il refuse toute requête (401) ; la vérification du JWT RS256
(clé publique via JWKS) le remplacera sans toucher aux routes. Les tests le substituent par un utilisateur fixe.
"""

import uuid
from dataclasses import dataclass
from typing import Literal

from fastapi import Depends, HTTPException


@dataclass(frozen=True)
class CurrentUser:
    id: uuid.UUID
    role: Literal["client", "operator"]


def get_current_user() -> CurrentUser:
    raise HTTPException(401, "Authentification requise", headers={"WWW-Authenticate": "Bearer"})


def require_operator(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    if user.role != "operator":
        raise HTTPException(403, "Réservé aux opérateurs")
    return user
