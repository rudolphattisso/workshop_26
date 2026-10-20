"""Routes du service d'auth : connexion, identité courante et clés publiques (JWKS).

La limitation du nombre de tentatives est confiée au WAF (Cyber) : un blocage par compte dans l'appli
permettrait à un attaquant de verrouiller le compte du smoke test et d'empêcher la preuve de reprise.
L'appli, elle, rend chaque tentative visible (logs + métrique) pour le SOC et le modèle de détection.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from prometheus_client import Counter
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_session
from app.keys import ACCESS_TOKEN_TTL_SECONDS, issue_access_token, jwks
from app.models import User
from app.passwords import verify_password
from app.schemas import LoginRequest, TokenResponse, UserOut
from app.security import CurrentUser, get_current_user

log = logging.getLogger(__name__)

# Préfixe /api/auth : le WAF transmet l'URI telle quelle (sans réécriture) à l'auth.
router = APIRouter(prefix="/api/auth", tags=["auth"])

LOGINS = Counter("auth_logins_total", "Tentatives de connexion", ["outcome"])  # success | invalid_credentials


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest, request: Request, response: Response, session: Session = Depends(get_session)
) -> TokenResponse:
    user = session.scalar(select(User).where(User.username == body.username))
    # Même vérification argon2 que l'utilisateur existe ou non (voir passwords.py), même message d'erreur :
    # la réponse ne révèle pas si le compte existe.
    if not verify_password(user.password_hash if user else None, body.password):
        LOGINS.labels("invalid_credentials").inc()
        log.warning(
            "login_failed",
            extra={"username": body.username, "client_ip": request.client.host if request.client else None},
        )
        raise HTTPException(401, "Identifiants invalides", headers={"WWW-Authenticate": "Bearer"})

    LOGINS.labels("success").inc()
    log.info("login_succeeded", extra={"user_id": str(user.id), "role": user.role.value})
    response.headers["Cache-Control"] = "no-store"  # un jeton ne doit jamais rester dans un cache (RFC 6749)
    return TokenResponse(access_token=issue_access_token(user), expires_in=ACCESS_TOKEN_TTL_SECONDS)


@router.get("/me")
def me(user: CurrentUser = Depends(get_current_user), session: Session = Depends(get_session)) -> UserOut:
    found = session.get(User, user.id)
    if found is None:  # jeton valide mais utilisateur supprimé depuis
        raise HTTPException(401, "Authentification requise", headers={"WWW-Authenticate": "Bearer"})
    return found


@router.get("/.well-known/jwks.json")
def get_jwks() -> dict:
    return jwks()
