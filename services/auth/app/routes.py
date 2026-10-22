"""Routes du service d'auth : connexion, identité courante, clés publiques (JWKS) et LED du back-office.

La limitation du nombre de tentatives est confiée au WAF (Cyber) : un blocage par compte dans l'appli
permettrait à un attaquant de verrouiller le compte du smoke test et d'empêcher la preuve de reprise.
L'appli, elle, rend chaque tentative visible (logs + métrique) pour le SOC et le modèle de détection.
"""

import logging

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from prometheus_client import Counter
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_session
from app.iot import LedPattern, device_token_valid, led
from app.keys import ACCESS_TOKEN_TTL_SECONDS, issue_access_token, jwks
from app.models import Role, User
from app.passwords import verify_password
from app.schemas import IdentifyRequest, IdentifyResponse, LedStatus, LoginRequest, TokenResponse, UserOut
from app.security import CurrentUser, get_current_user

log = logging.getLogger(__name__)

# Préfixe /api/auth : le WAF transmet l'URI telle quelle (sans réécriture) à l'auth.
router = APIRouter(prefix="/api/auth", tags=["auth"])

LOGINS = Counter("auth_logins_total", "Tentatives de connexion", ["outcome"])  # success | invalid_credentials
IDENTIFICATIONS = Counter(
    "auth_backoffice_identifications_total", "Étape identifiant du back-office", ["outcome"]
)  # recognized | unrecognized


def is_operator(user: User | None) -> bool:
    return user is not None and user.role == Role.operator


@router.post("/login/identify")
def identify(
    body: IdentifyRequest, request: Request, session: Session = Depends(get_session)
) -> IdentifyResponse:
    """Étape 1 de la connexion au back-office (dashboard) : l'identifiant est-il celui d'un opérateur ?

    Tient la place de la reconnaissance faciale prévue par la consigne (caméra non livrée) : « reconnu »
    signifie ici « compte opérateur existant ». La réponse révèle donc si un identifiant opérateur existe,
    comme le ferait la caméra ; seuls les comptes opérateur sont concernés et le débit est limité par le WAF.
    """
    user = session.scalar(select(User).where(User.username == body.username))
    recognized = is_operator(user)
    IDENTIFICATIONS.labels("recognized" if recognized else "unrecognized").inc()
    led.set(LedPattern.GREEN_BLINK if recognized else LedPattern.RED_FIXED_30S)
    if not recognized:
        log.warning(
            "backoffice_identify_failed",
            extra={"username": body.username, "client_ip": request.client.host if request.client else None},
        )
    return IdentifyResponse(recognized=recognized)


@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest, request: Request, response: Response, session: Session = Depends(get_session)
) -> TokenResponse:
    user = session.scalar(select(User).where(User.username == body.username))
    # Même vérification argon2 que l'utilisateur existe ou non (voir passwords.py), même message d'erreur :
    # la réponse ne révèle pas si le compte existe.
    # La LED ne suit que les comptes opérateur : le smoke test (smoke-client) et les attaques sur les
    # comptes clients ne doivent pas la faire clignoter en permanence.
    if not verify_password(user.password_hash if user else None, body.password):
        if is_operator(user):
            led.set(LedPattern.RED_BLINK_X10)
        LOGINS.labels("invalid_credentials").inc()
        log.warning(
            "login_failed",
            extra={"username": body.username, "client_ip": request.client.host if request.client else None},
        )
        raise HTTPException(401, "Identifiants invalides", headers={"WWW-Authenticate": "Bearer"})

    if is_operator(user):
        led.set(LedPattern.GREEN_FIXED_30S)
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


@router.get("/iot/led")
def iot_led(response: Response, x_device_token: str | None = Header(default=None)) -> LedStatus:
    """Motif à afficher par l'ESP32, interrogé toutes les 300 ms (iot/led-status/led-status.ino)."""
    valid = device_token_valid(x_device_token)
    if valid is None:
        raise HTTPException(503, "Objet connecté non configuré (IOT_DEVICE_TOKEN absent)")
    if not valid:
        raise HTTPException(401, "Jeton d'objet connecté invalide")
    pattern, seq = led.current()
    response.headers["Cache-Control"] = "no-store"
    return LedStatus(pattern=pattern.value, seq=seq)
