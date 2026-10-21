# Contexte de build : services/ (pour embarquer services/common)
#   docker build -f services/auth/Dockerfile services/
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Utilisateur non-root sans shell de connexion
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app

COPY common /opt/common
COPY auth/requirements.txt .
RUN pip install /opt/common -r requirements.txt

COPY auth/alembic.ini ./
COPY auth/migrations ./migrations
COPY auth/app ./app
COPY --chmod=755 auth/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

USER app
EXPOSE 8000

# python plutôt que curl : l'image slim n'embarque pas curl
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"

# Configuration (jamais dans l'image ; secrets en fichiers /run/secrets/*, voir resilience_common/config.py) :
#   base : DB_HOST, DB_NAME, DB_USER, DB_PASSWORD_FILE (ou DATABASE_URL en local)
#   mots de passe de démo : DEMO_CLIENT_PASSWORD_FILE, SMOKE_CLIENT_PASSWORD_FILE, OPERATOR_PASSWORD_FILE
# Optionnelle : JWT_PRIVATE_KEY_FILE (sinon clé de signature éphémère, régénérée à chaque démarrage).
ENTRYPOINT ["docker-entrypoint.sh"]
