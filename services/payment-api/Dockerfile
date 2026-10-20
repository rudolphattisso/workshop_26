# Contexte de build : services/ (pour embarquer services/common)
#   docker build -f services/payment-api/Dockerfile services/
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Utilisateur non-root sans shell de connexion
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app

COPY common /opt/common
COPY payment-api/requirements.txt .
RUN pip install /opt/common -r requirements.txt

COPY payment-api/alembic.ini ./
COPY payment-api/migrations ./migrations
COPY payment-api/app ./app
COPY --chmod=755 payment-api/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

USER app
EXPOSE 8000

# python plutôt que curl : l'image slim n'embarque pas curl
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"

# Variables requises : DATABASE_URL (fournie par Vault/SOPS, jamais dans l'image)
# et AUTH_JWKS_URL (clés publiques du service d'auth, ex. http://auth:8000/auth/.well-known/jwks.json)
ENTRYPOINT ["docker-entrypoint.sh"]
