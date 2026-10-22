# Contexte de build : services/ (pour embarquer services/common)
#   docker build -f services/smoke-test/Dockerfile services/
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Utilisateur non-root sans shell de connexion
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app

COPY common /opt/common
COPY smoke-test/requirements.txt .
RUN pip install /opt/common -r requirements.txt

COPY smoke-test/app ./app

USER app
EXPOSE 8000

# python plutôt que curl : l'image slim n'embarque pas curl
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"

# Configuration (jamais dans l'image) :
#   PROBE_PASSWORD_FILE : mot de passe de smoke-client, ex. /run/secrets/probe_user_password
#   PROBE_TARGET (http://bunkerweb:8080 : à travers le WAF, comme un client), PROBE_USERNAME (smoke-client),
#   PROBE_INTERVAL_SECONDS (5 ; 0 = à la demande seulement), PROBE_HTTP_TIMEOUT_SECONDS (5)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
