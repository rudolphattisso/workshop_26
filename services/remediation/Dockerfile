# Contexte de build : services/ (pour embarquer services/common)
#   docker build -f services/remediation/Dockerfile services/
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Utilisateur non-root sans shell de connexion
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app

COPY common /opt/common
COPY remediation/requirements.txt .
RUN pip install /opt/common -r requirements.txt

COPY remediation/app ./app

USER app
EXPOSE 8000

# python plutôt que curl : l'image slim n'embarque pas curl
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"

# Configuration (jamais dans l'image) :
#   AUTH_JWKS_URL : clés publiques de l'auth (accès opérateur), ex. http://auth:8000/api/auth/.well-known/jwks.json
#   WATCH_WAF_URL (http://bunkerweb:8080), WATCH_AUTH_URL (http://auth:8000), WATCH_PAYMENT_API_URL
#   (http://payment-api:8000), WATCH_SMOKE_TEST_URL (http://txprobe:8000), WATCHDOG_INTERVAL_SECONDS (5)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
