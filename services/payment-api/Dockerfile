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

COPY payment-api/app ./app

USER app
EXPOSE 8000

# python plutôt que curl : l'image slim n'embarque pas curl
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"

# --no-access-log : le middleware commun produit déjà un log d'accès JSON
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
