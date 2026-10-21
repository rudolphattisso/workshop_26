# Image unique pour les services Python de référence (auth, payment-api, txprobe, remediation).
# Construite avec --build-arg SERVICE=<dossier> ; les couches de dépendances sont partagées.
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

FROM base
ARG SERVICE
ENV SERVICE_NAME=${SERVICE}
COPY common/obs.py ./obs.py
COPY ${SERVICE}/app.py ./app.py
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips=*"]
