# ml-detector — image du module de détection (pôle IA).
# Conventions alignées sur services/Dockerfile du pôle infra : python:3.12-slim, utilisateur
# non-root 10001, aucune écriture hors /tmp (le conteneur tourne en read_only).
#
# Cibles :
#   base    : dépendances d'exécution uniquement
#   model   : entraîne la baseline pendant la construction (le modèle n'est pas versionné : l'image
#             se suffit à elle-même après un clone ; entraînement déterministe, quelques secondes)
#   runtime : service continu (python -m detector.service) : lit Loki, fenêtre glissante de 60 s
#             toutes les 10 s, escalade vers le llm-gateway, /metrics et /health sur 8000
#   dev     : + pytest, tests et scripts (entraînement, démos, rejeu en direct : scripts.run_service)

FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY detector/ ./detector/

FROM base AS model
COPY scripts/ ./scripts/
RUN python -m scripts.train_baseline --out /app/models/baseline.joblib

FROM base AS runtime
COPY --from=model /app/models/ ./models/
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]
CMD ["python", "-m", "detector.service"]

FROM base AS dev
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY pytest.ini ./
COPY scripts/ ./scripts/
COPY tests/ ./tests/
USER 10001:10001
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
