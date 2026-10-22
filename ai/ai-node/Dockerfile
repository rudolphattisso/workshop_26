# llm-gateway — service du PC IA (pôle IA).
# Mêmes conventions que infra/ml-detector : python:3.12-slim, utilisateur non-root 10001,
# conteneur en read_only (écriture seulement dans /tmp et le volume des rapports).
#
# Cibles :
#   runtime : API /analyze (uvicorn) + outils (python -m llm_gateway.cli index|analyze)
#   dev     : + pytest et tests (aucun GPU ni Ollama nécessaires : LLM simulé)

FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN groupadd --system --gid 10001 app && useradd --system --uid 10001 --gid app --no-create-home app
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY llm_gateway/ ./llm_gateway/
COPY knowledge/ ./knowledge/

FROM base AS runtime
USER 10001:10001
EXPOSE 8080
CMD ["uvicorn", "--factory", "llm_gateway.app:create_app", "--host", "0.0.0.0", "--port", "8080"]

FROM base AS dev
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY pytest.ini ./
COPY tests/ ./tests/
USER 10001:10001
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
