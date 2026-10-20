# services/ — domaine Dev

Microservices Python/FastAPI et interfaces React de RESILIENCE-ALPHA. Les choix sont décrits dans
`docs/adr/ADR-DEV-0001-stack-dev.md`, les conventions dans `contracts/service-conventions.md`.

| Dossier | Contenu |
|---|---|
| `common/` | Socle partagé : logs JSON, trace_id, `/health` `/ready` `/metrics`, erreurs RFC 9457 |
| `payment-api/` | Comptes et paiements fictifs (`contracts/openapi-payment.yaml`) |

## Développer en local (Windows, Git Bash)

```bash
cd services
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt

# Base PostgreSQL locale (127.0.0.1:5433) — copier d'abord .env.example en .env et changer le mot de passe
docker compose -f compose.dev.yml --env-file .env up -d --wait
set -a && . ./.env && set +a          # exporte DATABASE_URL

# Tests (ceux de payment-api VIDENT la base pointée par DATABASE_URL)
.venv/Scripts/python -m pytest common/tests
(cd payment-api && ../.venv/Scripts/python -m pytest)

# Schéma et comptes de démo
(cd payment-api && ../.venv/Scripts/alembic upgrade head && ../.venv/Scripts/python -m app.seed)

# Lancer un service avec la doc interactive sur http://127.0.0.1:8000/docs
cd payment-api
ENABLE_DOCS=true ../.venv/Scripts/python -m uvicorn app.main:app --reload
```

## payment-api : données

- Modèles : `payment-api/app/models.py` (comptes, paiements, grand livre). Migrations : `payment-api/migrations/`.
- Nouvelle migration : modifier les modèles puis `alembic revision --autogenerate -m "..."`, **relire** le fichier généré.
- Au démarrage du conteneur (`docker-entrypoint.sh`) : `alembic upgrade head` (avec attente de la base),
  seed idempotent, puis Uvicorn.

## Construire une image

Le contexte de build est `services/`, pour que l'image embarque `common/` :

```bash
docker build -t resilience/payment-api:dev -f services/payment-api/Dockerfile services/
```

## Créer un nouveau service

```python
from resilience_common import create_app

app = create_app("mon-service", ready_checks={"database": ping_db})  # ping_db lève une exception si KO
```

Ajouter ensuite le service à `requirements-dev.txt` et copier le `Dockerfile` de `payment-api` en adaptant les chemins.
