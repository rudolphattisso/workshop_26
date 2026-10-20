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

# Tests
.venv/Scripts/python -m pytest common/tests payment-api/tests

# Lancer un service avec la doc interactive sur http://127.0.0.1:8000/docs
cd payment-api
ENABLE_DOCS=true ../.venv/Scripts/python -m uvicorn app.main:app --reload
```

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
