# services/ — domaine Dev

Microservices Python/FastAPI et interfaces React de RESILIENCE-ALPHA. Les choix sont décrits dans
`docs/adr/ADR-DEV-0001-stack-dev.md`, les conventions dans `contracts/service-conventions.md`.

| Dossier | Contenu |
|---|---|
| `common/` | Socle partagé : logs JSON, trace_id, `/health` `/ready` `/metrics`, erreurs RFC 9457, vérification JWT |
| `auth/` | Connexion, jetons RS256, JWKS (`contracts/openapi-payment.yaml`, tag auth ; ADR-DEV-0003) |
| `payment-api/` | Comptes et paiements fictifs (`contracts/openapi-payment.yaml`) |
| `smoke-test/` | Transaction de bout en bout à travers le WAF, toutes les 5 s et sur `GET /check` (service Compose `txprobe`) |

## Développer en local (Windows, Git Bash)

```bash
cd services
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt

# Bases PostgreSQL locales (payment 127.0.0.1:5433, auth 127.0.0.1:5434)
# — copier d'abord .env.example en .env et remplacer TOUTES les valeurs (mots de passe de démo : 12 caractères min.)
docker compose -f compose.dev.yml --env-file .env up -d --wait
set -a && . ./.env && set +a          # exporte DATABASE_URL, AUTH_DATABASE_URL, mots de passe…

# Tests (ils VIDENT les bases pointées par DATABASE_URL et AUTH_DATABASE_URL)
.venv/Scripts/python -m pytest common/tests
(cd payment-api && ../.venv/Scripts/python -m pytest)
(cd auth && ../.venv/Scripts/python -m pytest)

# Schéma et comptes de démo
(cd payment-api && ../.venv/Scripts/alembic upgrade head && ../.venv/Scripts/python -m app.seed)

# Lancer un service avec la doc interactive sur http://127.0.0.1:8000/docs
cd payment-api
ENABLE_DOCS=true ../.venv/Scripts/python -m uvicorn app.main:app --reload

# Lancer l'auth en parallèle sur le port 8001 (payment-api y lit les clés via AUTH_JWKS_URL)
cd auth
DATABASE_URL=$AUTH_DATABASE_URL ../.venv/Scripts/alembic upgrade head
DATABASE_URL=$AUTH_DATABASE_URL ../.venv/Scripts/python -m app.seed
DATABASE_URL=$AUTH_DATABASE_URL ENABLE_DOCS=true ../.venv/Scripts/python -m uvicorn app.main:app --port 8001
```

## Routes publiques et configuration en déploiement

Le WAF (BunkerWeb, Infra) est le seul point d'entrée et transmet l'URI **sans la réécrire** : les routes
publiques sont donc préfixées `/api/...` (ADR-DEV-0005).

| Public (via le WAF) | Service | Sonde publique |
|---|---|---|
| `/api/auth/*` | `auth` | `/api/auth/ready` |
| `/api/payments*`, `/api/accounts*` | `payment-api` | `/api/payments/ready` |
| `/api/operations/*` | `payment-api` | — non publié : réseau interne seulement |

`/health`, `/ready` et `/metrics` restent servis à la racine pour Docker et Prometheus (réseau interne).

Secrets : convention `<NOM>_FILE` (fichier `/run/secrets/<nom>` monté par Compose, alimenté par Vault).
Base : `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD_FILE`. En local, `DATABASE_URL` et les variables
`<NOM>` de `.env` restent acceptées.

## auth : jetons

- `POST /api/auth/login` → jeton RS256 de 15 min. `payment-api` le vérifie avec la clé publique (`AUTH_JWKS_URL`),
  gardée en cache : une panne de l'auth n'interrompt pas les paiements en cours.
- Clé de signature : `JWT_PRIVATE_KEY_FILE` si défini, sinon clé éphémère. **Redémarrer l'auth révoque alors
  tous les jetons** (levier de remédiation en cas de compromission).
- Utilisateurs de démo : `alice`, `bob`, `cafe-demo` (clients), `smoke-client` (smoke test), `operator`.

## smoke-test : preuve de reprise

- Parcours d'un vrai client, **à travers le WAF** : login `smoke-client` → `GET /api/accounts` → paiement de
  **1 centime** → relecture. 1 centime : le compte tient ~5,8 jours à une transaction toutes les 5 s (à 1 €, 83 min).
- `GET /check` : une transaction à la demande, `200 {ok: true, tx_id, duration_s, trace_id}` ou
  `503 {ok: false, step, error, …}`. Utilisé par le moteur de remédiation. **Réseau interne seulement** (vrai paiement).
- Métriques reprises du `txprobe` de l'Infra : `synthetic_transaction_success`, `_duration_seconds`,
  `_last_success_timestamp`, `synthetic_transactions_total{result,step}`, plus `synthetic_account_balance_cents`.
- Un trace_id par transaction (en-tête `X-Trace-Id`, aussi utilisé comme `Idempotency-Key`) : la transaction se
  suit dans les logs de tous les services.

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
