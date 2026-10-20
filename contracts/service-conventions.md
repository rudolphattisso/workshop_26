# Conventions de service

> Producteur : Dev · Consommateurs : Infra (scraping, Loki, healthchecks), IA (features), Cyber (SIEM).
> Implémentées par le socle commun `services/common` (ADR-DEV-0001). Version 0.1 — 2026-10-20.

## Services concernés

Services Python du domaine Dev : `auth`, `payment-api`, `remediation`, `smoke-test`. Chacun écoute en HTTP sur le
**port 8000 dans son conteneur** (la publication éventuelle sur l'hôte relève de `contracts/network.md`).

## Sondes

| Endpoint | Sens | Réponse |
|---|---|---|
| `GET /health` | Le processus est vivant | `200 {"status":"ok","service":"<nom>"}` |
| `GET /ready` | Le service peut servir (dépendances joignables) | `200` si tout est OK, `503` sinon, avec `{"status","service","checks":{"database":"ok"\|"down"}}` |
| `GET /metrics` | Métriques Prometheus (format texte) | `200 text/plain` |

- Le **healthcheck Docker** utilise `/health`. Un échec signifie qu'il faut redémarrer le conteneur.
- Un échec de `/ready` signifie que le service tourne mais qu'une dépendance est en panne. Redémarrer ce service
  ne règle rien ; il faut traiter la dépendance.
- `/ready` répond en **2 s maximum** même si une dépendance ne répond plus (timeout ⇒ `down`).
- Ces endpoints ne sont **pas authentifiés** : ils restent sur le réseau interne et ne passent pas par le WAF.

## Métriques exposées

| Métrique | Type | Labels | Usage |
|---|---|---|---|
| `http_requests_total` | counter | `service`, `method`, `route`, `status` | Débit, taux d'erreurs 4xx/5xx (feature ML, alerting) |
| `http_request_duration_seconds` | histogram | `service`, `method`, `route` | Latence p50/p95/p99 (feature ML) |
| `service_dependency_up` | gauge | `service`, `dependency` | État des dépendances au dernier `/ready` |

`route` contient la **route modèle** (`/payments/{paymentId}`), jamais l'URL brute. Les requêtes hors route sont
regroupées sous `unmatched`.

Métriques métier de `payment-api` :

| Métrique | Type | Labels | Usage |
|---|---|---|---|
| `payments_total` | counter | `status` (`CAPTURED`/`REJECTED`), `reason` (motif de refus, vide si capturé) | Débit métier, pic de refus (feature ML) |
| `payment_idempotent_replays_total` | counter | — | Rejeux client : un pic signale des timeouts ou une perturbation |

## Logs

- **Une ligne JSON par événement sur stdout.** Pas de fichier de log dans le conteneur.
- Champs toujours présents :

| Champ | Exemple | Description |
|---|---|---|
| `timestamp` | `2026-10-20T09:16:56.512+00:00` | ISO 8601, UTC, à la milliseconde |
| `level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `service` | `payment-api` | Nom du service (bon label pour Loki) |
| `trace_id` | `cc53a895…` | Identifiant de la requête, `null` hors requête |
| `event` | `http_request` | Nom court de l'événement (snake_case) |
| `logger` | `resilience.http` | Module à l'origine du log |

- Champs propres à chaque événement, au même niveau. Exemple, l'événement `http_request` (une ligne par requête) :
  `method`, `route`, `status`, `duration_ms`, `client_ip`.
- Les requêtes vers `/health`, `/ready` et `/metrics` sont logguées en `DEBUG` (masquées au niveau par défaut `INFO`).
- **Jamais dans les logs** : mot de passe, jeton JWT, secret, en-tête `Authorization`.

## Corrélation : `X-Trace-Id`

- Un appelant peut fournir `X-Trace-Id` (8 à 64 caractères `[A-Za-z0-9-]`). Sinon le service en génère un.
- Le service le renvoie dans l'en-tête de réponse et le place dans tous ses logs, ainsi que dans le corps des erreurs.
- Un service qui en appelle un autre **propage** l'en-tête. On suit ainsi une transaction de bout en bout dans Loki.
- Recommandation (Cyber/Infra) : le WAF ou le reverse proxy pose un `X-Trace-Id` en entrée.

## Erreurs

Format RFC 9457, `Content-Type: application/problem+json` :

```json
{ "type": "about:blank", "title": "Requête invalide", "status": 400,
  "detail": "Champs invalides : body.amount_cents", "trace_id": "cc53a895…" }
```

Les erreurs de validation renvoient **400** (le nom du champ, jamais la valeur reçue). Une erreur interne renvoie
**500** générique, sans trace Python ; le détail reste dans les logs (`event: unhandled_exception`).

## Configuration (variables d'environnement)

| Variable | Défaut | Rôle |
|---|---|---|
| `LOG_LEVEL` | `INFO` | Niveau de log |
| `ENABLE_DOCS` | `false` | Sert `/docs` et `/openapi.json` (développement uniquement) |
| `READY_CHECK_TIMEOUT_SECONDS` | `2` | Durée max d'une vérification de `/ready` ; au-delà, la dépendance est `down` |

Variables propres à chaque service (URL de base de données, clés…) : documentées dans son `.env.example`.
Les secrets sont fournis par Vault ou SOPS, jamais en dur.

## Images

- Base `python:3.12-slim`, utilisateur **non-root** (uid 10001), `HEALTHCHECK` sur `/health`.
- **Contexte de build : `services/`** (pour embarquer `services/common`) :
  `docker build -f services/<service>/Dockerfile services/`
  Dans `docker-compose.yml` : `build: { context: ./services, dockerfile: <service>/Dockerfile }`.
