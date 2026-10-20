# Progression — dev

<!-- Une entrée par bloc de travail : date, fichiers, décisions, problèmes, ADR -->

## 2026-10-19 — Kick-off : organisation et cadrage du périmètre 3.1

**Fait**
- Lecture du sujet (PDF) et correction du `.gitignore` (chemin avec `\` non reconnu par Git)
- Mise en place de l'organisation Claude Code de l'équipe : `CLAUDE.md` racine (commun), `services/CLAUDE.md` (domaine Dev), `CLAUDE.local.md` personnel (non versionné)
- Squelette partagé : `contracts/`, `docs/adr/README.md`, `docs/progression/<domaine>.md`
- Brainstorm de cadrage du 3.1 à partir de l'archi cible de l'équipe (`doc/private/2026-10-19_15h01_47.png`)

**Fichiers créés / modifiés**
- `.gitignore`, `CLAUDE.md`, `services/CLAUDE.md`, `contracts/README.md`, `docs/adr/README.md`, `docs/progression/*.md`

**Décisions actées**
- Je couvre seul l'intégralité du 3.1 : DB, API métier, auth, frontal web, moteur de remédiation, dashboard React/Tailwind. Tous les composants sont jugés importants.
- Chaque profil reste dans son couloir (sections 3.1 à 3.5 du sujet).
- Le métier simulé est le **prestataire de paiement** (l'entreprise financière exploite la plateforme), pas une boutique : catalogue, panier et stock sont hors périmètre ; un marchand se réduit à une commande pré-créée ou un appel API.
- Principe du moteur de remédiation : relancer automatiquement les services quand l'applicatif tombe (scénario de référence : DDoS).

**Orientations proposées (non encore actées)**
- Moteur en trois temps : contenir → rétablir → vérifier par une transaction fictive, avec anti-boucle de redémarrage
- Deux rôles : client et opérateur (accès au dashboard de supervision)
- Cohérence vérifiable : somme des soldes constante, aucun paiement capturé sans débit/crédit correspondants

**Écarts relevés dans l'archi cible (à remonter à l'équipe)**
- Moteur de remédiation absent du schéma (le ML détecte, mais personne n'agit ni ne vérifie la reprise)
- « Applicatif front/back » en un seul bloc alors que le 3.1 exige frontal, API métier et auth séparés
- Grafana utilisé comme dashboard alors que le 3.1 impose une interface React/Tailwind (les deux peuvent coexister)
- Hors couloir Dev : le RAG qui modifie les règles WAF/SIEM contredit le 3.3 ; le ML sur le serveur secondaire contredit la section 4 (le PC de délestage n'héberge qu'Ollama)

**Questions ouvertes**
- Frontière moteur de remédiation ↔ WAF (Cyber) pour l'étape « contenir » — reportée
- Traitement du paiement en une requête ou en deux temps (`EN_ATTENTE` → traité)
- Langage des services (FastAPI proposé, ADR-DEV-0001 à rédiger)

**Prochain démarrage** : trancher le traitement du paiement (une requête ou deux temps), puis rédiger le contrat `contracts/openapi-payment.yaml`.

## 2026-10-20 — Branches Git et contrat de l'API métier

**Fait**
- Création de la branche d'intégration `develop` (flux Dev, à titre exceptionnel : `dev/<sujet>` → `dev/app` → `develop` → `main`)
- Renommage de `app_dev` en `dev/app` (convention `<domaine>/<sujet>`) ; PR #1 `dev/app` → `develop` mergée
- Rédaction du contrat `contracts/openapi-payment.yaml` (auth + comptes + paiements + contrôle de cohérence)

**Fichiers créés / modifiés**
- `contracts/openapi-payment.yaml`, `docs/adr/ADR-DEV-0002-paiement-synchrone-idempotent.md`, `docs/adr/README.md`

**Décisions actées**
- Paiement **synchrone** en une transaction SQL, avec `Idempotency-Key` obligatoire (ADR-DEV-0002)
- Montants en centimes entiers, devise EUR unique
- JWT RS256 de 15 min, vérifié par JWKS (aucun secret partagé entre services) ; rôles `client` / `operator`
- 404 au lieu de 403 sur le compte d'un autre client (pas d'énumération) ; erreurs au format RFC 9457
- `GET /operations/consistency` sert de preuve de « données cohérentes » après remédiation

**Problèmes rencontrés**
- Push impossible : le DNS du partage de connexion iPhone (VPN actif) ne répondait pas. Contourné pour la
  commande avec `git -c http.curloptResolve=github.com:443:<ip>`
- `gh` n'est pas installé : PR créée depuis le navigateur

**Questions ouvertes**
- Mise à jour du workflow Git de `CLAUDE.md` pour y ajouter `develop` (fichier commun, PR dédiée)
- Révocation de jetons par le moteur de remédiation : à définir dans `openapi-remediation.yaml`
- Ports et exposition de `/health`, `/ready`, `/metrics` : à fixer par Infra + Cyber dans `contracts/network.md`

**Prochain démarrage** : `contracts/alert.schema.json` et `contracts/service-conventions.md`, puis le squelette FastAPI commun et l'ADR-DEV-0001

## 2026-10-20 (suite) — Stack Dev et squelette FastAPI commun

**Fait**
- Choix de la stack (ADR-DEV-0001) : portefeuille de paiement client → marchand, tout en Python/FastAPI synchrone,
  PostgreSQL + SQLAlchemy + Alembic, auth maison RS256, SQLite pour le moteur de remédiation, 2 fronts React séparés
- Socle commun `services/common` (`create_app`) : logs JSON, `X-Trace-Id`, métriques HTTP par route modèle,
  `/health` `/ready` `/metrics`, erreurs RFC 9457, `/docs` désactivé par défaut
- Squelette `services/payment-api` (FastAPI + Dockerfile non-root slim avec HEALTHCHECK)
- Contrat `contracts/service-conventions.md`
- 14 tests pytest au vert ; lancement local vérifié (logs JSON propres)

**Fichiers créés / modifiés**
- `docs/adr/ADR-DEV-0001-stack-dev.md`, `docs/adr/README.md`, `services/CLAUDE.md`
- `services/common/**`, `services/payment-api/**`, `services/requirements-dev.txt`, `services/README.md`,
  `services/.gitignore`, `services/.dockerignore`, `contracts/service-conventions.md`

**Décisions techniques**
- `X-Trace-Id` entrant accepté seulement s'il respecte `[A-Za-z0-9-]{8,64}`, pour éviter l'injection dans les logs
- Les exceptions non prévues sont interceptées dans le middleware, ce qui garde le trace_id dans la réponse 500
- Une erreur de validation renvoie 400 avec le nom du champ, jamais la valeur reçue
- Le log d'accès d'Uvicorn est désactivé : il ferait doublon avec `http_request`

**Problèmes rencontrés**
- Le log d'accès d'Uvicorn était réactivé par la propagation des loggers : corrigé en le désactivant explicitement
- Docker Desktop n'était pas lancé au premier essai ; build vérifié ensuite : image de 200 Mo, uid 10001, HEALTHCHECK `healthy`, `/docs` en 404

**À demander aux autres domaines**
- Infra : contexte de build `./services` pour les services Python ; scraping `/metrics` sur le port 8000
- Infra + Cyber : mode d'action du moteur sur les conteneurs (docker-socket-proxy ou Ansible)

**Prochain démarrage** : la couche de données de payment-api (modèles SQLAlchemy, migration Alembic, seed des comptes fictifs)

## 2026-10-20 (suite) — Couche de données de payment-api

**Fait**
- Modèles SQLAlchemy : `accounts`, `payments`, `ledger_entries` (grand livre : OPENING / DEBIT / CREDIT)
- Première migration Alembic, relue et corrigée (suppression des types ENUM au downgrade) ; cycle up → down → up vérifié
- Seed idempotent des comptes fictifs (alice, bob, cafe-demo, smoke-client, smoke-merchant) avec UUID déterministes
  (`uuid5(NAMESPACE_URL, "resilience-alpha:user:<username>")`) partagés avec le futur service d'auth
- `/ready` vérifie PostgreSQL ; entrypoint du conteneur : migrations (30 tentatives) → seed → Uvicorn
- Base PostgreSQL de développement `services/compose.dev.yml` (127.0.0.1:5433) + `services/.env.example`
- 29 tests au vert, dont 12 sur les contraintes en base réelle

**Décisions techniques**
- Le solde stocké doit toujours égaler la somme des écritures du compte : un écart révèle une modification directe de la base
- Contraintes en base, en dernier rempart : solde ≥ 0, montant > 0, idempotence unique par demandeur, motif de refus cohérent avec le statut, signe des écritures
- `to_account_id` sans clé étrangère, pour pouvoir enregistrer un refus `UNKNOWN_DESTINATION`
- `pool_pre_ping` + `connect_timeout=2` : l'API se reconnecte seule après un redémarrage de PostgreSQL
- Chaque vérification de `/ready` est bornée à 2 s (`READY_CHECK_TIMEOUT_SECONDS`) dans le socle commun
- `.gitattributes` : `*.sh` en LF, sinon l'entrypoint est cassé dans le conteneur Linux quand il est extrait sous Windows

**Essai de résilience (local)**
- PostgreSQL arrêté : `/ready` passe en 503 en 2 s ; PostgreSQL relancé : retour à 200 sans redémarrer l'API

**Problèmes rencontrés**
- `/ready` mettait 8 s pendant la panne : le DNS Docker transmettait le nom introuvable au DNS de l'hôte (partage iPhone) ; corrigé par le timeout des vérifications

**À demander à l'Infra**
- Deux bases dans PostgreSQL (`payment`, `auth`) avec un utilisateur dédié par service (moindre privilège)
- `DATABASE_URL` fournie à payment-api (via Vault/SOPS) ; `depends_on: condition: service_healthy` sur la base
- Sauvegardes et restauration de la base `payment` (le schéma se rejoue via Alembic au démarrage)

**Prochain démarrage** : logique de paiement (`POST /payments` transactionnel et idempotent, lectures, `/operations/consistency`)

## 2026-10-20 (suite) — Logique de paiement de payment-api

**Fait**
- `POST /payments` : transaction unique, verrouillage des comptes, idempotence, refus enregistrés
- Lectures `GET /accounts`, `/accounts/{id}`, `/payments`, `/payments/{id}` avec règles de visibilité client / opérateur
- `GET /operations/consistency` (opérateur) : 4 invariants comptables sur un instantané REPEATABLE READ
- Métriques métier `payments_total{status,reason}` et `payment_idempotent_replays_total`
- Découpage : `security.py` (identité), `schemas.py` (entrées/sorties), `payments.py` (métier), `routes.py` (HTTP)
- Contrat `openapi-payment` passé en 0.2.0 (règle `BALANCE_LEDGER_MISMATCH`) ; métriques documentées dans `service-conventions.md`
- 52 tests au vert (38 payment-api, 14 socle), dont 2 tests de concurrence

**Décisions techniques**
- `SELECT … FOR UPDATE` sur les deux comptes, triés par id : pas de double dépense, pas d'interblocage entre paiements croisés
- Idempotence garantie par la contrainte unique en base : la requête perdante d'une course renvoie le paiement de la gagnante
- Empreinte SHA-256 du corps canonique : même clé + corps différent ⇒ 409
- 404 (et non 403) sur une ressource d'un autre client ; 403 si on tente de débiter le compte d'autrui
- `get_current_user` refuse tout (401) en attendant le service d'auth ; les tests le substituent

**Problèmes rencontrés**
- Le test de concurrence « même clé » a révélé un bug : la violation d'unicité survenait au `flush()`, hors du `try` qui protégeait le `commit()`, d'où une erreur 500 pour la requête perdante. Corrigé en protégeant toute la phase d'écriture

**Prochain démarrage** : service d'auth (login, JWT RS256, JWKS), puis branchement de `get_current_user` sur la vérification JWT

## 2026-10-20 (suite) — Service d'auth et branchement de payment-api

**Fait**
- `services/auth` : `POST /auth/login`, `GET /auth/me`, `GET /auth/.well-known/jwks.json` ; PostgreSQL (`users`), Alembic, seed, Dockerfile non-root
- Socle commun : `resilience_common.jwt_auth` (vérification RS256, cache JWKS, dépendances FastAPI `bearer_user` / `require_role`) et `resilience_common.identity.user_id` (UUID partagés auth ↔ payment-api)
- payment-api : `get_current_user` vérifie maintenant les vrais jetons (fin du 401 systématique) ; nouvelle variable `AUTH_JWKS_URL`
- Contrats : `openapi-payment` 0.3.0 (claims `iss`/`aud`, `kid`), `service-conventions` 0.2 (`auth_logins_total`, événements de log de sécurité)
- `compose.dev.yml` : base `auth` locale (127.0.0.1:5434) ; `.env.example` complété (valeurs factices)
- ADR-DEV-0003
- 96 tests au vert (36 socle, 21 auth, 39 payment-api)

**Décisions techniques** (ADR-DEV-0003)
- JWKS en cache : auth en panne ⇒ les jetons existants restent valides ; `kid` inconnu ⇒ rechargement (max 1 / 5 s)
- Clé éphémère par défaut : redémarrer l'auth révoque tous les jetons (levier de remédiation) ; `JWT_PRIVATE_KEY_FILE` pour une clé stable
- Pas de verrouillage de compte dans l'appli (un attaquant pourrait bloquer `smoke-client`) : limitation de débit au WAF, échecs visibles en métrique et en log
- argon2id (paramètres OWASP), haché factice pour les identifiants inconnus (pas d'énumération de comptes)
- Mots de passe de démo par variables d'environnement, 12 caractères minimum, rotation au redémarrage

**Essais en conteneurs**
- Login → paiement → rejeu → contrôle de cohérence (opérateur) : OK ; client sur `/operations/consistency` : 403
- Auth arrêté : `GET /accounts` avec un jeton existant → 200, `/ready` de payment-api → 200
- Auth redémarré : ancien jeton → 401, nouveau jeton → 200, sans redémarrer payment-api

**Problèmes rencontrés**
- Le log `signing_key_loaded` n'apparaissait pas : la clé était chargée avant que `create_app` configure les logs. Corrigé en chargeant la clé après

**À demander**
- **Infra** : conteneur `auth` (build `./services`, `auth/Dockerfile`) ; base `auth` + utilisateur `auth_service` ; variables `DATABASE_URL`, `DEMO_CLIENT_PASSWORD`, `SMOKE_CLIENT_PASSWORD`, `OPERATOR_PASSWORD` via Vault/SOPS ; `AUTH_JWKS_URL=http://auth:8000/auth/.well-known/jwks.json` pour payment-api ; scraping `/metrics` de l'auth
- **Cyber** : limitation de débit sur `/auth/login` au WAF ; collecte des événements `login_failed` / `token_rejected` dans le SIEM ; décider si l'on monte une clé stable (`JWT_PRIVATE_KEY_FILE`) ou si l'on garde la clé éphémère
- **IA** : `auth_logins_total{outcome}` est une bonne feature pour détecter la force brute

**Prochain démarrage** : contrats `alert.schema.json` et `openapi-remediation.yaml`, puis smoke test (avec réessai sur 401)

## 2026-10-20 (suite) — Contrats du moteur de remédiation

**Fait**
- `contracts/alert.schema.json` 0.1.0 : format d'alerte unique (IA, WAF, SIEM, watchdog), strict, 6 types d'incident
- `contracts/openapi-remediation.yaml` 0.1.0 :
  - `POST /alerts` (jeton de service) et `POST /alerts/alertmanager` (format natif) ;
  - `GET /incidents`, `/incidents/{id}`, `/services`, `/playbooks` et le flux SSE `/events` (JWT opérateur) ;
  - le cycle de vie, la table des playbooks et les métriques
- ADR-DEV-0004
- Validation : le schéma est conforme JSON Schema 2020-12 et ses exemples sont valides. 8 alertes invalides
  sont bien rejetées (types et cibles inconnus, IP invalide, champ « action » imposé…). Les deux OpenAPI sont valides.

**Décisions techniques** (ADR-DEV-0004)
- L'émetteur décrit l'incident, le moteur choisit l'action selon une table publique (`GET /playbooks`)
- Reprise = `/ready` + nouvelle transaction (smoke test) + cohérence des données
- Déduplication (`alert_id`), cooldown de 120 s, 3 tentatives puis `ESCALATED`
- Watchdog intégré (sondes toutes les 5 s, cohérence toutes les 30 s) : filet de sécurité si ML ou Prometheus manquent
- Aucun endpoint d'action manuelle ; dashboard en lecture seule, flux SSE lu avec `fetch()` (jamais de jeton dans l'URL)

**À demander**
- **IA, Cyber, Infra** : relire `alert.schema.json` (types d'incident, cibles, `indicators`) et le valider dans leurs émetteurs
- **Infra** : règles Prometheus avec les labels `incident_type`, `target` et `severity` ; receiver webhook Alertmanager vers `http://remediation:8000/alerts/alertmanager` avec le jeton en `credentials_file`
- **Cyber** : une API ou un mécanisme pour **bloquer une IP au WAF** depuis le moteur (playbooks `TRAFFIC_FLOOD`, `BRUTE_FORCE`) ; `REMEDIATION_ALERT_TOKEN` dans Vault/SOPS
- **Infra + Cyber** (toujours bloquant) : mode d'action sur les conteneurs ; procédure de restauration de la base `payment`

**Prochain démarrage** : smoke test (`services/smoke-test`), puis moteur de remédiation v0 (watchdog + `SERVICE_DOWN`)
