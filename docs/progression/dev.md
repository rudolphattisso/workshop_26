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
