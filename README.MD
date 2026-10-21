# PROJECT RESILIENCE-ALPHA

Démonstrateur de **cyber-résilience** (Workshop EPSI M2, octobre 2026). Une plateforme de paiement **fictive**
subit une attaque. Le système détecte l'anomalie, se répare **sans intervention humaine**, puis prouve la reprise
par une **nouvelle transaction réussie**.

> Aucune donnée bancaire réelle · aucune action offensive hors de notre SI · aucun secret dans le dépôt.

## Équipe — groupe 2

| Membre | Domaine | Dossier |
|---|---|---|
| ATTISSO Rudolph | Développement (EISI) | `services/` |
| BOZZANI Arman | Infrastructure (EISI) | `infra/`, `docker-compose.yml` |
| TRAN HUU Tri Quentin | IA / Data | `ai/` |
| GARCIA Robin | Cybersécurité | `security/` |
| BREMARD Thomas | Cybersécurité | `security/` |

## Organisation du dépôt

```
├── services/        Dev : microservices Python/FastAPI, front et dashboard React + Tailwind
├── contracts/       Contrats entre domaines (OpenAPI, format d'alerte, conventions de service)
├── docs/
│   ├── adr/         Décisions techniques (ADR-<DOMAINE>-NNNN), index dans docs/adr/README.md
│   └── progression/ Journal de chaque domaine (matière du dossier PDF)
├── CLAUDE.md        Règles communes de l'équipe
└── README.MD        Ce fichier
```

La plateforme complète (WAF BunkerWeb, Vault, Prometheus, Grafana, Loki, moteur d'attaque) est construite par
l'Infra sur la branche `infrastructure`. Elle rejoindra `develop` avec son `docker-compose.yml` racine. En
attendant, `services/compose.dev.yml` lance l'application seule, avec une passerelle nginx qui **imite** le WAF.

---

## 1. Prérequis

| Outil | Version | Pour quoi | Obligatoire |
|---|---|---|---|
| **Docker Desktop** (backend WSL2 sous Windows) | Compose v2.20 ou plus | Construire et lancer tous les services | ✅ |
| **Git** (Git Bash sous Windows) | 2.40 ou plus | Cloner le dépôt, lancer les commandes ci-dessous | ✅ |
| Accès Internet au premier lancement | | Télécharger les images Docker et les dépendances | ✅ |
| Python | 3.12 | Lancer les tests et développer sans Docker | Tests seulement |
| Node.js | 20 | Lancer les tests du front et du dashboard | Tests seulement |

Machine conseillée : 8 Go de RAM, dont **4 Go alloués à Docker**, et 10 Go d'espace disque libre.

Ports utilisés **sur 127.0.0.1 uniquement** (ils doivent être libres) : `8080`, `8001` à `8004`, `8090`, `5433`
et `5434`. Rien n'est exposé sur le réseau.

> Toutes les commandes sont à taper dans **Git Bash**. Sous macOS ou Linux, n'importe quel terminal convient.

## 2. Installation

```bash
git clone https://github.com/rudolphattisso/workshop_26.git
cd workshop_26
git checkout develop                 # branche d'intégration de l'équipe
cd services
cp .env.example .env
```

Ouvrir ensuite `services/.env` et **remplacer chaque `change-me`** par un mot de passe de votre choix :

| Variable | Rôle | Contrainte |
|---|---|---|
| `PAYMENT_DB_PASSWORD`, `AUTH_DB_PASSWORD` | Mots de passe des deux bases PostgreSQL | Les reporter aussi dans `DATABASE_URL` et `AUTH_DATABASE_URL` |
| `DEMO_CLIENT_PASSWORD` | Comptes clients `alice`, `bob`, `cafe-demo` | 12 caractères minimum |
| `SMOKE_CLIENT_PASSWORD` | Compte du test de transaction automatique | 12 caractères minimum |
| `OPERATOR_PASSWORD` | Compte `operator` (dashboard de supervision) | 12 caractères minimum |

Pour générer un mot de passe : `openssl rand -base64 18`.

⚠️ `services/.env` est ignoré par Git : **ne jamais le commiter**, ne jamais le coller dans un message ni l'afficher
pendant la démo.

## 3. Lancement

Depuis `services/` :

```bash
docker compose -f compose.dev.yml --env-file .env --profile app up -d --build --wait
```

Le premier lancement prend quelques minutes (construction des images). La commande rend la main quand tous les
services sont démarrés.

```bash
docker compose -f compose.dev.yml --profile app ps      # état des conteneurs
docker compose -f compose.dev.yml --profile app down    # arrêt (ajouter -v pour effacer les bases)
```

## 4. Utilisation

| Interface | Adresse | Connexion |
|---|---|---|
| **Application client** (connexion, solde, paiement, historique) | http://127.0.0.1:8080 | `alice`, `bob` ou `cafe-demo` + `DEMO_CLIENT_PASSWORD` |
| **Dashboard de supervision** (carte des services, journal, alertes) | http://127.0.0.1:8090 | `operator` + `OPERATOR_PASSWORD` |
| Swagger de l'authentification | http://127.0.0.1:8001/docs | |
| Swagger de l'API de paiement | http://127.0.0.1:8002/docs | Bouton **Authorize** avec un jeton obtenu sur l'auth |
| Swagger du test de transaction | http://127.0.0.1:8003/docs | |
| Swagger du moteur de remédiation | http://127.0.0.1:8004/docs | Jeton `operator` |

Vérification rapide : http://127.0.0.1:8080/api/auth/ready et http://127.0.0.1:8080/api/payments/ready doivent
afficher `"status":"ok"`.

### Services lancés

| Service | Rôle |
|---|---|
| `gateway` | Point d'entrée unique, imite le WAF de l'Infra (`services/dev/gateway.conf`) |
| `web` | Application client React + Tailwind |
| `auth` | Connexion, jetons JWT RS256, clés publiques (JWKS) |
| `payment-api` | Comptes et paiements fictifs, idempotents, contrôle de cohérence |
| `smoke-test` | Transaction de 1 centime de bout en bout, en continu : la preuve de reprise |
| `remediation` | Moteur de remédiation : surveille chaque service et chaque connexion toutes les 5 s |
| `dashboard` | Supervision temps réel pour l'opérateur et le jury |
| `auth-db`, `payment-db` | Bases PostgreSQL de développement |

### Simuler une panne

Garder le dashboard ouvert, puis depuis `services/` :

```bash
docker compose -f compose.dev.yml stop payment-db    # popup rouge « Panne détectée » en ~5 s
docker compose -f compose.dev.yml start payment-db   # popup verte « Rétabli », avec la durée de l'interruption
```

## 5. Tests automatisés

Depuis `services/`. Les tests Python ont besoin des bases de développement.

```bash
# Une seule fois : environnement Python et dépendances du front
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt     # macOS / Linux : .venv/bin/python
(cd web && npm ci) && (cd dashboard && npm ci)

# Bases démarrées et variables de .env chargées
docker compose -f compose.dev.yml --env-file .env up -d --wait
set -a && . ./.env && set +a

.venv/Scripts/python -m pytest common/tests
for s in payment-api auth smoke-test remediation; do (cd $s && ../.venv/Scripts/python -m pytest); done
(cd web && npm test) && (cd dashboard && npm test)
```

⚠️ Les tests **vident les bases**. Pour retrouver les comptes de démo ensuite :
`docker compose -f compose.dev.yml --env-file .env --profile app up -d --force-recreate --wait`.

## 6. Documentation

| Sujet | Où |
|---|---|
| API de paiement et d'authentification (OpenAPI) | `contracts/openapi-payment.yaml` |
| API du moteur de remédiation (OpenAPI) | `contracts/openapi-remediation.yaml` |
| Format des alertes (IA, Prometheus, WAF → moteur) | `contracts/alert.schema.json` |
| Conventions de tout service (`/health`, `/ready`, `/metrics`, logs JSON) | `contracts/service-conventions.md` |
| Détail des services Dev (développement sans Docker, routes, jetons) | `services/README.md` |
| Décisions techniques | `docs/adr/README.md` |
| Avancement par domaine | `docs/progression/` |

Les contrats s'ouvrent aussi dans https://editor.swagger.io (Fichier → Importer).

## 7. Dépannage

| Symptôme | Cause et solution |
|---|---|
| `définir PAYMENT_DB_PASSWORD dans services/.env` | Le fichier `.env` manque, ou la commande n'est pas lancée depuis `services/` |
| `port is already allocated` | Un autre programme occupe le port : l'arrêter, ou arrêter l'ancienne pile (`down`) |
| « Identifiants invalides » | `cafe-demo` s'écrit avec un tiret ; vérifier la variable de `.env` utilisée |
| Plus aucun compte après les tests | Les tests vident les bases : relancer avec `--force-recreate` (voir §5) |
| `401` dans Swagger | Jeton absent, expiré (15 min) ou annulé par un redémarrage de l'auth : se reconnecter |
| Page Swagger blanche | Swagger charge ses fichiers depuis Internet : vérifier la connexion |
| La page se déconnecte au rechargement | Voulu : le jeton est gardé en mémoire uniquement (protection contre le XSS) |

## 8. Règles de contribution

- Branches `<domaine>/<sujet>` (ex. `dev/payment-api`, `infra/loki`), PR vers `develop`. `main` doit toujours démarrer.
- Commits au format `<domaine>: <action>` (ex. `dev: ajoute endpoint POST /payments`).
- Chaque domaine ne modifie que son dossier. `contracts/`, `docs/`, `CLAUDE.md` et ce README sont communs :
  toute modification passe par une PR.
- Détails dans `CLAUDE.md`.
