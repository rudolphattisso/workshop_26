# PROJECT RESILIENCE-ALPHA

Démonstrateur de **cyber-résilience** (Workshop EPSI Bac+5, octobre 2026). Une plateforme de paiement
**fictive** subit une attaque. Le système détecte l'anomalie, se répare **sans intervention humaine**, puis
prouve la reprise par une **nouvelle transaction réussie**, le tout observé (Prometheus / Grafana / Loki)
et protégé par un WAF (BunkerWeb) + SIEM (Wazuh).

> Aucune donnée bancaire réelle · aucune action offensive hors de notre SI · aucun secret dans le dépôt.

## Équipe — groupe 2

| Membre | Domaine |
|---|---|
| ATTISSO Rudolph | Développement (EISI dev) |
| BOZZANI Arman | Infrastructure (EISI infra) |
| TRAN HUU Tri Quentin | IA / Data |
| GARCIA Robin | Cybersécurité |
| BREMARD Thomas | Cybersécurité |

## Organisation du dépôt

```
docker-compose.yml        Définition de toute la plateforme (réseaux, secrets, services)
.env.example              Paramètres non secrets (ports, WAF, remédiation)
scripts/ops.ps1|ops.sh    Point d'entrée des opérations (lance Ansible en conteneur)
ansible/                  Runner, inventaire, playbooks (deploy, verify, backup, restore, recover, chaos…)
infra/                    Configs : postgres, prometheus, alertmanager, loki, alloy, grafana, blackbox, docker-proxy, wazuh, vault
services/                 Dev : microservices Python/FastAPI, front et dashboard React + Tailwind
contracts/                Contrats entre domaines (OpenAPI, format d'alerte, conventions de service)
attack/                   Banc d'attaque de démo (DDoS, XSS) — à lancer depuis le PC Attaquant
docs/
├── adr/                  Décisions techniques (ADR-<DOMAINE>-NNNN), index dans docs/adr/README.md
└── progression/          Journal de chaque domaine (matière du dossier PDF)
CLAUDE.md                 Règles communes de l'équipe
secrets/ backups/ reports/ exports/   Données locales (non versionnées)
```

---

## 1. Prérequis (PC Hôte)

| Élément | Minimum | Remarque |
|---|---|---|
| OS | Windows 10/11 (ou Linux) | droits admin, virtualisation activée |
| Docker Desktop | 4.x avec backend **WSL2**, Compose ≥ 2.20 | **seule** dépendance à installer |
| Mémoire allouée à Docker | 4 Go (6–8 Go conseillés) | la stack consomme ~2,5 Go au repos |
| Disque | 10 Go libres | images + volumes |

**Rien d'autre à installer** : Ansible tourne dans un conteneur (`ansible/Dockerfile`),
construit automatiquement au premier lancement.

## 2. Démarrage rapide (plateforme complète)

```powershell
git clone <url-du-depot> ; cd <depot>
git checkout develop                  # branche d'intégration de l'équipe
.\scripts\ops.ps1 deploy              # Windows PowerShell
```
```bash
./scripts/ops.sh deploy               # Linux, WSL ou Git Bash
```

Le playbook `deploy` :
1. vérifie Docker (version, mémoire) et crée `.env` depuis `.env.example` si absent ;
2. **génère les secrets manquants** dans `secrets/` (jamais versionnés, jamais écrasés) ;
3. valide la configuration (`docker compose config`, `promtool`, `amtool`) ;
4. construit les images applicatives et démarre la stack en attendant les healthchecks ;
5. **vérifie fonctionnellement** la plateforme : transaction de paiement réelle via le WAF,
   cibles Prometheus, arrivée des logs dans Loki, sonde synthétique, moteur de remédiation.

Durée : ~5 min au premier lancement (téléchargement des images), < 1 min ensuite.

### Lancer uniquement l'application (sans la plateforme Infra)

Pour développer sur les services sans monter tout BunkerWeb/Vault/Wazuh, `services/compose.dev.yml`
lance l'application seule avec une passerelle nginx qui **imite** le WAF — voir `services/README.md`
pour le détail (ports, comptes de démo, tests automatisés).

## 3. Accès

| Interface | URL | Exposition |
|---|---|---|
| Application (via WAF BunkerWeb) | `http://<IP-hote>/` ou `https://<IP-hote>/` (certificat auto-signé : avertissement navigateur normal) | réseau du hotspot |
| Dashboard de supervision | http://127.0.0.1:18096 (ou port défini par `DASHBOARD_PORT`) | local uniquement |
| Grafana | http://127.0.0.1:3000 — dashboard *Resilience-Alpha* (métriques, logs, alertes, section SIEM Wazuh) | local uniquement |
| Vault (secrets) | http://127.0.0.1:18200 — jeton : `docker exec resilience-vault-unsealer-1 cat /vault/keys/root_token` | local uniquement |
| Console BunkerWeb (GUI du WAF) | http://127.0.0.1:17000 — utilisateur `admin`, mot de passe : valeur `BW_UI_PASSWORD` du fichier `.env` | local uniquement |
| Prometheus | http://127.0.0.1:9090 | local uniquement |
| Alertmanager | http://127.0.0.1:9093 | local uniquement |
| Moteur de remédiation (événements) | http://127.0.0.1:18090/events | local uniquement |

Identifiants : `type secrets\grafana_admin_password` (Grafana `admin`), `type secrets\demo_user_password`
(utilisateurs fictifs `alice`/`bob`/`cafe-demo`). Wazuh n'a pas d'interface propre : ses alertes sont dans
Grafana. La base de données, Loki, Wazuh, les exporters et les proxies Docker ne sont **jamais** publiés.

## 4. Opérations courantes

Toutes les opérations passent par **un seul point d'entrée** : `scripts/ops.ps1 <action>`
(ou `scripts/ops.sh`). Chaque action est un playbook Ansible de `ansible/playbooks/`.

| Action | Rôle | Exemple |
|---|---|---|
| `deploy` | installation / mise à jour idempotente + vérification | `.\scripts\ops.ps1 deploy` |
| `verify` | contrôle de santé fonctionnel (avant la démo !) | `.\scripts\ops.ps1 verify` |
| `backup` | sauvegarde base horodatée + SHA-256 + rotation | `.\scripts\ops.ps1 backup` |
| `restore` | restauration (dernière sauvegarde par défaut) | `.\scripts\ops.ps1 restore -e restore_file=payments-…dump` |
| `recover` | **PRA** : reconstruction depuis les sources (compromission) | `.\scripts\ops.ps1 recover -e wipe_data=true` |
| `chaos` | recette : injecte une panne et mesure MTTD/MTTR | `.\scripts\ops.ps1 chaos -e target=auth -e fault=kill` |
| `reload` | rechargement des configs d'observabilité | `.\scripts\ops.ps1 reload` |
| `teardown` | arrêt (`-e purge=true` supprime aussi les données) | `.\scripts\ops.ps1 teardown` |

Relance après redémarrage du PC : démarrer Docker Desktop puis lancer `.\scripts\ops.ps1 deploy`
(idempotent, ~1 min). Ne pas compter sur `restart: unless-stopped` : quand Docker Desktop est quitté
proprement, les conteneurs sont arrêtés et ne repartent PAS tout seuls (constaté). La politique ne
joue que pour un plantage d'un conteneur.

## 5. Démos

**Reprise automatique (panne de service)** :
```powershell
.\scripts\ops.ps1 chaos                       # arrête payment-api et chronomètre la reprise
```
Dans Grafana : la transaction synthétique passe au rouge, l'alerte `PaymentApiUnavailable`
se déclenche, le moteur redémarre le service, puis la transaction repasse au vert.
Le rapport JSON (temps de détection / de reprise) est écrit dans `reports/`.

**Attaque DDoS + XSS (depuis le PC Attaquant)** — voir [attack/README.md](attack/README.md) :
```bash
DEMO_PASSWORD=<mdp alice> ./attack/run_demo.sh http://192.168.137.1
```
Le WAF BunkerWeb bloque les XSS/SQLi (403) et bannit l'IP qui inonde (DDoS) ; **Wazuh** lève les
alertes correspondantes, **visibles dans Grafana** (section « SIEM Wazuh » + alertes Alertmanager) avec
le pic et les blocages, et la transaction synthétique interne reste verte : le service tient.

## 6. Documentation

| Sujet | Où |
|---|---|
| Architecture infra, rôle de Compose / Ansible / observabilité, réseau, sécurité | [docs/INFRA.md](docs/INFRA.md) |
| Schéma d'architecture, matrice de flux, inventaire | [docs/diagrams/architecture.drawio](docs/diagrams/architecture.drawio) |
| Procédures d'exploitation et de reprise (PRA) | [docs/RUNBOOK.md](docs/RUNBOOK.md) · [docs/PCA-PRA.md](docs/PCA-PRA.md) |
| Contrats pour les pôles DEV, IA et Cyber | [docs/INTEGRATION.md](docs/INTEGRATION.md) |
| API de paiement et d'authentification (OpenAPI) | `contracts/openapi-payment.yaml` |
| API du moteur de remédiation (OpenAPI) | `contracts/openapi-remediation.yaml` |
| Format des alertes (IA, Prometheus, WAF → moteur) | `contracts/alert.schema.json` |
| Conventions de tout service (`/health`, `/ready`, `/metrics`, logs JSON) | `contracts/service-conventions.md` |
| Détail des services Dev (développement sans Docker, routes, jetons) | `services/README.md` |
| Décisions techniques | `docs/adr/README.md` |
| Avancement par domaine | `docs/progression/` |

Les contrats s'ouvrent aussi dans https://editor.swagger.io (Fichier → Importer).

## 7. Dépannage rapide

| Symptôme | Cause probable | Action |
|---|---|---|
| `Docker n'est pas joignable` | Docker Desktop arrêté | le lancer, attendre « Engine running » |
| port 80 déjà utilisé | IIS / autre serveur web | `PUBLIC_HTTP_PORT=8080` dans `.env`, puis `deploy` |
| `verify` : logs Loki KO juste après le déploiement | Alloy démarre | relancer `verify` 30 s plus tard |
| mots de passe refusés après rotation des secrets | la base garde les anciens | `recover -e wipe_data=true` |
| PC Attaquant ne joint pas l'hôte | pare-feu Windows | autoriser le port 80 entrant sur le profil du hotspot |

## 8. Règles de contribution

- Branches `<domaine>/<sujet>` (ex. `dev/payment-api`, `infra/loki`), PR vers `develop`. `main` doit toujours démarrer.
- Commits au format `<domaine>: <action>` (ex. `dev: ajoute endpoint POST /payments`).
- Chaque domaine ne modifie que son dossier. `contracts/`, `docs/`, `CLAUDE.md` et ce README sont communs :
  toute modification passe par une PR.
- Détails dans `CLAUDE.md`.

Toutes les données sont **fictives**. Aucune donnée bancaire réelle ne doit être utilisée.
