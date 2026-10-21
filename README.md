# PROJECT RESILIENCE-ALPHA — Plateforme de paiement cyber-résiliente

Démonstrateur EPSI Workshop 2026 (Bac+5) : SI de paiement **fictif** conteneurisé, observé
(Prometheus / Grafana / Loki), protégé par un WAF, et capable de **se rétablir seul** après
un incident (détection → décision → action → vérification par une vraie transaction).

> Ce dépôt couvre le **pilier Infrastructure** (déploiement reproductible, observabilité,
> automatisation Ansible, PRA) ainsi que des services de référence permettant de tester
> la chaîne de bout en bout. Les autres pôles (DEV, IA, Cyber, Gouvernance) s'y branchent
> via les contrats décrits dans [docs/INTEGRATION.md](docs/INTEGRATION.md).

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

## 2. Démarrage rapide

```powershell
git clone <url-du-depot> ; cd <depot>
.\scripts\ops.ps1 deploy        # Windows PowerShell
```
```bash
./scripts/ops.sh deploy         # Linux, WSL ou Git Bash
```

Le playbook `deploy` :
1. vérifie Docker (version, mémoire) et crée `.env` depuis `.env.example` si absent ;
2. **génère les secrets manquants** dans `secrets/` (jamais versionnés, jamais écrasés) ;
3. valide la configuration (`docker compose config`, `promtool`, `amtool`) ;
4. construit les images applicatives et démarre la stack en attendant les healthchecks ;
5. **vérifie fonctionnellement** la plateforme : transaction de paiement réelle via le WAF,
   cibles Prometheus, arrivée des logs dans Loki, sonde synthétique, moteur de remédiation.

Durée : ~5 min au premier lancement (téléchargement des images), < 1 min ensuite.

## 3. Accès

| Interface | URL | Exposition |
|---|---|---|
| Application (via WAF BunkerWeb) | `http://<IP-hote>/` ou `https://<IP-hote>/` (certificat auto-signé : avertissement navigateur normal) | réseau du hotspot |
| Grafana | http://127.0.0.1:3000 — dashboard *Resilience-Alpha* (métriques, logs, alertes, **section SIEM Wazuh**) | local uniquement |
| Vault (secrets) | http://127.0.0.1:18200 — jeton : `docker exec resilience-vault-unsealer-1 cat /vault/keys/root_token` | local uniquement |
| **Console BunkerWeb (GUI du WAF)** | http://127.0.0.1:17000 — utilisateur `admin`, mot de passe : valeur `BW_UI_PASSWORD` du fichier `.env` | local uniquement |
| Prometheus | http://127.0.0.1:9090 | local uniquement |
| Alertmanager | http://127.0.0.1:9093 | local uniquement |
| Moteur de remédiation (événements) | http://127.0.0.1:18090/events | local uniquement |

Identifiants : `type secrets\grafana_admin_password` (Grafana `admin`), `type secrets\demo_user_password`
(utilisateur fictif `alice`). Wazuh n'a pas d'interface propre : ses alertes sont dans Grafana.
La base de données, Loki, Wazuh, les exporters et les proxies Docker ne sont **jamais** publiés.

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
alertes correspondantes, **visibles dans Grafana** (section « SIEM Wazuh » + alertes Alertmanager) avec le pic et les
blocages, et la transaction synthétique interne reste verte : le service tient.

## 6. Organisation du dépôt

```
docker-compose.yml        Définition de toute la plateforme (réseaux, secrets, services)
.env.example              Paramètres non secrets (ports, WAF, remédiation)
scripts/ops.ps1|ops.sh    Point d'entrée des opérations (lance Ansible en conteneur)
ansible/                  Runner, inventaire, playbooks (deploy, verify, backup, restore, recover, chaos…)
infra/                    Configs : postgres, prometheus, alertmanager, loki, alloy, grafana, blackbox, docker-proxy, wazuh, vault (le WAF BunkerWeb se règle dans docker-compose.yml)
services/                 Services de référence : auth, payment-api, txprobe, remediation, frontend, logshipper
attack/                   Banc d'attaque de démo (DDoS, XSS) — à lancer depuis le PC Attaquant
docs/                     Architecture infra, runbook d'exploitation, contrats d'intégration
secrets/ backups/ reports/ exports/  Données locales (non versionnées)
```

## 7. Documentation

- [docs/diagrams/architecture.drawio](docs/diagrams/architecture.drawio) — schéma d'architecture, matrice de flux, inventaire
  (exports PNG `architecture-p1..3.png` ; régénérer avec `python docs/diagrams/gen_architecture.py`)
- [docs/INFRA.md](docs/INFRA.md) — architecture, rôle de Compose / Ansible / observabilité, réseau, sécurité
- [docs/RUNBOOK.md](docs/RUNBOOK.md) — procédures d'exploitation et de reprise (source du RAG opérateur)
- [docs/INTEGRATION.md](docs/INTEGRATION.md) — contrats pour les pôles DEV, IA et Cyber

## 8. Dépannage rapide

| Symptôme | Cause probable | Action |
|---|---|---|
| `Docker n'est pas joignable` | Docker Desktop arrêté | le lancer, attendre « Engine running » |
| port 80 déjà utilisé | IIS / autre serveur web | `PUBLIC_HTTP_PORT=8080` dans `.env`, puis `deploy` |
| `verify` : logs Loki KO juste après le déploiement | Alloy démarre | relancer `verify` 30 s plus tard |
| mots de passe refusés après rotation des secrets | la base garde les anciens | `recover -e wipe_data=true` |
| PC Attaquant ne joint pas l'hôte | pare-feu Windows | autoriser le port 80 entrant sur le profil du hotspot |

Toutes les données sont **fictives**. Aucune donnée bancaire réelle ne doit être utilisée.
