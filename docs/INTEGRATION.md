# Contrats d'intégration entre pôles

L'infrastructure fournit des **services de référence** (`services/`) pour que la chaîne
complète fonctionne dès le premier jour. Chaque pôle peut les remplacer par ses propres
composants **en respectant les contrats ci-dessous** — rien d'autre n'est à modifier côté infra.

---

## Pôle DEV

### Remplacer un service (auth, payment-api, frontend, remediation)
1. Placer le code dans `services/<nom>/` avec son `Dockerfile` (Node.js, FastAPI ou Go).
2. Dans `docker-compose.yml`, adapter seulement `build:` du service (garder nom, réseaux, secrets).
3. `.\scripts\ops.ps1 deploy`.

### Contrat de chaque service métier
| Exigence | Détail |
|---|---|
| Port interne | `8000` (frontend : `8080`) |
| `GET /health` | 200 si le processus vit (healthcheck Docker) |
| `GET /ready` | 200 seulement si les dépendances (base) répondent — utilisé par les sondes via le WAF |
| `GET /metrics` | format Prometheus ; au minimum `http_requests_total{service,method,route,status}` et `http_request_duration_seconds` (histogramme) |
| Logs | **JSON, une ligne par événement, sur stdout** ; champs `ts`, `level`, `service`, `msg` (+ libres) |
| Secrets | lus dans `/run/secrets/<nom>` (jamais en variable d'environnement en clair) |
| Utilisateur | non-root ; le système de fichiers est en lecture seule (écrire dans `/tmp` seulement) |

### Routes publiées par le WAF
BunkerWeb transmet l'URI **telle quelle** au back-end (aucune réécriture) : les services doivent donc
exposer leurs routes publiques **sous leur préfixe `/api/...`**.

| Public (via le WAF) | Back-end |
|---|---|
| `/api/auth/*` (ex. `POST /api/auth/login`, `GET /api/auth/ready`) | `auth:8000` |
| `/api/payments*` (ex. `POST /api/payments`, `GET /api/payments/ready`) | `payment-api:8000` |
| `/` (tout le reste) | `frontend:8080` |

Pour ajouter une route : ajouter `REVERSE_PROXY_URL_<n>` / `REVERSE_PROXY_HOST_<n>` au service
`bunkerweb-scheduler` dans `docker-compose.yml`, puis `.\scripts\ops.ps1 deploy`.

### Moteur de remédiation
- **Entrée** : `POST /webhook/alertmanager` (format webhook Alertmanager v4), en-tête
  `Authorization: Bearer <secrets/remediation_token>`.
- Chaque alerte porte `labels.remediation` (`restart` | `none`) et `labels.target` (service Compose).
- **Accès Docker** : uniquement via `http://docker-proxy:2375` (API Docker restreinte :
  lecture des conteneurs, `start`/`stop`/`restart`).
- **Sortie pour le dashboard React** : `GET http://127.0.0.1:18090/events` (JSON, plus récent d'abord) —
  types `alert_received`, `remediation_started`, `remediation_action_done`, `remediation_succeeded`,
  `remediation_failed`, `remediation_refused`, `remediation_skipped`.
- **Vérification métier** : `GET http://txprobe:8000/check` exécute une transaction complète et
  renvoie `{"ok": true, "tx_id": ..., "duration_s": ...}`.

### Données Prometheus / Loki pour le dashboard React
Le dashboard peut interroger (depuis le PC Hôte) `http://127.0.0.1:9090/api/v1/query?query=...` ;
requêtes utiles : `synthetic_transaction_success`, `probe_success`, `ALERTS{alertstate="firing"}`,
`remediation_last_recovery_seconds`. Si le dashboard tourne dans un conteneur, l'ajouter aux réseaux
`mgmt` et `monitoring` et l'exposer sur `127.0.0.1`.

---

## Pôle IA

### Données disponibles pour l'entraînement
- **Métriques** (API Prometheus, pas de 5 s, rétention 7 j) :
  `http://127.0.0.1:9090/api/v1/query_range?query=<promql>&start=<ts>&end=<ts>&step=5s`.
  Features suggérées : débit WAF et blocages (Loki, voir ci-dessous),
  `sum by (status) (rate(http_requests_total{service="payment-api"}[1m]))`,
  latence p95, `rate(container_cpu_usage_seconds_total{service="payment-api"}[1m])`,
  `container_memory_working_set_bytes`, compte de 403/429 du WAF (Loki : `{service="bunkerweb"}`).
- **Logs** (API Loki via Grafana) :
  `http://127.0.0.1:3000/api/datasources/proxy/uid/loki/loki/api/v1/query_range?query={service="bunkerweb"}`
  (authentification Grafana `admin`).
- **Export prêt** : les alertes Wazuh (JSONL + CSV) se regénèrent depuis `/var/ossec/logs/alerts` du conteneur
  `wazuh.manager` ; elles ne contiennent que des détections, pas le trafic normal (voir Loki/Prometheus pour le normal).
- Pour générer des périodes « normales » : la sonde synthétique produit un trafic de fond
  permanent ; ajouter de la charge légitime avec un script de trafic.

### Brancher le détecteur d'anomalies
1. Ajouter le service `ml-detector` dans `docker-compose.yml`, réseau `monitoring`
   (+ `mgmt` s'il doit être consulté).
2. Exposer `GET /metrics` avec la jauge **`aiops_anomaly_score{service="<service compose>"}`** ∈ [0, 1].
3. Déclarer la cible dans `infra/prometheus/targets/extensions.yml` :
   ```yaml
   - targets: ["ml-detector:8000"]
     labels: { service: ml-detector, tier: aiops }
   ```
4. La règle `AnomalyDetected` (score > 0,8 pendant 15 s) déclenche automatiquement la
   remédiation du service désigné par le label `service`. Seuil modifiable dans
   `infra/prometheus/rules/alerts.yml`.

### Assistant RAG (Ollama + LangChain)
- Corpus conseillé : `docs/*.md` (ce fichier, `INFRA.md`, `RUNBOOK.md`) + dossier de gouvernance.
- L'assistant n'a **aucun accès** au proxy Docker ni au webhook de remédiation (séparation
  imposée par le sujet). Accès en lecture à Prometheus/Loki possible pour contextualiser.
- Si Ollama tourne sur un 3e PC, le joindre via son IP sur le hotspot ; ne pas l'exposer ailleurs.

---

## Pôle Cyber

| Sujet | Où / comment |
|---|---|
| WAF (BunkerWeb) | réglages dans `docker-compose.yml` (service `bunkerweb-scheduler`) et `.env` (`WAF_*`) ; config poussée par le scheduler. Settings BunkerWeb complets : https://docs.bunkerweb.io |
| Règles / exclusions CRS | `MODSECURITY_CRS_VERSION`, exclusions via un `bw-plugin`/config custom montée dans le scheduler |
| Mode détection seule (démo avant/après) | `WAF_RULE_ENGINE=DetectionOnly` dans `.env` puis `ops reload` |
| Anti-DoS | `USE_LIMIT_REQ` (débit) + `USE_BAD_BEHAVIOR` (auto-ban) : `WAF_API_RATE`, `WAF_BADBEHAVIOR_THRESHOLD`, `WAF_BAN_TIME` |
| SOC léger (temps réel) | règles LogQL `infra/loki/rules/fake/security.yml` (→ Alertmanager) ; section « Sécurité » du dashboard Grafana |
| SIEM (Wazuh) | règles de détection `infra/wazuh/config/wazuh_cluster/local_rules.xml` (plage 100000+) ; conf agent `infra/wazuh/config/wazuh_agent/ossec.conf` ; alertes visibles dans Grafana (Loki, `service="wazuh"`) ; règles d'alerte `infra/loki/rules/fake/security.yml`. `ops deploy` recharge les règles. |
| Nouveaux signaux pour Wazuh | ajouter un `<localfile>` dans l'ossec.conf de l'agent (le forwarder écrit déjà tous les journaux dans `/var/log/agent/<service>.log`) |
| Secrets (SOPS/Vault) | alimenter `secrets/<nom>` par `sops -d` ou un agent Vault avant `deploy` ; aucun autre changement |
| Surface exposée | seul le WAF (port 80) est joignable depuis le PC Attaquant |
| Logs d'investigation | accès JSON + audit ModSecurity de BunkerWeb (Loki) ; alertes corrélées et historisées (Wazuh) |
| Banc d'attaque de démo | `attack/attack.py` (xss / ddos / probe) + `attack/run_demo.sh` |

Cibles légitimes du PC Attaquant : **uniquement** `http://192.168.137.1/` (IP du PC Hôte du groupe).
