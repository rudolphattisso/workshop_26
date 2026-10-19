# Infrastructure — architecture, déploiement, observabilité, reprise

## 1. Vue d'ensemble

```
                       Réseau hotspot Windows (192.168.137.0/24)
   PC Attaquant ───────────────┐
   Jury / navigateur ──────────┤  :80  (seul port publié sur le LAN)
                               ▼
┌──────────────────────────── PC Hôte — Docker Desktop (WSL2) ────────────────────────────┐
│  [edge]        WAF  nginx + ModSecurity + OWASP CRS  (rate-limit, logs JSON)            │
│                 │                                                                       │
│  [app]   frontend   auth   payment-api   txprobe (transaction synthétique)              │
│                       │        │                                                        │
│  [data]               └─ PostgreSQL ─┘   (rôles à moindre privilège, aucun port publié) │
│                                                                                         │
│  [monitoring]  Prometheus ◄─ exporters (blackbox, waf, postgres, cAdvisor) + /metrics   │
│                Loki ◄─ Alloy ◄─ proxy Docker lecture seule  [dockerapi-ro]              │
│                Grafana  (Prometheus + Loki + Alertmanager)                              │
│                Prometheus/Loki rules ─► Alertmanager ─► Moteur de remédiation           │
│                                                              │                          │
│  [control]                         proxy Docker (restart/start/stop uniquement)        │
│  [mgmt]  Grafana :3000, Prometheus :9090, Alertmanager :9093, remédiation :18090        │
│          publiés sur 127.0.0.1 seulement                                                │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

## 2. Place de chaque outil

| Outil | Question à laquelle il répond | Ce qu'il fait ici | Ce qu'il ne fait PAS |
|---|---|---|---|
| **Docker** | *Comment isoler et livrer chaque composant ?* | Images immuables, une par service ; limites mémoire/CPU ; utilisateurs non-root | — |
| **Docker Compose** | *Quel est l'état désiré de la plateforme ?* | Décrit de façon déclarative les 21 conteneurs, 9 réseaux, volumes, secrets, healthchecks, politiques de redémarrage | N'opère rien dans le temps (pas de sauvegarde, pas de vérification métier, pas de PRA) |
| **Ansible** | *Comment opère-t-on la plateforme de façon reproductible ?* | Procédures codées et idempotentes : préflight, génération des secrets, validation des configs, déploiement, vérification fonctionnelle, sauvegarde, restauration, **PRA**, recette chaos | N'est pas dans la boucle de remédiation temps réel (trop lent, trop privilégié) |
| **BunkerWeb** (WAF) | *Comment filtrer le trafic entrant ?* | Point d'entrée unique : nginx + ModSecurity + OWASP CRS v4 (bloque XSS/SQLi), limitation de débit et **bannissement automatique** des IP « bad behavior » (anti-DoS), reverse proxy vers les microservices | Export Prometheus = option PRO → supervision via blackbox + Loki |
| **HashiCorp Vault** | *Où vivent les secrets ?* | **Source de vérité** des 9 secrets de la plateforme (KV v2 `resilience/`), audit activé, politiques moindre privilège ; Ansible y range les secrets et reconstruit `./secrets/` depuis Vault (PRA) ; descellement automatique après un redémarrage | Les conteneurs lisent toujours des Docker secrets (copie d'exécution) : Vault ne sert pas de runtime en ligne aux services |
| **Prometheus** | *Dans quel état sont les services ?* | Scrape toutes les 5 s : métriques applicatives, sondes boîte noire via le WAF, conteneurs, base ; évalue les règles d'alerte | — |
| **Loki + Alloy** | *Que s'est-il passé ?* | Centralise les journaux stdout de **tous** les conteneurs (découverte automatique), règles LogQL de sécurité (fonction SOC légère) | Pas d'Elastic : Loki n'indexe que les labels → ~10× moins de RAM |
| **Wazuh** (SIEM/HIDS) | *Quelles menaces de sécurité ?* | Moteur de détection : un agent surveille toute la plateforme (FIM, rootcheck, SCA, analyse des journaux) ; le manager applique des règles XSS/SQLi/DDoS/force brute et **envoie ses alertes en syslog JSON vers Loki** → visualisées et alertées dans **Grafana** | Pas de dashboard ni d'indexer Wazuh (OpenSearch = Elastic, écarté par le sujet) : un seul outil de visualisation |
| **Alertmanager** | *Qui doit réagir ?* | Groupe, dédoublonne, inhibe (si le WAF tombe, on ne redémarre pas l'API) puis appelle le moteur de remédiation (webhook authentifié) | — |
| **Grafana** | *Comment le jury voit-il l'incident ?* | Dashboard provisionné « as code » : état avant / pendant / après, alertes, actions, logs, section Sécurité (SOC) | Aucune configuration manuelle : tout est dans `infra/grafana/` |

> **Un seul pupitre : Grafana.** Métriques (Prometheus), journaux (Loki), alertes (Alertmanager) et
> détections du SIEM Wazuh (ses alertes sont poussées dans Loki) sont consultés au même endroit,
> avec le même moteur d'alerte. Ni Elastic Stack ni OpenSearch ni dashboard Wazuh : économie
> d'environ 3 Go de RAM et conformité à la consigne du sujet.

### Les deux WAF ? Non : un WAF en deux conteneurs

`bunkerweb` est le **plan de données** (reçoit et filtre le trafic) ; `bunkerweb-scheduler`
est le **plan de contrôle** (porte tous les réglages, génère la configuration nginx, met à
jour l'OWASP CRS, la pousse à l'instance via une API interne sur le réseau `bw-universe`).
Basculer `WAF_RULE_ENGINE=On|DetectionOnly` (dans `.env`, puis `ops reload`) permet la démo
« avant / après » : en `DetectionOnly` les attaques passent mais sont journalisées, en `On`
elles sont bloquées (403).

### Wazuh : agent « hôte » plutôt qu'un agent par conteneur

Un agent Wazuh dans chaque conteneur imposerait root + système de fichiers inscriptible +
superviseur de processus, ce qui **détruirait le durcissement** des conteneurs applicatifs.
On déploie donc **un seul agent** qui surveille toute la plateforme : FIM sur les secrets et
les configurations, rootcheck/SCA, et analyse des journaux de tous les conteneurs. Comme les
journaux ne sont pas des fichiers lisibles sur Docker Desktop, un petit **log-forwarder**
(`logshipper`) les relaie via le proxy Docker **en lecture seule** vers des fichiers que
l'agent analyse. Les conteneurs applicatifs restent intacts (non-root, FS en lecture seule).

### Deux boucles de reprise complémentaires

| | **Boucle rapide (automatique)** | **Boucle lente (PRA, Ansible)** |
|---|---|---|
| Déclencheur | Alerte Prometheus / Loki / ML | Décision humaine ou remédiation en échec |
| Exécutant | Moteur de remédiation via proxy Docker restreint | `ops recover` (Ansible) |
| Action | Redémarrage ciblé d'un service | Reconstruction des images depuis les sources, conteneurs recréés, données restaurées depuis une sauvegarde saine vérifiée (SHA-256) |
| Traite | Perte de **disponibilité** | **Compromission** (conteneur altéré, données corrompues) |
| Preuve de reprise | Transaction synthétique réussie | `verify` : transaction E2E + chaîne d'observabilité |
| Durée typique | 15–40 s | 1–3 min |

> Un redémarrage ne corrige pas une compromission : un conteneur altéré redémarré reste
> altéré si l'attaquant a modifié un volume. C'est pourquoi la reconstruction PRA repart
> d'images reconstruites et d'une sauvegarde antérieure à l'incident.

## 3. Chaîne détection → remédiation → vérification

1. **Collecte** : Prometheus (métriques, 5 s) et Alloy → Loki (logs, quasi temps réel).
2. **Détection** : règles `infra/prometheus/rules/alerts.yml` (seuils + `aiops_anomaly_score`
   produit par le modèle ML) et `infra/loki/rules/fake/security.yml` (bursts WAF, brute force).
3. **Décision** : chaque règle porte les labels `remediation` (action) et `target` (service) ;
   Alertmanager route vers le moteur, inhibe les effets de bord (cause racine uniquement).
4. **Action** : le moteur vérifie la **liste blanche** des cibles, applique un **cooldown**,
   puis demande le redémarrage au proxy Docker restreint.
5. **Vérification** : la reprise n'est déclarée réussie que lorsqu'une **transaction
   synthétique complète** (login → paiement → relecture en base, via le WAF) aboutit.
   Échec → événement `remediation_failed` → alerte Loki `RemediationFailed` → PRA.

## 4. Segmentation réseau

| Réseau | Interne | Membres | Raison |
|---|---|---|---|
| `edge` | non | bunkerweb | seul point d'entrée exposé |
| `app` | oui | bunkerweb, frontend, auth, payment-api, txprobe | trafic applicatif |
| `data` | oui | postgres, auth, payment-api, postgres-exporter | la base n'est joignable que par ses clients |
| `monitoring` | oui | observabilité + endpoints `/metrics` | collecte |
| `control` | oui | remediation, docker-proxy | plan de contrôle isolé |
| `dockerapi-ro` | oui | alloy, logshipper, docker-proxy-ro | lecture des logs/API Docker |
| `mgmt` | non | grafana, prometheus, alertmanager, remediation | publication sur 127.0.0.1 |
| `bw-universe` | oui | bunkerweb, bunkerweb-scheduler | plan de contrôle du WAF (API interne) |
| `vault` | oui | vault, vault-unsealer | Vault et son sidecar de descellement (+ vault sur `mgmt` pour l'UI loopback) |
| `siem` | oui | wazuh.manager, wazuh-agent, alloy | SIEM Wazuh (agent → manager ; alertes du manager → Alloy → Loki) |

Un réseau `internal` n'a **aucune route vers l'extérieur** : un service applicatif compromis
ne peut ni télécharger d'outil ni exfiltrer directement des données vers Internet.

## 5. Durcissement appliqué

- **Exposition minimale** : un seul port sur le LAN (WAF :80) ; admin sur `127.0.0.1` ; base jamais publiée.
- **Conteneurs** : `cap_drop: ALL`, `no-new-privileges`, utilisateurs non-root (uid 10001, postgres uid 70),
  système de fichiers **en lecture seule** pour les services applicatifs et la base, limites mémoire/CPU
  (protection contre l'épuisement de ressources pendant un DoS).
- **Secrets** : **HashiCorp Vault** est la source de vérité (KV v2, audit stdout, jeton Ansible à politique restreinte) ;
  ils sont déclinés en Docker secrets (`/run/secrets`), jamais dans les images, variables d'environnement ni le dépôt.
- **Base** : un rôle par service (`payment_svc` : SELECT/INSERT sur `transactions` ; `auth_svc` : SELECT sur
  `users` ; `exporter` : `pg_monitor`). Mots de passe applicatifs hachés en bcrypt.
- **Moteur de remédiation** : jamais d'accès direct au socket Docker. Le proxy n'autorise que
  `GET /containers/*` et `start/stop/restart` ; `create`, `exec`, images, volumes, réseaux → 403.
  Webhook authentifié par jeton ; liste blanche de cibles ; cooldown anti-boucle.
- **WAF BunkerWeb** : OWASP CRS v4, limitation de débit par IP (toutes URL 20 r/s, login 5 r/s),
  **bannissement automatique** des IP « bad behavior » (seuil 20 réponses 4xx/429 en 60 s → ban 5 min),
  taille de requête bornée (256 Ko), en-têtes de sécurité. API interne du WAF restreinte au réseau
  `bw-universe` + jeton.
- **SIEM Wazuh** : agent unique (pas d'agent dans les conteneurs applicatifs → durcissement préservé) ;
  accès Docker du log-forwarder **en lecture seule** via le proxy ; aucun port Wazuh publié.
- **Exceptions assumées** : cAdvisor est privilégié (lecture des cgroups) ; `logshipper` et `wazuh-agent`
  tournent en root (écriture du volume de journaux / collecte système) mais restent durcis (`cap_drop ALL`,
  `no-new-privileges`, accès Docker en lecture seule) et sur des réseaux internes, sans port publié.

## 6. Observabilité : ce qui est mesuré

| Signal | Source | Usage |
|---|---|---|
| `synthetic_transaction_success` | txprobe (toutes les 5 s) | **preuve métier** avant/pendant/après |
| `probe_success{service}` | blackbox via WAF | disponibilité vue du client |
| `http_requests_total`, `http_request_duration_seconds` | services | trafic, erreurs 5xx, latence p95 |
| `payments_total{status}` | payment-api | activité métier |
| Débit WAF, blocages ModSecurity, bannissements | logs BunkerWeb → Loki | volumétrie / DoS (l'export Prometheus du WAF est une option PRO) |
| `container_cpu_*`, `container_memory_*` | cAdvisor | ressources ; features pour le ML |
| `pg_up`, stats PostgreSQL | postgres-exporter | santé base |
| `remediation_actions_total`, `remediation_last_recovery_seconds` | remédiation | MTTR |
| Logs JSON (accès WAF, détections ModSecurity, login_failed, remédiation) | Loki | SOC léger temps réel, RAG |
| Alertes XSS/SQLi/DDoS/force brute, FIM, rootcheck | Wazuh (manager → syslog → Alloy → Loki) | détections visibles et alertées dans Grafana |

Rétention : 7 jours (métriques et logs) — couvre la semaine du workshop.

## 7. Mesures réalisées (PC de test : Docker Desktop 29.5, WSL2, 8 Go alloués)

| Essai | Résultat |
|---|---|
| RAM de toute la stack (21 conteneurs, Wazuh manager + agent inclus) | **~1,7 Go** (mesuré ; 2,3 Go avec l'indexer + dashboard Wazuh, retirés) |
| `chaos` : arrêt de `payment-api` / `kill auth` | détection ~21–24 s, reprise vérifiée par transaction ~32–33 s |
| `recover -e wipe_data=true` : volume détruit, reconstruction + restauration | **48 s**, aucune perte de transaction |
| Proxy Docker de la remédiation | `restart` → 204 ; `create`, `exec`, `kill`, `images`, `volumes` → **403** |
| Attaque XSS / SQLi via le WAF | **403** (OWASP CRS) ; Wazuh lève 100101 (XSS) / 100102 (SQLi) → alertes `WazuhXssDetected` / `WazuhSqliDetected` dans Alertmanager/Grafana |
| DDoS applicatif (~450 req) | WAF : **429** puis **403** (IP bannie) ; Wazuh règle 100110 → alerte `WazuhDdosDetected` dans Grafana |
| Pendant l'attaque | `synthetic_transaction_success = 1` : le service métier reste disponible |

L'empreinte laisse de la marge sur un PC 16 Go ; le modèle de langage (Ollama) est
déporté sur le 3e poste. Les rapports détaillés des essais `chaos` sont dans `reports/`.

## 8. Points d'attention connus (et choix assumés)

- **Secrets lisibles (0444)** : Compose monte les secrets « fichier » sans remapping d'UID ; ils
  doivent être lisibles par les utilisateurs non-root des conteneurs. La protection côté hôte
  repose sur le profil utilisateur Windows. En production : Docker Swarm/Kubernetes secrets ou Vault.
- **Proxy Docker** : l'image `tecnativa/docker-socket-proxy` exige `POST=1` pour autoriser un
  restart, ce qui ouvrirait aussi `containers/create`. On remplace donc sa configuration HAProxy
  (`infra/docker-proxy/haproxy.cfg.template`) pour n'accepter que `start`/`stop`/`restart`.
- **Faux positifs WAF** : la règle CRS 932260 bloque des mots ressemblant à des commandes Unix
  (ex. un marchand nommé « ANSIBLE-… »). À traiter par exclusions ciblées si les données métier
  réelles le nécessitent, pas en baissant la paranoïa globale.
- **cAdvisor ≥ 0.55** est requis avec Docker Engine 29 (API minimale relevée) — sinon aucune
  métrique par conteneur.
- **Bannissement d'IP et NAT Docker** : sur Docker Desktop, le trafic externe est traduit vers une
  IP unique. Le bannissement par IP du WAF touche donc aussi les clients légitimes partageant cette
  IP. La **preuve de continuité** pendant un DDoS repose sur la transaction synthétique interne
  (source distincte) et sur la reprise, pas sur l'accès de l'attaquant. En production, `USE_REAL_IP` avec
  un équilibreur transmettant l'IP cliente lèverait cette limite.
- **Pas d'interface Wazuh** : volontaire. Le manager n'expose aucun port ; son API (identifiants par défaut de l'image)
  reste sur le réseau interne `siem`. Sans indexer, l'historique long des alertes n'est conservé que dans Loki (7 jours).
- **Agent Wazuh unique** : excellent pour FIM/rootcheck/SCA et l'analyse des journaux, mais ne
  fournit pas la télémétrie *intra-conteneur* qu'un agent par conteneur donnerait — choix assumé
  pour préserver le durcissement (voir §2).
- **cAdvisor ≥ 0.55** est requis avec Docker Engine 29 (API minimale relevée) — sinon aucune
  métrique par conteneur.
- **Mono-hôte** : pas de haute disponibilité réelle (un seul PC). La reprise couvre la panne
  d'un service, pas celle de la machine (→ PROC-01 + sauvegarde copiée hors du PC).

## 9. Gestion des secrets : HashiCorp Vault

**Rôle.** Vault est la source de vérité ; `./secrets/` n'est qu'une copie d'exécution pour Docker.
`ops deploy` réconcilie chaque secret (voir `ansible/tasks/secrets.yml`) : généré s'il n'existe nulle
part ; versé dans Vault s'il n'existe qu'en fichier (migration, valeur conservée) ; **reconstruit depuis
Vault si le fichier est perdu** (PRA) ; Vault l'emporte en cas d'écart.

**Reprise sans humain.** Le sidecar `vault-unsealer` initialise Vault au premier démarrage, le descelle
à chaque redémarrage et (re)configure moteur KV, audit et politiques (`infra/vault/bootstrap.sh`).
Mesuré : Vault tué (SIGKILL) → redescellé automatiquement en quelques secondes. Si Vault ne répond
plus, l'alerte `VaultDown` déclenche son redémarrage par le moteur de remédiation ; `VaultSealed` et
`VaultAccessDenied` (audit) alertent dans Grafana.

**Moindre privilège.** Le jeton d'exploitation `ansible-ops` ne lit/écrit que `resilience/*` : il ne peut
ni lister les politiques ni les moteurs de secrets. Vault n'est joignable que sur le réseau interne `vault`
et en loopback (`http://127.0.0.1:18200`).

**Compromis de lab, à dire au jury.** Les clés de descellement et le jeton racine sont stockés dans un
volume à côté de Vault (sinon pas de reprise autonome). En production : auto-unseal via KMS/HSM ou clés
Shamir réparties, TLS, stockage Raft en haute disponibilité, jeton racine révoqué après initialisation.
Le TLS est désactivé car Vault n'est joignable que sur des réseaux internes et en loopback.
