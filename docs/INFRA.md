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
│  [mgmt]  Grafana :3000, Prometheus :9090, Alertmanager :9093, remédiation :8090         │
│          publiés sur 127.0.0.1 seulement                                                │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

## 2. Place de chaque outil

| Outil | Question à laquelle il répond | Ce qu'il fait ici | Ce qu'il ne fait PAS |
|---|---|---|---|
| **Docker** | *Comment isoler et livrer chaque composant ?* | Images immuables, une par service ; limites mémoire/CPU ; utilisateurs non-root | — |
| **Docker Compose** | *Quel est l'état désiré de la plateforme ?* | Décrit de façon déclarative les 18 conteneurs, 7 réseaux, volumes, secrets, healthchecks, politiques de redémarrage | N'opère rien dans le temps (pas de sauvegarde, pas de vérification métier, pas de PRA) |
| **Ansible** | *Comment opère-t-on la plateforme de façon reproductible ?* | Procédures codées et idempotentes : préflight, génération des secrets, validation des configs, déploiement, vérification fonctionnelle, sauvegarde, restauration, **PRA**, recette chaos | N'est pas dans la boucle de remédiation temps réel (trop lent, trop privilégié) |
| **Prometheus** | *Dans quel état sont les services ?* | Scrape toutes les 5 s : métriques applicatives, sondes boîte noire via le WAF, conteneurs, base ; évalue les règles d'alerte | — |
| **Loki + Alloy** | *Que s'est-il passé ?* | Centralise les journaux stdout de **tous** les conteneurs (découverte automatique), règles LogQL de sécurité (fonction SOC) | Pas d'Elastic : Loki n'indexe que les labels → ~10× moins de RAM |
| **Alertmanager** | *Qui doit réagir ?* | Groupe, dédoublonne, inhibe (si le WAF tombe, on ne redémarre pas l'API) puis appelle le moteur de remédiation (webhook authentifié) | — |
| **Grafana** | *Comment le jury voit-il l'incident ?* | Dashboard provisionné « as code » : état avant / pendant / après, alertes, actions, logs | Aucune configuration manuelle : tout est dans `infra/grafana/` |

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
| `edge` | non | waf | seul point d'entrée exposé |
| `app` | oui | waf, frontend, auth, payment-api, txprobe | trafic applicatif |
| `data` | oui | postgres, auth, payment-api, postgres-exporter | la base n'est joignable que par ses clients |
| `monitoring` | oui | observabilité + endpoints `/metrics` | collecte |
| `control` | oui | remediation, docker-proxy | plan de contrôle isolé |
| `dockerapi-ro` | oui | alloy, docker-proxy-ro | lecture des logs Docker |
| `mgmt` | non | grafana, prometheus, alertmanager, remediation | publication sur 127.0.0.1 |

Un réseau `internal` n'a **aucune route vers l'extérieur** : un service applicatif compromis
ne peut ni télécharger d'outil ni exfiltrer directement des données vers Internet.

## 5. Durcissement appliqué

- **Exposition minimale** : un seul port sur le LAN (WAF :80) ; admin sur `127.0.0.1` ; base jamais publiée.
- **Conteneurs** : `cap_drop: ALL`, `no-new-privileges`, utilisateurs non-root (uid 10001, postgres uid 70),
  système de fichiers **en lecture seule** pour les services applicatifs et la base, limites mémoire/CPU
  (protection contre l'épuisement de ressources pendant un DoS).
- **Secrets** : Docker secrets (fichiers montés dans `/run/secrets`), générés par Ansible, jamais dans
  les images, les variables d'environnement ni le dépôt.
- **Base** : un rôle par service (`payment_svc` : SELECT/INSERT sur `transactions` ; `auth_svc` : SELECT sur
  `users` ; `exporter` : `pg_monitor`). Mots de passe applicatifs hachés en bcrypt.
- **Moteur de remédiation** : jamais d'accès direct au socket Docker. Le proxy n'autorise que
  `GET /containers/*` et `start/stop/restart` ; `create`, `exec`, images, volumes, réseaux → 403.
  Webhook authentifié par jeton ; liste blanche de cibles ; cooldown anti-boucle.
- **WAF** : OWASP CRS (paranoïa 1, seuil d'anomalie 5), limitation de débit par IP (API 20 r/s,
  login 5 r/s), taille de requête bornée, en-têtes de sécurité, `/api/` non routée → 404.
- **Exception assumée** : cAdvisor est privilégié (lecture des cgroups de l'hôte) ; il n'est
  joignable que sur le réseau interne `monitoring`, sans port publié.

## 6. Observabilité : ce qui est mesuré

| Signal | Source | Usage |
|---|---|---|
| `synthetic_transaction_success` | txprobe (toutes les 5 s) | **preuve métier** avant/pendant/après |
| `probe_success{service}` | blackbox via WAF | disponibilité vue du client |
| `http_requests_total`, `http_request_duration_seconds` | services | trafic, erreurs 5xx, latence p95 |
| `payments_total{status}` | payment-api | activité métier |
| `nginx_http_requests_total`, connexions | WAF | volumétrie / DoS |
| `container_cpu_*`, `container_memory_*` | cAdvisor | ressources ; features pour le ML |
| `pg_up`, stats PostgreSQL | postgres-exporter | santé base |
| `remediation_actions_total`, `remediation_last_recovery_seconds` | remédiation | MTTR |
| Logs JSON (accès WAF, détections ModSecurity, login_failed, événements de remédiation) | Loki | investigation, SOC, RAG |

Rétention : 7 jours (métriques et logs) — couvre la semaine du workshop.

## 7. Mesures réalisées (PC de test : Docker Desktop 29.5, WSL2, 8 Go alloués)

| Essai | Résultat |
|---|---|
| RAM de toute la stack au repos (`docker stats`) | **~0,95 Go** pour 18 conteneurs |
| `chaos` : arrêt de `payment-api` | détection **23,8 s**, reprise vérifiée par transaction **32 s** |
| `recover -e wipe_data=true` : volume détruit, reconstruction + restauration | **48 s**, aucune perte de transaction |
| Proxy Docker de la remédiation | `restart` → 204 ; `create`, `exec`, `kill`, `images`, `volumes` → **403** |
| Injection SQL via le WAF (`?id=1' OR 1=1--`) | **403** (OWASP CRS) |

La faible empreinte mémoire laisse de la marge sur un PC 16 Go pour le modèle de langage local.
Les rapports détaillés des essais `chaos` sont dans `reports/`.

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
- **Mono-hôte** : pas de haute disponibilité réelle (un seul PC). La reprise couvre la panne
  d'un service, pas celle de la machine (→ PROC-01 + sauvegarde copiée hors du PC).
