# Intégration du module IA SOC dans la plateforme

Ce document s'adresse aux pôles infra et cyber. Il décrit ce qu'il faut ajouter à la branche
`infrastructure` pour brancher le module IA. Tous les blocs sont prêts à coller.

## Vue d'ensemble

```
PC INFRA (compose resilience)                                PC IA (compose ai-node)
                                                             
 bunkerweb ─┐                                                 
 wazuh ─────┼─ Alloy ─> Loki ──(lecture)──> ml-detector ──HTTP 8080──> llm-gateway ─> Ollama (qwen2.5)
            │                               │  réseau "ia"     jeton       │         ChromaDB (RAG)
            │                               │                              └─> reports/ (règles à
 Prometheus <──── /metrics :8000 ───────────┘                                  copier-coller, /reports)
 Grafana  <── tableau « Module IA SOC » (Prometheus + Loki)
```

- **ml-detector** tourne sur le PC infra, dans votre compose. Toutes les 10 s, il lit les accès
  BunkerWeb et les alertes Wazuh dans Loki, détecte ce que le WAF laisse passer et, sous
  conditions, demande une analyse au LLM.
- **llm-gateway** tourne sur le PC IA, dans un compose séparé (`ai/ai-node/`). Il rédige un rapport et
  des **recommandations** de règles WAF.
- **Le module ne remédie jamais** : aucune règle n'est appliquée automatiquement, aucun appel au
  webhook de remédiation, aucune écriture dans la configuration du WAF. Un humain relit puis
  copie-colle les règles.

## 1. Bloc compose (`docker-compose.yml` de la branche infrastructure)

Le détecteur doit joindre le PC IA. Le réseau `monitoring` étant `internal: true`, il faut un réseau
avec sortie. Le bloc ci-dessous en crée un, dédié (`ia`), plutôt que d'utiliser `mgmt` : seul le
détecteur y est branché, et la sortie peut être restreinte au seul PC IA (voir §5).

**Sous `networks:`**

```yaml
  ia:           # pôle IA : sortie du ml-detector vers le llm-gateway du PC IA (port 8080)
    ipam: { config: [{ subnet: 172.30.110.0/24 }] }
```

**Sous `secrets:`**

```yaml
  llm_gateway_token:      { file: ./secrets/llm_gateway_token }
```

**Sous `services:`**

```yaml
  ml-detector:
    <<: *python-service
    build: { context: ./infra/ml-detector, target: runtime }   # modèle entraîné pendant le build
    image: resilience/ml-detector:${APP_VERSION:-1.0.0}
    environment:
      LOKI_URL: http://loki:3100
      LOKI_WAF_QUERY: '{service="bunkerweb"}'
      LOKI_WAZUH_QUERY: '{service="wazuh"}'
      LOKI_REMEDIATION_QUERY: '{service="remediation"}'   # actions de votre moteur, en lecture seule
      LLM_GATEWAY_URL: ${LLM_GATEWAY_URL:-}       # vide : détection seule, sans appel au LLM
      REPORTS_URL: ${REPORTS_URL:-}               # lien « Ouvrir » du tableau Grafana
      DETECTOR_CYCLE_S: "10"
      # Seuils estimés : à remplacer par les valeurs mesurées (voir « Calibrage » plus bas).
      DETECTOR_INGEST_DELAY_S: "5"      # retard d'ingestion de Loki
      DETECTOR_PROBE_INTERVAL_S: "5"    # vos sondes blackbox à travers le WAF (scrape_interval)
      DETECTOR_PROBE_MISSED: "3"        # sondes manquées d'affilée = perte de visibilité
      DETECTOR_VISIBILITY_ERRORS: "3"   # cycles de 10 s avec Loki injoignable
      LOKI_WAZUH_MARGIN_S: "30"         # retard des alertes Wazuh sur les faits
    secrets: [llm_gateway_token]
    networks: [monitoring, ia]
    depends_on: { loki: { condition: service_started } }
    labels: { resilience.tier: soc }
    deploy: { resources: { limits: { memory: 512m, cpus: "1.0" } } }
```

**Dans `.env`** (facultatif : sans ces deux lignes, le détecteur tourne seul, avec métriques et
journaux, sans appeler le LLM ; le reste de la plateforme n'est pas concerné) :

```sh
LLM_GATEWAY_URL=http://<IP du PC IA>:8080
REPORTS_URL=http://<IP du PC IA>:8080/reports
```

Le bloc reprend le contrat de service commun (`contracts/service-conventions.md`) : port 8000 (`/health`,
`/ready` et `/metrics` ; `/ready` répond 503 si Loki est injoignable), utilisateur non-root
10001, système de fichiers en lecture seule (aucune écriture à l'exécution), secret lu dans
`/run/secrets/llm_gateway_token`, journaux JSON sur stdout (`timestamp`, `level`, `service`, `trace_id`,
`event`, `logger`).
Aucun port n'est publié sur l'hôte. Le `HEALTHCHECK` est dans le Dockerfile.

Si Loki ou le PC IA sont indisponibles, le service continue de tourner. L'erreur est journalisée
(`cycle_erreur`, `gateway_erreur`) et comptée (`soc_detector_errors_total`, `soc_llm_errors_total`),
puis le cycle suivant rattrape la période manquée (deux fenêtres au plus).

**Si l'attaque fait tomber les sources de données**, un rapport sort quand même :

| Situation | Ce que fait le module |
|---|---|
| Loki injoignable 3 cycles de suite (30 s) | analyse « perte de visibilité » envoyée au LLM avec ce qui a été vu avant la coupure (2 dernières minutes, alarmes, actions de remédiation) |
| Plus aucune de vos sondes blackbox dans les journaux du WAF depuis 3 intervalles (15 s) | même analyse : WAF arrêté ou collecte coupée ; si d'autres requêtes arrivent encore, le WAF ne sert plus les sondes (saturé, sondes bannies) |
| Sondes absentes des journaux (cible changée) | repli : plus aucune requête après du trafic |
| Volume hors norme (lecture tronquée) | même analyse, et `soc_detector_truncated_total` |
| Wazuh tombé | les échecs de remédiation sont aussi lus directement dans le journal de votre moteur (`remediation_failed`) |
| PC infra ou réseau coupé | le PC IA ne reçoit plus le signal de vie (toutes les 30 s) : bandeau « détecteur muet » sur `/reports` et dans `/health` |

Le LLM étant sur l'autre PC, l'analyse ne dépend pas de la machine attaquée. Les rapports restent
consultables sur `/reports` même si Grafana ou Loki sont tombés.

**Actions de votre moteur de remédiation** : le détecteur lit `{service="remediation"}` (alertes
reçues, redémarrages lancés, réussis, en échec, ignorés). La chronologie est donnée au LLM, qui dit
si elles ont aidé, et recopiée telle quelle dans le rapport. Aucune interaction avec le moteur.

### Calibrage des seuils (au premier déploiement)

Les délais ci-dessus sont estimés. Ce script les mesure sur votre plateforme (lecture seule de
Loki) et affiche les valeurs à reporter dans le bloc compose :

```sh
docker compose run --rm ml-detector python -m detector.calibrate                    # ~2 min
docker compose run --rm ml-detector python -m detector.calibrate --watch-loki 180   # + redémarrage de Loki
#   (pendant les 180 s, dans un autre terminal : docker compose restart loki)
```

Il mesure :
- le retard d'ingestion de Loki ;
- l'intervalle réel des sondes et le plus grand trou observé ;
- le retard des alertes Wazuh ;
- le temps de réponse de Loki ;
- la durée d'un redémarrage de Loki.

Il recommande des valeurs à partir du p99, pas du maximum : un trou isolé figure dans le résultat
pour qu'un humain le regarde, mais il ne relève pas les seuils à lui seul.

Si vous changez l'intervalle de Prometheus (`scrape_interval`) ou l'agent utilisateur de la sonde
blackbox, prévenez-nous : `DETECTOR_PROBE_INTERVAL_S` et `DETECTOR_PROBE_UA` en dépendent.

## 2. Secret `llm_gateway_token`

Il s'agit d'un jeton partagé entre les deux PC, d'au moins 32 caractères. À ajouter à la génération
des secrets (Ansible), comme les autres :

```sh
python3 -c "import secrets; print(secrets.token_urlsafe(48))" > secrets/llm_gateway_token
```

Recopier **la même valeur** dans `ai/ai-node/.env`, sur le PC IA (`LLM_GATEWAY_TOKEN=`). Si
`LLM_GATEWAY_URL` est défini mais que le jeton est absent ou trop court, le détecteur refuse de
démarrer.

## 3. Prometheus : `infra/prometheus/targets/extensions.yml`

```yaml
- targets: ["ml-detector:8000"]
  labels: { service: ml-detector, tier: soc }
```

La cible est prise en compte sans redémarrer Prometheus. Si le détecteur tombe, votre alerte
`TargetDown` le signale (`remediation: none`, donc aucune action automatique).

## 4. Grafana

Copier `infra/ml-detector/grafana/soc-ia-dashboard.json` dans `infra/grafana/dashboards/`. Il
utilise vos UID de sources fixes (`prometheus`, `loki`) et apparaît dans le dossier
Resilience-Alpha. Il contient :

- la gravité en continu (0-100) ;
- les compteurs d'escalades, de rapports et d'erreurs ;
- les annotations « Escalade » et « Rapport » sur la courbe ;
- le tableau des incidents (verdict, type, règles proposées, lien vers le rapport complet).

## 5. PC IA

Installation pas à pas : [DEPLOIEMENT-PC-IA.md](DEPLOIEMENT-PC-IA.md). Ce qui concerne le lien entre
les deux PC :

- Dans `ai/ai-node/.env` :
  - `GATEWAY_BIND=<IP du PC IA>` : la valeur par défaut, `127.0.0.1`, n'accepte que les connexions
    locales ;
  - `LLM_GATEWAY_TOKEN` ;
  - `REPORTS_PASSWORD`, pour les pages `/reports` (utilisateur `soc`).
- Seul le port 8080 du llm-gateway est exposé : Ollama et ChromaDB restent internes.
- Pare-feu du PC IA : n'autoriser le port 8080 que depuis le PC infra (le détecteur) et les postes
  qui consultent les rapports.
- Côté PC infra (facultatif, recommandé) : limiter la sortie du réseau `ia` au seul PC IA.

  ```sh
  iptables -I DOCKER-USER -s 172.30.110.0/24 -j DROP
  iptables -I DOCKER-USER -s 172.30.110.0/24 -d <IP_PC_IA> -p tcp --dport 8080 -j ACCEPT
  ```

- Vérifications :
  - depuis le PC infra, `curl http://<IP_PC_IA>:8080/health` ;
  - après démarrage, `curl -s localhost:9090/api/v1/targets | grep ml-detector` ;
  - dans Grafana Explore, `{service="ml-detector"}`.

## 6. Pourquoi `soc_waf_anomaly_score` et pas `aiops_anomaly_score`

Votre `extensions.yml` et `docs/INTEGRATION.md` prévoient que le détecteur publie
`aiops_anomaly_score`. Nous publions volontairement **une autre métrique**, `soc_waf_anomaly_score`
(0-100), pour la raison suivante.

- `aiops_anomaly_score > 0.8` déclenche `AnomalyDetected`, avec `remediation: restart`. Alertmanager
  appelle alors le webhook de remédiation, qui redémarre le service visé.
- Le détecteur voit des **attaques**, pas des pannes. Redémarrer quoi que ce soit en réponse à une
  attaque ne protège rien. Si c'est le WAF qui redémarre pendant un DDoS, c'est même l'effet
  recherché par l'attaquant : on a observé des 503 pendant les redémarrages du WAF dans vos
  exports Wazuh.
- Un faux positif du modèle déclencherait un redémarrage en pleine démo. Le module ne doit pas
  pouvoir dégrader la plateforme.
- La réponse à une attaque est une **règle WAF relue par un humain**, et c'est ce que produit le
  LLM.

Conséquence : `AnomalyDetected` ne se déclenche jamais à cause de nous, ce qui est voulu. Merci de
**ne pas** créer d'alerte avec remédiation sur `soc_waf_anomaly_score`. Une alerte purement
informative (`remediation: none`) reste possible.

## 7. Sélecteurs Loki

- Les accès du WAF portent `{service="bunkerweb"}`, nom du service compose posé par Alloy. Votre
  `docs/INTEGRATION.md` mentionne encore `{service="waf"}`, qui ne correspond plus à rien.
- Les alertes Wazuh portent `{service="wazuh"}` (JSON dans une ligne syslog).
- Les actions du moteur de remédiation portent `{service="remediation"}`. Le détecteur lit le nom de
  l'action dans `event` (convention commune) ou `msg` (ancien format) : `remediation_started`,
  `remediation_succeeded`, `remediation_failed`, `remediation_skipped`, `remediation_refused`,
  `alert_received`. Le moteur v0 de `develop` (surveillance seule) n'en écrit pas encore : la
  chronologie restera vide tant qu'il ne journalise pas ses actions sous ces noms. Si vous
  renommez ces événements, prévenez-nous (fichier `detector/infra_actions.py`).
- Les règles locales lues par le détecteur sont 100100-100103, 100110-100112, 100200-100201 et
  100210-100211. Si vous ajoutez une règle, prévenez-nous pour qu'on la classe (fichier
  `detector/alarms.py`).

## 8. Organisation dans le dépôt

- `infra/ml-detector/` : le détecteur, rangé chez l'infra puisqu'il tourne dans leur compose (à
  valider avec le responsable infra). Le bloc compose du §1 est à ajouter par l'infra.
- `ai/ai-node/` : le PC IA (llm-gateway, base de connaissances, compose séparé).
- `docs/ia/` et `contracts/analyze/` : parties communes, à relire en PR par l'équipe.
- Aucun fichier existant des autres domaines n'est modifié par la branche IA.
