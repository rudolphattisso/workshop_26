# Point de reprise — ml-detector (module IA SOC)

Dernière mise à jour : 2026-10-21 (intégration à la branche infrastructure). À lire en début de nouvelle conversation.

## État actuel
- `detector/` : parsing (nginx/BunkerWeb), features (attack_signals, path_template, path_rarity, fenêtres par IP), modèles (IsolationForest + DBSCAN), détection, sanitize.
- `detector/sources/` : `loki.py` (source réelle), `simulated.py` + `sim_normal.py` / `sim_attacks.py` / `sim_common.py` (trafic simulé étiqueté, labels utilisés uniquement pour l'évaluation).
- `scripts/` : `train_baseline.py`, `demo_detect.py`, `scenarios.py`. Baseline entraînée dans `models/baseline.joblib`.
- `tests/` : parsing, features, détection.

## Décisions validées
- Aucune remédiation par l'IA ; métrique dédiée (`soc_waf_anomaly_score`), jamais `aiops_anomaly_score`.
- ml-detector sur le PC infra, LLM (Ollama + RAG) sur le PC IA, via POST /analyze.
- **Règles recommandées écrites dans un fichier** (pas de push auto) ; un humain copie-colle (BunkerWeb/ModSecurity), avec commentaire explicatif.

## Fait le 2026-10-20 (export Wazuh)
- Export dans `workshop_26/wazuh-alerts.jsonl` (+ `.csv`) : 4719 alertes, 19/10 12:48 → 20/10 09:18 UTC.
  1613 `web-accesslog` (ligne BunkerWeb brute dans `full_log`), 2130 `nginx-errorlog` (ModSecurity, id CRS), reste = SCA/syscheck/ossec.
- **Bug parseur corrigé** : le vrai format BunkerWeb est `$host $remote_addr - $request_id $remote_user [...]` (0 % parsé avant, 100 % après).
- `detector/sources/wazuh.py` : `WazuhJsonlSource` (garde `web-accesslog`, exclut host `bwapi` = health checks internes, 511 lignes) → 1102 requêtes client. Tests : `tests/test_wazuh_source.py`.
- `scripts/replay_wazuh.py` : `python -m scripts.replay_wazuh ../../wazuh-alerts.jsonl [--show-json]`.

## Constats du rejeu
- **Wazuh n'exporte que les requêtes ayant déclenché une règle** (403/444/503/429/401/502, aucun 200) : inutilisable pour entraîner une baseline, utilisable pour rejouer.
- Attaque principale 19/10 16:33–16:45, IP 172.30.10.1 (UA `resilience-labtest/1.0`) : XSS + SQLi + flood de 403 après bannissement (80–320 req/min/IP, floods simulés ~1 800).
- Non signalés à juste titre : 503 des sondes `resilience-blackbox`/`txprobe` (service indisponible), IP 172.30.20.x/40.x.

## Corrections détection (2026-10-20, après rejeu)
- Flood raté au départ (38 % de l'attaquant signalé). Causes et corrections :
  1. Enveloppe des compteurs par IP en log1p : l'écart-type du débit normal repoussait le seuil à ~760 req/min.
     → `DetectorConfig.envelope_max_factor` (défaut 3, env `DETECTOR_ENVELOPE_MAX_FACTOR`) : anormal au plus tard à 3 × le max baseline.
  2. Le débit seul ne sépare pas ce flood du NAT d'entreprise légitime (~60 req/min).
     → nouvelle feature `ip_errors_per_min` (dans l'enveloppe + indice `request_flood`). 30 features, `MODEL_FORMAT_VERSION = 2`.
  3. Bug préexistant : `ua_tool` dans l'enveloppe signalait l'intégration marchand légitime (`python-requests`, retirée de la baseline par le filtre anti-empoisonnement) → retiré de l'enveloppe. C'était la vraie cause de l'échec de `test_low_false_positive_rate` (pas la version de sklearn).
- Résultats (modèle réentraîné, sklearn 1.6.1) : attaquant réel 38 % → **92 %**, autres IP 0 % ; flood = cluster distinct `request_flood`.
  Démo : FP 0,99 % → 2,71 %, dus surtout au NAT (192.168.137.100) banni par le WAF simulé → traité ensuite (cf. « bannissement collatéral »).
  Canaris actuels (IP distinctes) : bruteforce 0,997, flood 0,956, autres 1,0.
- Nouveau test : `test_moderate_flood_detected_by_rate_alone`.
- Tests à lancer avec les versions épinglées (`requirements-dev.txt`) : la machine a sklearn 1.9.0 en global (le modèle livré est en 1.6.1).

## Audit de fuite de données (2026-10-20)
- **Fuite 1 (corrigée)** : tous les scénarios (démo ET canaris) attaquaient depuis la même IP .200 (`first_ip` jamais renseigné) → le scan la faisait bannir, toutes les attaques suivantes étaient des 403 avec l'historique d'erreurs du scan. Désormais une plage par attaque dans `scripts/scenarios.py`. Impact final faible (chaque attaque reste détectable par ses propres signaux), mais les canaris étaient faussés.
- **Fuite 2 (évaluation, non corrigeable)** : 11/12 charges XSS/SQLi du rejeu réel sont **identiques** à celles du simulateur (construit sur l'outil `resilience-labtest`). Le rejeu réel ne prouve donc pas la généralisation des regex. Jeu tenu à l'écart (24 charges obfusquées hors simulateur) : XSS 11/12, SQLi 9/12 ; ratés : triple encodage `%253C`, `1)) OR ((1=1`, `extractvalue(...)`, `-1 OR 2>1`. 0 faux positif regex sur 12 textes légitimes proches (O'Brien, « select a plan », « union bank »...).
- **Biais 3 (réglage sur le test)** : `envelope_max_factor` et `ip_errors_per_min` ont été choisis en regardant le rejeu réel → les 92 % sur l'attaquant sont optimistes. Il faudra une autre attaque réelle, non regardée, pour une mesure honnête.
- **Pas une fuite mais à savoir** : `status_blocked`/erreurs par IP réutilisent la décision du WAF (disponible en production, donc légitime). Ablation sans statuts ni erreurs/IP : démo FP 0,44 %, flood 77 %, réel 59 % → une bonne partie de la détection du flood réel « suit » les refus du WAF.
- Artefacts du simulateur testés par ablation (tailles de réponse fixes → `bytes_log` ; UA d'outils → `ua_len`/`ua_tool`) : les retirer change peu (réel 87–88 %), ils ne portent pas les résultats.
- Pas de fuite temporelle : features par IP = passé seulement ; `path_rarity` et seuil appris sur la baseline seule ; seeds différents train/démo/canaris (mais même générateur).
- Script d'audit (hors dépôt) : refaire l'AUC univariée + ablations si les features changent.

## Faux positifs « bannissement collatéral » (2026-10-20)
- `detector/ip_history.py` : `IpHistory` (1 h par IP, compteurs seulement, aucune chaîne client) → `IpProfile` : n_requests, share_2xx, share_blocked, n_successful_writes, n_distinct_user_agents, n_payload_requests.
- `DetectionPipeline.analyze(records, X, history=...)` : chaque entrée de `top_ips` porte `history` (comportement AVANT la fenêtre) et `assessment` = `"possible_waf_collateral"` ou null. Indice de cluster `possible_waf_collateral` si ces IP font ≥ 50 % du cluster (retire alors `request_flood`/`unknown_anomaly`). Mettre l'historique à jour APRÈS l'analyse (fait dans `demo_detect`/`replay_wazuh`).
- Hypothèse = passé sain (≥ 10 req, ≥ 50 % 2xx, 0 charge) ET dans le cluster : ≥ 80 % bloquées, 0 charge/outil, chemins connus, débit ≤ enveloppe. Jamais un verdict ; une IP sans historique n'est jamais marquée.
- `ip_auth_failures` ne compte plus que les 401 (un 403 sur /login = WAF, pas un mot de passe refusé).
- Indice `request_flood` : plancher absolu 60 req/min (ou erreurs/min).
- Démo : FP 2,71 % → 1,50 % ; 34/41 requêtes faussement signalées portent l'hypothèse collatérale ; **0 requête d'attaque marquée collatérale**. Le NAT n'est plus mélangé au cluster de force brute.
- Réel : attaquant non marqué (historique : 185 requêtes à charge, 0 % 2xx, 1 UA). Limite : l'export Wazuh n'a pas de 2xx, l'historique y est forcément « malsain ».
- Limites : un NAT banni à < ~40 req/min n'est pas signalé du tout (sous le seuil) ; un attaquant qui « chauffe » une IP avec du trafic propre puis floode à débit normal sur des chemins normaux serait marqué collatéral (d'où « hypothèse »).
- 36/36 tests OK (venv sklearn 1.6.1).

## Indépendance vis-à-vis du WAF (2026-10-20, décision utilisateur)
- Objectif : trouver ce que le WAF ne voit pas ; **aucune feature n'encode sa décision**.
  - Retirés : `status_blocked`, `bytes_log` (la page de blocage BunkerWeb fait 69 298 octets). 28 features, `MODEL_FORMAT_VERSION = 3`.
  - `features.app_status()` : 403/429/444 masqués en 200 (pas 0 : une combinaison inédite serait elle-même un signal). Statuts et erreurs par IP = réponses de l'application uniquement.
  - `status_blocked` retiré du regroupement DBSCAN. `blocked_ratio` reste dans le résumé (contexte LLM), calculé depuis les statuts bruts.
  - Test `test_features_ignore_waf_decision` : mêmes features pour 200 et 403/429/444.
  - Le filtre d'entraînement exclut toujours les requêtes bloquées (hygiène de la baseline, pas une entrée du modèle).
- Métrique principale = **rappel sur ce que le WAF laisse passer** (statut ∉ {403, 429, 444}) :
  - `demo_detect` : par type d'attaque, WAF seul | module sur ce que le WAF laisse passer | WAF + module.
  - Canaris : WAF inactif (ni signature ni bannissement) et rappel compté sur les requêtes non bloquées ; sinon le flood, banni en ~1 s, n'avait plus que sa première seconde à mesurer.
- Résultats :
  - DetectionOnly : le module trouve **100 %** des SQLi/XSS/traversal que le WAF laisse passer ; 82 % de toutes les attaques non bloquées.
  - Flood : 0 % sur les 55 requêtes non bloquées (première seconde avant le bannissement : rien à mesurer).
  - **FP 0,40 %** (contre 1,50 %) : le NAT banni n'est plus signalé.
  - Canaris : flood 0,863, autres 1,0.
- Réel : attaquant 92 % → **59 %**. 100 % de ses requêtes à charge, mais 34 % seulement de son flood sans charge. Débit p50 135 req/min, plafond de l'enveloppe 177 (3 × max baseline 59). Sans la décision du WAF, ce flood lent ne se distingue pas d'un NAT chargé par le seul débit.
  - Les 280 requêtes non bloquées de l'export (sondes 503, 401) sont à 0,7 % signalées. L'export ne permet pas de mesurer ce que le WAF rate : il faut l'access log complet BunkerWeb (avec les 200).
- L'hypothèse `possible_waf_collateral` ne se déclenche plus que si une IP au passé sain est signalée pour une autre raison (un bannissement seul ne suffit plus) ; testée directement.

## Démo DDoS : ce que le WAF n'attrape pas (2026-10-20, décision utilisateur)
- Cadre : la démo porte sur le DDoS, WAF actif ; le module ne vise pas l'exhaustivité mais ce qui passe sous les seuils du WAF.
- `python -m scripts.demo_detect` (scénario `ddos` par défaut, 20 min ; `--scenario web` pour l'ancien) :
  - 03:00 flood d'une IP → arrêté par le WAF ;
  - 06:00 afflux promo de 200 clients → piège à faux positifs ;
  - 10:00 botnet de 300 IP à 0,5 req/s ;
  - 14:00 contournement de cache, 40 IP avec `?_=<horodatage>` ;
  - 17:00 exports coûteux `?limit=10000` depuis 15 comptes.
- Simulateur (`simulated.py`), couches appliquées dans l'ordre :
  - `RateLimit` par IP : 429 au-delà de 5 req/s sur le login, 20 req/s ailleurs (sortie des générateurs, qui comptaient le débit par attaque et non par IP) ;
  - `BadBehavior` ;
  - `Capacity` : 60 unités/s, un export coûteux en vaut 40 ; 503 pour tout le monde au-delà, clients légitimes compris.
  - Afflux : `rush_visitors`, IP `10.50.x.y` (`RUSH_NET`). Botnets : `10.<first_ip>.x.y`.
- Features (30, `MODEL_FORMAT_VERSION = 4`), toujours indépendantes de la décision du WAF :
  - `endpoint_sessionless_ips` : nombre d'IP « automatisées » sur le même endpoint en 60 s. Une IP est automatisée si elle fait au moins 5 requêtes, avec un ratio chemins distincts / requêtes ≤ 0,3 et aucune action métier réussie (POST/PUT/PATCH/DELETE en 2xx). La valeur est nulle sous 5 IP, et nulle pour une IP qui n'est pas automatisée (les vrais clients pris dans l'attaque ne sont pas signalés).
  - `known_automated_ips` : IP déjà automatisées dans la baseline (sondes : Blackbox Exporter), exclues du comptage de foule. La liste est écrite dans `baseline.meta.json` **pour relecture** : une IP d'attaquant présente dans la baseline y serait aveuglée.
  - `bytes_log` (réponses 2xx seulement, sinon la médiane) : BunkerWeb remplace les pages d'erreur par les siennes (~69 Ko). Sans cette restriction, en réel, les 401/502 devenaient des faux positifs.
  - Enveloppe : ces deux features avec un plafond de 3 × le max baseline. Indices LLM : `distributed_flood` (≥ 10 IP automatisées), `heavy_requests`.
- Canaris : les 3 DDoS sont ajoutés (WAF, limitation de débit et saturation désactivés). Résultats : distribué 0,87, contournement de cache 0,90, exports coûteux 0,82.
- Résultats de la démo (WAF On) :

  | | WAF seul | module sur ce que le WAF laisse passer |
  |---|---|---|
  | botnet | 0 % | 95,5 % |
  | contournement de cache | 0 % | 97,1 % |
  | exports coûteux | 0 % | 72 % (les ratés ont reçu un 503 de saturation) |

  - Flood d'une IP : 97,8 % arrêté par le WAF.
  - Faux positifs : afflux promo 1,15 %, clients légitimes en 503 2,8 %, global 0,88 %.
  - Démo web inchangée ; réel inchangé (0,7 % des requêtes non bloquées signalées).
- **Biais à garder en tête** : features conçues en connaissant les attaques simulées. Variantes de botnet non réglées (6 min de trafic normal + botnet) :

  | Variante | Détecté |
  |---|---|
  | 300 IP à 30 req/min (référence) | 97 % |
  | 1000 IP à 6/min | 74 % |
  | **2000 IP à 3/min** | **28 %** |
  | 300 IP sur 4 chemins | 90 % |
  | 300 IP sur 8 chemins | 85 % |
  | connexion réussie d'abord | 74 % |

  FP 0,42 % dans tous les cas. Évasions connues : très grand botnet très lent, bots qui imitent une vraie session (connexion + actions).
- Test : `test_distributed_ddos_under_waf_thresholds_is_detected_but_not_a_legit_rush`. 42/42 tests OK.

## Performance et tests (2026-10-21)
- **DBSCAN était quadratique** sur un botnet (requêtes quasi identiques, chacune voisine de toutes) : 20 000 requêtes anormales → 17 s ; un DDoS à 1 000 req/s aurait dépassé la fenêtre de 60 s. Corrigé dans `DetectionPipeline._cluster` : points arrondis à 0,01 et regroupés une fois avec `sample_weight`. Mesures : 20 000 → 0,3 s, 60 000 → ~3 s. Résultats des démos identiques au chiffre près.
- Nouveaux tests :
  - `test_performance.py` : budget large (20 000 req < 20 s) et rapport d'échelle (×4 de volume → moins de ×8 de temps ; un algorithme quadratique donnerait ×16) ;
  - `test_simulator.py` : limitation de débit par IP, plancher du login, bannissement et expiration, saturation (les refus du WAF ne chargent pas l'application), coût des exports ;
  - `test_ip_history.py`.
- 52 tests.

## Escalade vers le LLM (2026-10-21, décision utilisateur : appel déclenché, pas cyclique)
- Le détecteur tourne en continu ; le LLM (~40 s de GPU) n'est appelé que sur escalade (`detector/escalation.py`).
- **Gravité 0-100, déterministe, avec ses raisons** :
  - indice le plus grave du détecteur (botnet 40, requêtes lourdes 35, force brute 30, injections 25…) ;
  - impact : 5xx ≥ 10 % → +25, ≥ 50 % → +40 ;
  - injection qui reçoit une **réponse de l'application** (ni refus du WAF ni 5xx) ≥ 20 % → +30 ;
  - WAF qui bloque ≥ 95 % sans impact → -30 ;
  - ≥ 50 IP, ≥ 1 000 requêtes, persistance ≥ 3 fenêtres → +10 chacun ;
  - alarme de disponibilité → +20 ; alarme WAF sur les mêmes IP → +10.
  - Impact et alarmes ne comptent que pour une vraie campagne (≥ 20 requêtes) : sinon des clients légitimes en 503 seraient escaladés.
  - Seuil 50 ; au plus 2 appels par fenêtre, les plus graves d'abord ; délai de garde de 30 min par signature, sauf aggravation de +20. Réglages par variables `ESCALATION_*`.
- **Symptôme sans campagne** (`Escalator.decide_symptom`) : au moins 3 alarmes de disponibilité qu'aucune campagne n'explique, ou **un seul échec de remédiation (règle 100210), qui passe outre le délai de garde** → le LLM reçoit `DetectionPipeline.overview` (toute la fenêtre, indice `service_degradation`, résumé vide si plus aucune requête).
- `detector/alarms.py` : alarmes Wazuh → familles (`availability` : 31123, 31163, 100210, 100211 ; `waf_ban` : 100110 ; `waf_block` : 100100-102, 31105, 31154, 31333 ; `recon` : 31151). `scripts/sim_alarms.py` : les mêmes, dérivées du trafic simulé.
- Résultats :

  | Scénario | Groupes anormaux | Appels au LLM | Lesquels |
  |---|---|---|---|
  | démo DDoS | 18 | 4 | botnet, contournement de cache, exports coûteux ×2 (aggravation) ; 0 trafic normal |
  | démo web, WAF actif | 18 | 1 | le flood qui sature ; injections bloquées ignorées |
  | démo web, DetectionOnly | 18 | 4 | les injections qui atteignent l'application, et le flood |
  | **export réel (20 h)** | 22 | **4** | 3 épisodes de service dégradé sans attaque détectée + l'échec de remédiation du 20/10 à 07:30 |

  - Essai réel de bout en bout (fenêtre du 20/10 à 08:43 → qwen2.5) : verdict **incident d'exploitation probable** (les sondes voient 100 % de 503), conseil de vérifier une saturation interne, aucune règle.
- Le rejeu parcourt aussi les fenêtres sans requête mais avec alarme (sinon l'échec de 07:30 était manqué).
- 66 tests (dont `test_escalation.py`).

## Service continu (2026-10-21)
- `detector/service.py` (`python -m detector.service`, cible Docker `runtime`) :
  - toutes les **10 s** (`DETECTOR_CYCLE_S`), analyse de la **fenêtre glissante de 60 s** (celle de l'entraînement) ;
  - deux fenêtres gardées en mémoire, pour les features par IP ;
  - escalade, puis **file d'attente et fil séparé** vers le llm-gateway (l'appel de ~40 s ne bloque jamais la détection) ;
  - `/metrics` et `/health` sur **8000** en production (9108 par défaut dans `scripts.run_service`) (`soc_waf_anomaly_score`, requêtes, groupes, durée de cycle, escalades par déclencheur, rapports par verdict, erreurs, file) ;
  - journal JSON (escalades, rapports).
- Coût mesuré : ~0,2 s par cycle (3 700 requêtes dans la fenêtre) ; ~3 s pour 60 000 req/min.
- Escalade adaptée à la fenêtre glissante :
  - persistance en minutes (`ESCALATION_PERSISTENCE_S`=120) ;
  - plafond par minute glissante (`ESCALATION_MAX_PER_MINUTE`=2) ;
  - **identité de campagne** = famille d'attaque + chemins majeurs (≥ 20 % des requêtes) : la signature variait d'un cycle à l'autre et renvoyait la même campagne ;
  - **une seule réanalyse sur aggravation** par délai de garde (vu : 55 → 80 → 100 = 3 analyses).
- `ClusterSummary.injections_answered` : requêtes avec charge d'injection ayant reçu une vraie réponse de l'application (ni refus du WAF, ni 5xx), compté requête par requête. Escalade si ≥ 3. La proportion de statuts du groupe déclenchait à tort en début de fenêtre glissante.
- `detector/gateway_client.py` (bibliothèque standard), `detector/metrics.py`, `detector/sources/replay.py` (rejeu « en direct » avec horloge accélérée).
- **Démo** : `python -m scripts.run_service --scenario ddos|web|wazuh --speed 5 [--gateway URL --token T] [--metrics-port 9108]`.
  - Essai réel de bout en bout (gateway + qwen2.5 locaux, vitesse ×5) : 4 escalades → 4 rapports « attaque » avec règles. Le botnet est escaladé dès ~20 s d'attaque (518 requêtes de 195 IP). Le premier appel paie le chargement du modèle (~20 s) : `LLM_KEEP_ALIVE=24h` côté gateway.
  - Limite : à très grande vitesse (×60 et plus), un cycle de calcul fait sauter des fenêtres. Pour l'export Wazuh de 20 h, utiliser `scripts.replay_wazuh`.
- Sources de production : voir « Intégration à la branche infrastructure ».
- 70 tests.

## File vers le LLM, réanalyses, restitution Grafana (2026-10-21)
- `detector/llm_queue.py` :
  - **une place par campagne** : une nouvelle escalade remplace le résumé en attente par le plus récent (fusion) ;
  - **la plus grave d'abord** ;
  - **péremption** à 5 min ; **taille maximale** 10 (la moins grave est écartée).
  - Une analyse écartée ou en erreur **libère le délai de garde** (`Escalator.release`) : la campagne est réescaladée avec des données fraîches. Métrique `soc_llm_dropped_total{reason}`.
- **Réanalyse** : le service garde le dernier rapport de chaque campagne et l'envoie dans `context.analyse_precedente` (date, verdict, résumé, règles déjà proposées).
- **Journal pour Grafana** : une ligne JSON `"event": "rapport"` par rapport (`famille`, `declencheur`, `mise_a_jour`, `gravite`, `verdict`, `confiance`, `type`, `regles`, `avertissements`, `duree_s`, `lien`) et une `"event": "escalade"`. `REPORTS_URL` (ou `--reports-url`) produit le lien vers la page du rapport.
- **Tableau de bord à importer** : `grafana/soc-ia-dashboard.json` (UID de sources fixes de l'infra `prometheus` / `loki`, à provisionner dans `infra/grafana/dashboards/` ; sélecteur Loki `$selecteur`, `{service="ml-detector"}` par défaut). Contenu :
  - tuiles : gravité actuelle (seuils 50 / 80), analyses en attente, rapports, écartées, erreurs sur 24 h ;
  - courbe de gravité avec le seuil, annotations escalades et rapports (Loki) ;
  - tableau des incidents, **une ligne par rapport, jamais réécrite**, verdict coloré, lien « Ouvrir ».
  - **Non testé dans un vrai Grafana** (JSON valide ; label `service` d'Alloy confirmé en lisant la branche infrastructure).
- Vérifié en réel (rejeu DDoS + gateway + qwen2.5) : 4 rapports, la réanalyse est marquée `mise_a_jour` et cite la limitation déjà proposée au lieu de la recopier. Le diagnostic de la réanalyse ne décrit pas explicitement ce qui a changé (consigne mal suivie par le 7B).
- 74 tests (dont `test_service.py`).

## Intégration à la branche infrastructure (2026-10-21)
Lu dans `git show infrastructure:...` (jamais modifiée par nous). **Document pour l'infra : `docs/ia/INTEGRATION.md`** (blocs compose / secret / Prometheus prêts à coller, validés par `docker compose config` sur une copie de leur compose).
- Bloquants corrigés :
  - réseau `monitoring` en `internal: true` → réseau dédié `ia` (172.30.110.0/24) avec sortie, pour joindre le PC IA ;
  - `detector/sources/loki.py` : `LokiClient` (pagination `query_range`), `LokiSource` (`{service="bunkerweb"}` : label posé par Alloy, `"waf"` dans leur doc est périmé), `LokiWazuhAlarmSource` (`{service="wazuh"}`, JSON dans une ligne syslog) ;
  - modèle entraîné pendant le build (étape `model` du Dockerfile), `HEALTHCHECK`, port 8000.
- Contrat de service aligné :
  - jeton lu dans `/run/secrets/llm_gateway_token` (`LLM_GATEWAY_TOKEN_FILE`) ;
  - `detector/logs.py` : journal JSON `ts`, `level`, `service`, `msg` (+ `event` et champs libres) ;
  - lecture en retard de 5 s (`DETECTOR_INGEST_DELAY_S`) pour l'ingestion Loki ;
  - `LLM_GATEWAY_URL` / `REPORTS_URL` facultatifs (vides : détection seule) pour ne pas bloquer leur `compose up`.
- Résilience : une erreur de cycle (Loki injoignable) est journalisée (`cycle_erreur`) et comptée (`soc_detector_errors_total`) ; le cycle suivant rattrape au plus deux fenêtres. Vérifié en lançant `main()` contre un Loki absent.
- Règles Wazuh de leur `local_rules.xml` ajoutées : 100103 (WAF_BLOCK), 100112 (WAF_BAN), 100200/100201 (nouvelle famille `AUTH`, corroborante).
- `.gitignore` : `reports/*` + `!reports/.gitkeep` (motif de l'infra), exports Wazuh exclus.
- À la fusion : supprimer `README.MD` (collision de casse avec leur `README.md` sous Windows).
- **Non vérifié** : build Docker (daemon arrêté pendant la session), vrai Loki, vrai Grafana.
- 86 tests (à cette étape).

## Actions de l'infra et perte de visibilité (2026-10-21, décision utilisateur)
- `detector/infra_actions.py` + `LokiRemediationSource` (`{service="remediation"}`, journal JSON du moteur de remédiation de l'infra, lecture seule) :
  - chronologie des 15 dernières minutes jointe à CHAQUE analyse (`context.actions_infra`) ;
  - `remediation_failed` devient une alarme critique (`_CRITICAL_RULES`), même si Wazuh est tombé.
- Correction : une même alarme critique restait 60 s dans la fenêtre glissante et relançait une analyse à chaque cycle ; seule une alarme critique NOUVELLE passe outre le délai de garde (`Escalator._critical_seen`).
- Perte de visibilité (`Escalator.decide_visibility`, clé `__visibilite__`, gravité 60, une analyse par délai de garde) :
  - Loki en erreur `visibility_errors`=3 cycles d'affilée ;
  - 0 requête dans la fenêtre après ≥ 30 requêtes/fenêtre dans les 5 min (le trafic calme ne déclenche pas) ;
  - lecture tronquée (`LokiClient.truncated`, `soc_detector_truncated_total`).
  - Le LLM reçoit l'aperçu du tampon (2 dernières fenêtres avant la coupure), indice `visibility_loss`, `donnees_jusqu_a`.
- Signal de vie toutes les 30 s (`POST /heartbeat`) : `/health` et `/reports` du PC IA affichent « muet » (> 2 min sans signal) ou « aveugle ».
- Essai réel (DDoS rejoué, remédiation du WAF en échec, Loki coupé en pleine attaque, qwen2.5) : rapport en ~31 s. Premier essai : verdict « incident d'exploitation » (signalé par le contrôle de cohérence) ; consignes 6-7 du prompt précisées → verdict « attaque », impact citant les redémarrages du WAF en échec, 2 règles (observation des IP, anti-bot).
- 96 tests.

## Seuils de visibilité calés sur les sondes, calibrage (2026-10-21)
- Constat : les seuils (30 s Loki, 60 s de silence, 5 s d'ingestion, 30 s Wazuh) étaient estimés. L'export Wazuh ne permet pas de les mesurer (il ne contient que les lignes d'accès qui ont déclenché une alerte : 114 sondes en 20 h).
- Leur Prometheus sonde 3 URL À TRAVERS le WAF toutes les 5 s (`blackbox-http`, `scrape_interval: 5s`, agent `resilience-blackbox/1.0`) : ≥ 36 requêtes/min dans les journaux du WAF, utilisateurs ou pas.
- Détection : aucune sonde depuis `DETECTOR_PROBE_MISSED` × `DETECTOR_PROBE_INTERVAL_S` (3 × 5 = 15 s) → perte de visibilité. Si d'autres requêtes arrivent, le motif dit « le WAF ne sert plus les sondes ». Le seuil de volume (≥ 30 puis 0) ne sert plus que de repli si aucune sonde n'a jamais été vue.
- Journal sur changement d'état (`perte_de_visibilite` avec `causes`, puis `visibilite_retablie`), plus une ligne par cycle.
- Seuils en variables : `DETECTOR_PROBE_UA`, `DETECTOR_PROBE_INTERVAL_S`, `DETECTOR_PROBE_MISSED`, `DETECTOR_VISIBILITY_ERRORS`, `LOKI_WAZUH_MARGIN_S`.
- `detector/calibrate.py` (`python -m detector.calibrate [--watch-loki 180]`, dans l'image runtime) : mesure retard d'ingestion (Loki interrogé chaque seconde), intervalle et trous des sondes, retard des alertes Wazuh, temps de réponse et redémarrage de Loki ; recommande sur le p99. Vérifié contre un faux Loki (retards simulés 3 s / 5 s / 7 s retrouvés). **Pas encore lancé sur la vraie plateforme.**
- 105 tests.

## Côté LLM
- `ai/ai-node/` (PC IA) : llm-gateway implémenté et testé avec un LLM simulé. Voir `ai/ai-node/HANDOFF.md`.

## Prochaine étape
- La démo est gérée par l'infra (attaque depuis un 3e PC).
- Au premier essai sur le PC infra : `docker compose build ml-detector`, puis `python -m detector.calibrate --watch-loki 180` et reporter les valeurs, vérifier la cible Prometheus, les lignes `{service="ml-detector"}` dans Loki, l'arrivée des accès `{service="bunkerweb"}` (format de ligne réel via Loki) et le tableau Grafana.
- Récupérer l'access log complet BunkerWeb (Loki) pour une baseline réelle (le max simulé de 59 req/min fixe le seuil du flood).
- Commits : à faire à la fin (décision utilisateur).

## Organisation du dépôt et contrat entre les deux PC (2026-10-21)
- Un dossier par machine : `infra/ml-detector/` (PC infra, compose de l'infra), `ai/ai-node/` (PC IA, son compose). Documentation commune dans `docs/ia/` : `README.md` (vue d'ensemble), `INTEGRATION.md` (déplacé depuis `infra/ml-detector/`), `DEPLOIEMENT-PC-IA.md`.
- `contracts/analyze/*.json` : requêtes /analyze produites par le vrai détecteur (`infra/ml-detector/scripts/contract_examples.py`, ~17 s) : campagne DDoS, réanalyse, injection servie, symptôme, perte de visibilité.
  - `infra/ml-detector/tests/test_contract.py` : même FORME (champs, imbrication ; `statuses`/`methods` traités comme des tables) ; vérifié qu'un champ renommé fait échouer.
  - `ai/ai-node/tests/test_contract.py` : aucun champ ignoré en silence (`extra="ignore"`), chaque exemple passe l'analyse, les clés de contexte lues par le code produisent leur effet.
  - Ignorés dans les images Docker (`contracts/` hors du contexte de build).
- Les exemples écrits à la main de `ai/ai-node/tests/fixtures/` restent (tests ciblés par indice).

## Intégration dans develop (2026-10-22)
- Branches : `ai/module-soc` (travail IA), `ai/fusion-develop` (copie d'`origin/develop` + fusion + intégration), PR vers `develop`.
- Intégré dans `ai/fusion-develop` : service `ml-detector`, réseau `ia`, secret `llm_gateway_token` (compose) ; `llm_gateway_token` dans `ansible/inventory/hosts.yml` (généré au déploiement) ; cible `extensions.yml` (`tier: soc`) ; tableau déplacé dans `infra/grafana/dashboards/soc-ia-dashboard.json` ; `LLM_GATEWAY_URL` / `REPORTS_URL` dans `.env.example`.
- Dans develop, c'est `auto-recovery` (ancien moteur infra) qui redémarre et journalise `remediation_*` (champ `msg`) : requête par défaut `{service="auto-recovery"}`. `remediation` n'est que le watchdog Dev.
- Journaux au format commun (`timestamp`, `level`, `service`, `trace_id`, `event`, `logger`) ; `/ready` (503 si Loki injoignable).
- Vérifié en réel (2026-10-22, `ops deploy` sur ai/fusion-develop) : 28 conteneurs sains, vérification de l'équipe au vert, ml-detector healthy, /ready OK, cible Prometheus up, 131 requêtes BunkerWeb réelles lues par fenêtre (cycle 0,1 s), lien PC IA (réseau ia, jeton, signal de vie) OK via une gateway locale.
- Test de panne (`ops chaos -e target=bunkerweb -e fault=kill`, détection 25 s, reprise 64 s) : perte de visibilité (sondes absentes 22 s) -> rapport, puis symptôme (30 alarmes Wazuh) -> rapport avec la chronologie d'auto-recovery ; « visibilité rétablie » au retour des sondes.
- Corrigé pendant ce lancement : `LLM_GATEWAY_URL=   # commentaire` (valeur vide + commentaire) pris pour l'URL par Compose -> fil du signal de vie tué ; client et démarrage durcis, exceptions de fil en JSON ; motif « autres requêtes » compté sur le cycle et non sur la fenêtre.
- Bug de develop (non corrigé, à signaler à l'infra) : sur un poste neuf, `ops deploy` démarre Vault avant `bunkerweb_prepare` -> BW_API_TOKEN / BW_UI_PASSWORD manquants, échec.
