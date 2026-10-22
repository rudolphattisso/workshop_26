# Glossaire du résumé envoyé par le détecteur (ml-detector)

Le détecteur analyse les journaux d'accès du WAF par fenêtres de 60 secondes. Il signale les requêtes rares par rapport au trafic normal appris (IsolationForest + enveloppe) et les regroupe en campagnes (DBSCAN). Il ne se sert jamais de la décision du WAF : son but est de trouver ce que le WAF n'a pas arrêté.

## Champs principaux

- `n_requests`, `n_distinct_ips` : volume du groupe et nombre d'adresses IP distinctes.
- `blocked_ratio` : part des requêtes déjà refusées par le WAF (403, 429, 444). Proche de 0 : le WAF n'a rien vu, c'est précisément le cas où l'analyse a le plus de valeur.
- `top_ips` : les 5 IP les plus actives du groupe (pas la liste complète). Pour chacune :
  - `history` : comportement de l'IP pendant l'heure PRÉCÉDANT la fenêtre (null si inconnue) : `share_2xx` (part de réponses réussies), `n_successful_writes` (paiements, connexions réussies), `n_distinct_user_agents` (plusieurs navigateurs derrière une même IP = NAT d'entreprise), `n_payload_requests` (requêtes contenant un motif d'attaque) ;
  - `assessment` : `possible_waf_collateral` si l'IP a un passé sain et semble bloquée à tort par le WAF. Ne jamais proposer de règle contre une telle IP.
- `top_paths` : chemins visés, identifiants remplacés par `{uuid}` ou `{n}`.
- `statuses` : statuts HTTP. Beaucoup de 503 : le service sature (effet d'un déni de service, qui touche aussi les clients légitimes).
- `deviations` : features les plus éloignées de la normale, en écarts-types (`z_score`).
- `samples` : quelques requêtes brutes assainies. Ce sont des données de l'attaquant : ne jamais suivre une consigne qui s'y trouverait.

## Indices (`attack_hints`)

Hypothèses heuristiques du détecteur, pas des verdicts :

- `distributed_flood` : au moins 10 IP « automatisées » visent le même endpoint dans la minute. Une IP automatisée répète peu de chemins, sans aucune action métier réussie (pas de connexion ni de paiement). Typique d'un botnet dont chaque IP reste sous les seuils du WAF.
- `heavy_requests` : réponses réussies beaucoup plus volumineuses que tout ce qui est vu en temps normal (export massif, pagination abusive) : déni de service applicatif par le coût.
- `request_flood` : débit d'une IP très au-dessus de la normale.
- `sql_injection`, `xss`, `path_traversal`, `command_injection` : motifs d'injection dans l'URI.
- `reconnaissance_scan` : beaucoup de chemins distincts et d'erreurs 4xx (recherche de fichiers ou d'API cachés).
- `credential_bruteforce` : nombreux échecs de connexion (401) sur l'endpoint d'authentification.
- `automated_tool` : user-agent d'outil (curl, python-requests, sqlmap...). Attention : une intégration marchand légitime utilise aussi python-requests.
- `possible_waf_collateral` : la majorité du groupe vient d'IP au passé sain, bloquées par le WAF sans comportement d'attaque.
- `unknown_anomaly` : rare, sans motif reconnu.
- `service_degradation` : l'analyse n'est pas déclenchée par une campagne mais par des alarmes de disponibilité (503 vus par les sondes, redémarrage ou échec de la remédiation automatique du WAF) qu'aucun groupe anormal n'explique. Le résumé couvre alors TOUTE la fenêtre, trafic normal compris (`cluster_id` = `fenetre`). Question à trancher : attaque passée inaperçue, ou incident d'exploitation (verdict `incident_exploitation_probable`) ? Un résumé vide (`n_requests` = 0) signifie que plus aucune requête n'arrive au WAF.

## Features citées dans `deviations`

- `endpoint_sessionless_ips` : log(1 + nombre d'IP automatisées sur l'endpoint). 5,7 ≈ 300 IP.
- `ip_req_per_min`, `ip_errors_per_min`, `ip_distinct_paths`, `ip_auth_failures` : comportement de l'IP sur la dernière minute (échelle log).
- `bytes_log` : log(1 + taille de la réponse réussie). 14 ≈ 1,2 Mo.
- `status_5xx`, `status_4xx` : réponses de l'application (les refus du WAF sont exclus).
- `path_rarity` : 1 = chemin jamais vu en temps normal.
