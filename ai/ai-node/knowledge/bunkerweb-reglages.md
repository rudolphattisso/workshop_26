# Réglages BunkerWeb utiles en réponse à une attaque

Format : variables `RÉGLAGE=valeur` (fichier d'environnement ou configuration du service). Plusieurs instances d'un même réglage prennent un suffixe numérique : `LIMIT_REQ_URL_1`, `LIMIT_REQ_RATE_1`. En mode multisite, préfixer par le nom du service (`www.exemple.fr_USE_ANTIBOT`).
Noms issus de la documentation BunkerWeb 1.5/1.6 : vérifier avec la version déployée.

## Anti-bot (défi)

- `USE_ANTIBOT` : `cookie`, `javascript`, `captcha`, `recaptcha`, `hcaptcha`, `turnstile`, `mcaptcha`.
- `ANTIBOT_URI` : URL du défi (défaut `/challenge`).
- `ANTIBOT_TIME_RESOLVE` (secondes pour résoudre), `ANTIBOT_TIME_VALID` (durée de validité).
- Mesure la plus efficace contre un botnet distribué : chaque IP doit résoudre le défi, ce que la plupart des bots ne font pas, quel que soit leur nombre.
- `javascript` est transparent pour un navigateur ; `captcha` gêne les humains.
- Effet de bord majeur : les clients non navigateurs (API, intégration marchand, sondes de supervision) échouent au défi. Réserver le défi aux pages visitées par des navigateurs, ou vérifier comment exclure l'API selon la version.

## Limitation de débit

- `USE_LIMIT_REQ=yes`, `LIMIT_REQ_URL_n` (préfixe d'URL ou expression), `LIMIT_REQ_RATE_n` (ex. `5r/s`, `30r/m`).
- Comptée PAR IP : inefficace contre un botnet dont chaque IP reste sous le seuil, sauf à descendre sous l'usage d'un humain. Utile pour un endpoint coûteux (export) : `LIMIT_REQ_URL_2=/api/payments` et `LIMIT_REQ_RATE_2=2r/s`.
- `USE_LIMIT_CONN=yes`, `LIMIT_CONN_MAX_HTTP1`, `LIMIT_CONN_MAX_HTTP2` : connexions simultanées par IP.

## Bannissement « bad behavior »

- `USE_BAD_BEHAVIOR=yes`, `BAD_BEHAVIOR_STATUS_CODES` (ex. `400 401 403 404 405 429 444`), `BAD_BEHAVIOR_THRESHOLD`, `BAD_BEHAVIOR_COUNT_TIME`, `BAD_BEHAVIOR_BAN_TIME` (secondes).
- Ne réagit qu'aux réponses d'erreur : un botnet qui reçoit des 200 n'est jamais banni.
- Effet de bord : un NAT d'entreprise peut être banni pour les erreurs cumulées de ses utilisateurs.

## Listes de blocage

- `USE_BLACKLIST=yes`, `BLACKLIST_IP` (IP ou réseaux séparés par des espaces), `BLACKLIST_USER_AGENT`, `BLACKLIST_URI`.
- Liste d'IP : pertinente pour quelques IP stables, pas pour un botnet de centaines d'IP qui tournent.
- Ne jamais bloquer plus large qu'un /24 sans analyse : les réseaux mobiles et les NAT partagent des IP.
- `USE_DNSBL=yes` : refuse les IP listées dans des listes de réputation.

## À ne jamais proposer

`USE_WHITELIST`, `WHITELIST_IP`, `USE_MODSECURITY=no`, `USE_MODSECURITY_CRS=no`, ou toute désactivation de protection.
