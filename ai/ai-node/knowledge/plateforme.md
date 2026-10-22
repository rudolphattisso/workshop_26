# Plateforme de paiement protégée

Constaté dans les journaux (export Wazuh du 19-20/10/2026 et simulateur) ; à compléter par le pôle infrastructure.

## Endpoints

- `/` : page d'accueil de l'application (SPA). Les visiteurs arrivent souvent avec des paramètres marketing (`utm_source`, `gclid`, `fbclid`).
- `/api/auth/login` (POST) : authentification. Les échecs renvoient 401.
- `/api/payments` (GET liste, paramètre `limit` ; POST création, 201). Le front n'envoie jamais `limit` au-delà de 100. La SPA ajoute parfois un paramètre anti-cache `_=<horodatage en millisecondes>`.
- `/api/payments/{uuid}` : détail d'une transaction.
- `/api/payments/ready`, `/api/auth/ready` : sondes de disponibilité.

## Trafic légitime à ne pas bloquer

- Sondes de supervision : `resilience-txprobe/1.0` (transactions synthétiques : connexion, paiement, lecture), Blackbox Exporter (`resilience-blackbox/1.0`), UptimeRobot. Comportement automatisé par nature.
- Intégration marchand : back-end qui envoie des lots de paiements avec `python-requests` ou `axios`, 1 à 2 requêtes/s.
- Entreprises derrière un NAT : plusieurs personnes et plusieurs navigateurs derrière une seule IP, débit par IP élevé.
- Afflux promotionnels : des centaines de nouveaux visiteurs en quelques minutes. Ils naviguent, se connectent et paient : ce ne sont pas des IP « automatisées ».

## Protections en place (WAF BunkerWeb)

- ModSecurity + OWASP CRS v4 (paranoïa 1).
- Limitation de débit par IP : 5 req/s sur la connexion, 20 req/s sur l'API.
- « Bad behavior » : 20 réponses 4xx/429 en 60 s => IP bannie 300 s (403).
- Ces protections raisonnent IP par IP : une attaque répartie sur des centaines d'IP, chacune sous les seuils, n'est ni limitée ni bannie.

## Attaque de référence du 19/10/2026

Outil `resilience-labtest/1.0` depuis une seule IP (172.30.10.1) : XSS, injections SQL, puis flood. Le WAF a bloqué les injections et banni l'IP (318 bannissements). Les sondes ont mesuré des 503 (service indisponible) pendant l'attaque.
