# ADR-DEV-0003 — Service d'auth : JWT RS256, JWKS en cache, clé éphémère

- **Statut** : accepté
- **Date** : 2026-10-20
- **Domaine** : Dev
- **Contrat impacté** : `contracts/openapi-payment.yaml` (0.3.0), `contracts/service-conventions.md` (0.2)

## Contexte

ADR-DEV-0001 fixe le principe : un service d'auth maison qui signe des JWT en RS256, des mots de passe hachés
en argon2. Il reste quatre points à trancher, chacun avec un effet direct sur la démo :

1. Comment payment-api obtient la clé publique, et ce qui se passe **quand l'auth tombe**.
2. D'où vient la **clé privée** de signature.
3. Comment **révoquer** les jetons si la remédiation conclut à une compromission.
4. Qui **limite les tentatives** de connexion (force brute).

## Décision

1. **JWKS en cache dans chaque service** (`resilience_common.jwt_auth.JwksKeyStore`).
   - Les clés connues restent en mémoire. Si l'auth est injoignable, les jetons déjà émis restent vérifiables.
   - Un `kid` inconnu déclenche un rechargement, limité à un toutes les 5 s, pour qu'un attaquant ne puisse pas
     saturer l'auth en envoyant des `kid` aléatoires.
   - Un rechargement remplace tout le jeu de clés : une clé retirée par l'auth cesse d'être acceptée.
   - Clé inconnue et auth injoignable ⇒ **503** (réessayer), et non 401 (se reconnecter).
2. **Clé de signature** :
   - si `JWT_PRIVATE_KEY_FILE` est défini, la clé est lue dans ce fichier PEM, monté depuis Vault/SOPS ;
   - sinon, une **clé éphémère** RSA 2048 est générée au démarrage et n'est jamais écrite sur disque.
   - Le `kid` est l'empreinte RFC 7638 de la clé publique.
3. **Révocation globale = redémarrer l'auth** avec une clé éphémère. Les anciens jetons portent un `kid` que
   payment-api retire dès le premier jeton récent qu'il voit. Les jetons durent 15 min.
4. **Pas de verrouillage de compte dans l'application**. La limitation de débit sur `/auth/login` est confiée
   au WAF (Cyber). L'application rend chaque échec visible : la métrique `auth_logins_total{outcome}` et le
   log `login_failed` (avec `username` et `client_ip`) alimentent le SOC et le modèle de détection.

Autres choix :

- **argon2id** avec les paramètres OWASP (m = 19 Mio, t = 2, p = 1).
- Un identifiant inconnu fait aussi un calcul argon2 (haché factice) : la réponse a la même durée et le même
  message qu'un mauvais mot de passe, ce qui empêche de deviner quels comptes existent.
- Le jeton porte `iss` et `aud`, vérifiés par tous les services, et `algorithms=["RS256"]` est imposé.
  Cela refuse `alg: none` et la confusion RS256/HS256.
- Les mots de passe de démo arrivent par variables d'environnement (`DEMO_CLIENT_PASSWORD`,
  `SMOKE_CLIENT_PASSWORD`, `OPERATOR_PASSWORD`), avec 12 caractères minimum. Le seed est idempotent :
  si une variable change, le haché est mis à jour au démarrage suivant.

## Conséquences

- ✅ Aucun secret partagé entre services : compromettre payment-api ne permet pas de fabriquer des jetons.
- ✅ Une panne de l'auth n'interrompt pas les paiements en cours. Le `/ready` de payment-api ne dépend pas
  de l'auth, ce qui évite les pannes en cascade.
- ✅ Un levier de remédiation simple et démontrable : « compromission de jetons ⇒ recréer le conteneur auth ».
- ✅ Vérifié en conteneurs :
  - auth arrêté ⇒ `GET /accounts` avec un jeton existant répond toujours 200 ;
  - auth redémarré ⇒ l'ancien jeton reçoit 401 et le nouveau 200, sans redémarrer payment-api.
- ⚠️ Un redémarrage de l'auth déconnecte tous les utilisateurs. C'est acceptable sur une démo, et le front
  renvoie vers la page de connexion sur 401. Pour l'éviter, il suffit de monter `JWT_PRIVATE_KEY_FILE`.
- ⚠️ Juste après un redémarrage de l'auth, un nouveau jeton peut être refusé pendant 5 s au plus, si un
  rechargement vient d'avoir lieu. Le smoke test doit donc **réessayer** une connexion en 401.
- ⚠️ Sans WAF devant `/auth/login`, la force brute n'est limitée que par le coût d'argon2.
  C'est une dépendance au domaine Cyber.

## Alternatives écartées

- **HS256 (secret partagé)** : chaque service capable de vérifier pourrait aussi fabriquer des jetons.
- **Introspection à chaque requête** (payment-api interroge l'auth) : l'auth devient un point de panne unique
  pour tous les paiements.
- **Verrouillage du compte après N échecs** : un attaquant pourrait verrouiller `smoke-client` et empêcher
  la preuve de reprise, soit un 0/5 garanti sur la remédiation.
- **Liste de révocation par `jti`** : il faudrait un stockage partagé et un appel par requête. C'est trop lourd
  pour le sprint, et la rotation de clé couvre le besoin de la démo.
