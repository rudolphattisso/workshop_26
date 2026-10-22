# Règles ModSecurity personnalisées (BunkerWeb)

Les règles proposées par l'IA vont dans un fichier de règles personnalisées chargé par BunkerWeb. Identifiants réservés à l'IA : 99000 à 99999 (plage locale, hors CRS).

## Syntaxe

`SecRule VARIABLE "OPÉRATEUR" "id:99001,phase:1,deny,status:403,log,msg:'explication courte'"`

- Variables utiles : `REMOTE_ADDR`, `REQUEST_FILENAME` (chemin sans paramètres), `REQUEST_METHOD`, `ARGS_GET:nom` (paramètre de l'URL), `ARGS_GET_NAMES`, `REQUEST_HEADERS:User-Agent`, `REQUEST_HEADERS:Referer`, `&REQUEST_HEADERS:Referer` (nombre d'en-têtes Referer).
- Opérateurs : `@streq`, `@beginsWith`, `@rx` (expression régulière), `@gt` et `@lt` (numériques), `@eq`, `@ipMatch` (IP ou réseaux séparés par des virgules).
- Actions : `phase:1` (en-têtes et URL, le plus tôt possible), `deny` + `status:403` (ou `429`), `log`, `msg:'...'`, `chain` (la règle suivante doit aussi correspondre).
- Interdit dans les propositions : `SecRuleEngine`, `ctl:`, `SecRuleRemoveById`, `SecAction`, `allow`, `nolog`.

## Exemples

Chaque exemple est un contenu complet, prêt à copier ; les lignes « # » sont des commentaires. Les adresses 203.0.113.x sont fictives : les remplacer par des IP du groupe analysé.

    # Plafonner la taille des exports (déni de service applicatif par le coût)
    SecRule REQUEST_FILENAME "@streq /api/payments" "id:99001,phase:1,deny,status:403,log,msg:'Export trop volumineux (limit > 1000)',chain"
        SecRule ARGS_GET:limit "@gt 1000"

    # Bloquer quelques IP identifiées (pas un botnet entier)
    SecRule REMOTE_ADDR "@ipMatch 203.0.113.10,203.0.113.11" "id:99002,phase:1,deny,status:403,log,msg:'IP de la campagne'"

    # Contournement de cache sur la page d'accueil : paramètre anti-cache sans Referer
    # (la SPA légitime envoie un Referer : à vérifier avant application)
    SecRule REQUEST_FILENAME "@streq /" "id:99003,phase:1,deny,status:403,log,msg:'Contournement de cache sans Referer',chain"
        SecRule ARGS_GET_NAMES "@streq _" "chain"
            SecRule &REQUEST_HEADERS:Referer "@eq 0"

    # Injection déjà connue sur un paramètre (si le CRS ne la bloque pas)
    SecRule ARGS_GET:q "@rx (?i)<script" "id:99004,phase:1,deny,status:403,log,msg:'Injection XSS sur q'"

## Bonnes pratiques

- Une règle = une campagne ; `msg` explicite et signature du cluster en commentaire.
- Tester d'abord en détection (`pass,log` au lieu de `deny`) si l'effet de bord est incertain.
- Une règle ModSecurity ne compte pas les requêtes : pour un débit, utiliser la limitation de BunkerWeb.
