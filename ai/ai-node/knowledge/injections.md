# Injections (SQL, XSS, traversée de chemin, commande) : écrire une règle qui tient

## Quand une règle est utile

Le CRS de BunkerWeb bloque déjà la plupart des injections connues. Une règle complémentaire ne se justifie que si des injections ont reçu une vraie réponse de l'application (`injections_answered` > 0 : ni refus du WAF, ni erreur 5xx). Si le WAF a tout bloqué (`blocked_ratio` proche de 100 %), il fait son travail : aucune règle, ou au plus un blocage des IP concernées.

## Ne jamais recopier la charge exacte

Une même injection arrive sous plusieurs écritures : `1;%20DROP%20TABLE`, `1%3B%20DROP%20TABLE`, `1;+drop+table`, majuscules ou minuscules. `REQUEST_URI` et `QUERY_STRING` sont comparés sous leur forme BRUTE, telle qu'envoyée (le CRS doit lui-même les décoder) : une règle « contient %20DROP%20TABLE » laisse passer toutes les autres écritures. Les règles proposées ne peuvent pas ajouter de transformation (décodage, minuscules) : il faut une forme de règle qui ne dépend pas de l'encodage.

## Méthode 1 (préférée) : valider le format attendu

Quand un paramètre ou un segment de chemin a un format connu, refuser tout ce qui n'a pas ce format. Ça arrête toutes les injections sur ce point d'entrée, quelle que soit leur écriture, sans connaître la charge.

- `/api/payments/{uuid}` : après `/api/payments/`, seul un identifiant (chiffres hexadécimaux et tirets) ou `ready` est légitime.
- `limit` sur `/api/payments` : un nombre entier (le front n'envoie jamais plus de 100).

Pour un PARAMÈTRE : une règle (chemin concerné + paramètre avec `negate`, « ne correspond PAS », et une expression régulière ancrée par `^` et `$`). Pour un SEGMENT DE CHEMIN (injection dans `/api/payments/...`) : la proposer dans `ideas_to_review` avec l'expression suggérée, car une expression fausse bloquerait tout l'endpoint ; un expert la vérifie sur le trafic légitime.

## Méthode 2 : un motif, sur un paramètre décodé

Les valeurs de `ARGS_GET:nom` et `ARGS:nom` sont DÉCODÉES par ModSecurity : un motif y voit `;` et `'` quelle que soit l'écriture d'origine. Utiliser une expression régulière insensible à la casse `(?i)` qui décrit la FAMILLE d'attaque, pas une charge :

- SQL : `(?i)(union[ +]+select|;[ +]*drop[ +]+table|'[ +]*or[ +]+'?1'?[ +]*=)`
- XSS : `(?i)(<[ +]*script|javascript:|on(error|load)[ +]*=)`
- Traversée de chemin : `[.][.]/`
- Commande : `(?i)(;|[|]|&&)[ +]*(cat|wget|curl|nc|bash|sh)[ +]`

Effet de bord : un champ de recherche libre peut contenir légitimement des apostrophes ou des mots comme « select ». Viser le paramètre précis, sur le chemin précis.

## Exemples

Les identifiants sont fictifs. Adapter le chemin et le paramètre à ceux observés dans le groupe analysé.

Piste à expertiser (segment de chemin) : « refuser après /api/payments/ tout ce qui ne correspond pas à `^/api/payments/([0-9a-fA-F-]{1,36}|ready)$` ».

    # Format attendu : limit entier sur la liste des paiements
    SecRule REQUEST_FILENAME "@streq /api/payments" "id:99011,phase:1,deny,status:403,log,msg:'Paramètre limit non numérique',chain"
        SecRule ARGS_GET:limit "!@rx ^[0-9]{1,4}$"

    # Motif d'injection SQL sur un paramètre décodé
    SecRule REQUEST_FILENAME "@streq /api/payments" "id:99012,phase:1,deny,status:403,log,msg:'Injection SQL sur id',chain"
        SecRule ARGS_GET:id "@rx (?i)(union[ +]+select|;[ +]*drop[ +]+table)"
