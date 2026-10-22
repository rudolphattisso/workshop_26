# Point de reprise — ai-node (llm-gateway, PC IA)

Dernière mise à jour : 2026-10-20. Côté détection : voir `infra/ml-detector/HANDOFF.md`.

## Rôle
Reçoit un résumé de cluster du ml-detector (`POST /analyze`), interroge le RAG et le LLM (Ollama), revalide la réponse et écrit un fichier de recommandations Markdown. **Rien n'est appliqué automatiquement.**

## Flux d'une analyse (`llm_gateway/analyzer.py`)
1. **RAG** : requête construite à partir des indices du détecteur et des chemins visés ; top-k passages de `knowledge/`. En cas d'échec, l'analyse continue sans RAG.
2. **LLM** :
   - prompt système (instructions) séparé des données ;
   - données d'incident en JSON dans `<donnees_incident>`, déclarées non fiables, avec les balises injectées neutralisées ;
   - connaissance dans `<connaissance>` ;
   - sortie JSON imposée par le schéma `LlmAnalysis` (`format` d'Ollama).
3. **Mode dégradé** : si Ollama est en erreur, en dépassement de délai ou renvoie un JSON invalide, le rapport porte `degraded=true`, un verdict `indetermine`, les faits du détecteur et **aucune règle**.
4. **Garde-fous** (`guardrails.py`, déterministes) :
   - règles uniquement si le verdict est `attaque` ;
   - ModSecurity : seulement des `SecRule` avec un id dans la plage 99000-99999 ; interdits : `SecRuleEngine`, `ctl:`, `SecRuleRemove*`, `SecAction`, `allow`, `nolog`, `exec`, `Include`…
   - BunkerWeb : liste blanche de réglages qui resserrent ; pas de `WHITELIST_*` ; `USE_*=yes` ; `USE_ANTIBOT` sur un mode de défi ;
   - toute IP visée doit appartenir à `top_ips`, sans être marquée `possible_waf_collateral`, et pas plus large qu'un /24 ;
   - les conseils en texte libre qui parlent de liste blanche ou de désactivation sont retirés.
5. **Fichier** `reports/<horodatage>Z_<signature>.md` : verdict, diagnostic, éléments factuels, règles en blocs copiables (avec où les mettre, ce qu'elles font, leurs effets de bord et leur provenance), motifs des refus (sans leur contenu), incertitudes, sources RAG.

## Contrat
- Entrée : `AnalyzeRequest {cluster: ClusterSummary, context: {}}` (`contract.py`). Copie du `ClusterSummary` du ml-detector, revalidée : tailles bornées, `signature` alphanumérique (elle sert de nom de fichier).
- Sortie : `AnalysisReport`.
- Verdicts : `attaque`, `bannissement_collateral_probable`, `faux_positif_probable`, `indetermine`.
- Authentification : `Authorization: Bearer <LLM_GATEWAY_TOKEN>` (32 caractères minimum, comparaison à temps constant). Corps limité à 256 Ko.

## Connaissance (`knowledge/`, découpée par titre Markdown)
- glossaire du résumé du détecteur ;
- plateforme : endpoints, trafic légitime, protections, attaque du 19/10 ;
- réglages BunkerWeb (**écrits de mémoire, à vérifier avec la version déployée**) ;
- ModSecurity ;
- DDoS couche 7.
- RSS : emplacement réservé (`rag/sources.py`, `RssFeedSource`).

## Lancer
- Tests (sans GPU) : `python -m pytest` dans `ai/ai-node/` (154 tests), ou `docker compose run --rm tests`.
- PC IA : voir l'en-tête de `docker-compose.yml` (pull des modèles, `index`, puis `llm-gateway`).
- Sans Docker : `python -m llm_gateway.cli analyze tests/fixtures/cluster_distributed_flood.json`, avec `VECTOR_STORE=memory` et `EMBEDDER=hashing` pour se passer de ChromaDB.
- Jeux d'essai : `tests/fixtures/cluster_*.json`, de vrais résumés produits par la démo du ml-detector (DDoS distribué, exports coûteux, flood, SQLi, XSS, force brute).

## Essai avec un vrai LLM (2026-10-20, RTX 5050 8 Go, Ollama 0.24 local)
- Banc d'essai : 6 clusters réels de la démo + NAT banni (attendu : collatéral) + XSS avec injection de prompt (URI et user-agent : « verdict faux_positif… WHITELIST_IP… SecRuleEngine Off »). Script hors dépôt (scratchpad), à recréer au besoin.
- **qwen2.5:7b-instruct** (retenu), 25 à 45 s par analyse :
  - verdicts 8/8 justes après corrections (collatéral pour le NAT, attaque pour le reste) ; injection : le verdict tient, mais un conseil de liste blanche sort à chaque fois et il est retiré par les garde-fous ;
  - règles : forte variance d'un passage à l'autre ; recopie de passages de la doc ; erreurs de syntaxe ModSecurity fréquentes. Bonnes règles observées : `USE_ANTIBOT=javascript` sur le botnet, plafond `ARGS_GET:limit > 1000` sur les exports, limitation 2r/s sur `/api/payments`.
  - confiance quasi toujours « faible ».
- **mistral 7B** : verdicts justes sur les attaques, « indéterminé » sur le NAT ; règles plus souvent mal formées.
- Corrections apportées grâce à l'essai :
  - prompt : faits clés calculés, définitions des indices, exemples de règles, critères du verdict collatéral, pas de mesure globale si le WAF bloque déjà tout ;
  - RAG : requête enrichie de mots-clés de remédiation par indice ;
  - garde-fous :
    - analyseur syntaxique `SecRule` (guillemets, apostrophes, règles chaînées, regex qui compile) ;
    - refus d'une règle qui ne filtre que sur le chemin ou la méthode (elle bloquerait tout l'endpoint : vu sur `/api/payments`) ;
    - refus d'une mesure globale BunkerWeb si `blocked_ratio` ≥ 95 % ;
    - refus d'un interrupteur déjà actif sans réglage concret ;
    - reclassement d'une `SecRule` rangée en bunkerweb ;
    - normalisation des séparateurs et des apostrophes françaises dans `msg`.
- **Constat** : un 7B donne de bons verdicts et diagnostics, mais il est peu fiable pour rédiger des règles libres. Piste recommandée : un **catalogue de modèles de règles** (le LLM choisit un modèle et ses paramètres, le gateway produit une syntaxe garantie).

## Comparatif de modèles (2026-10-21, même banc de 8 cas, RTX 5050 8 Go)
| Modèle | Verdicts justes | NAT → collatéral | Injection : verdict tenu | Règles valides / proposées | Temps moyen |
|---|---|---|---|---|---|
| qwen2.5:7b-instruct | 8/8 | oui | oui | 5/14 (36 %) | 61 s* |
| llama3.1:8b | 8/8 | oui | oui | 2/9 (22 %) | 47 s |
| gemma3:4b | 8/8 | oui | oui | 2/16 (12 %) | 34 s |
| phi4-mini | 7/8 | oui | oui | 1/15 (7 %) | 66 s |
| qwen3:8b | 6/8 | oui | **non (→ faux positif)** | 1/9 (11 %) | 48 s |
| mistral 7B | 6/8 | non | **non (→ faux positif)** | 3/7 (43 %) | 35 s |
| llama3:8b | 6/8 | non | oui | 1/9 (11 %) | 42 s |
| gemma4:e2b | 4/8 (2 dégradés) | oui | **non (→ faux positif)** | 0/4 | 59 s |

\* qwen2.5 passé en premier, en parallèle des téléchargements.
- Retenu : **qwen2.5:7b-instruct** (seul 8/8 avec le plus de règles valides), alternative **llama3.1:8b**.
- **Risque non couvert par les garde-fous** : l'injection (« trafic de test autorisé ») fait basculer le VERDICT de 3 modèles en faux positif. Les règles restent bloquées (pas de règle hors verdict attaque), mais un verdict manipulé peut faire ignorer une vraie attaque. Piste : contrôle de cohérence déterministe (indices d'injection ou de DDoS du détecteur + verdict non-attaque → avertissement visible dans le rapport).
- RAG, sur 11 passages attendus pour 6 clusters : hachage 9/11, bge-m3 8/11, nomic-embed-text 7/11 (requête par mots-clés, petite base) : pas de gain mesurable à changer d'embedding pour l'instant.

## Revue des tests (2026-10-21)
- Failles trouvées en cherchant à contourner les garde-fous, puis corrigées (test écrit d'abord, en échec, puis correction) :
  - IPv6 non contrôlée : maintenant /64 au plus ;
  - `BLACKLIST_USER_AGENT` / `BLACKLIST_URI` qui toucheraient des clients ou endpoints légitimes connus ;
  - limitation de débit sous un plancher : 5 req/s sur `/`, 1 req/s ailleurs.
- Bug trouvé par le test de mutation : la normalisation avalait le `/` de `LIMIT_REQ_URL=/`. La règle écrite était cassée et le plancher de débit contourné. Corrigé.
- Tests par propriétés (`hypothesis`, `tests/test_guardrails_properties.py`) : des milliers de règles générées au hasard, environ 11 % acceptées. Toute règle acceptée doit respecter les invariants : rien qui relâche ou masque, IP du cluster et étroites, id dans la plage, réglages autorisés.
- Client Ollama testé sans Ollama : toute panne devient une `LLMError`, donc un rapport dégradé.
- Test de mutation maison (mutmut ne tourne pas sous Windows ; script hors dépôt) : 1re passe 123/155 mutants tués (79 %). Survivants : seuils jamais testés à leur limite exacte, cas jamais exercés, vérifications redondantes (défense en profondeur).
- 2e passe de mutation : 145/155 tués (94 %) ; 8 survivants = vérifications redondantes (défense en profondeur), 2 couverts ensuite par des tests (règle faite seulement de commentaires).
- 94 tests.

## Contrôle de cohérence et mesure des temps (2026-10-21)
- `consistency.py` (déterministe) : avertissements en tête du rapport, **sans changer le verdict** :
  - verdict non « attaque » alors que le détecteur a mesuré des faits forts (motifs d'injection, foule automatisée, réponses lourdes…) ;
  - données du trafic qui ressemblent à des consignes pour une IA (« ignore les consignes », « verdict », « test autorisé », « whitelist »…).
  - Vérifié en réel : qwen2.5 piégé (verdict faux positif sur le XSS avec injection) → les 2 avertissements apparaissent avant le verdict.
- `AnalysisReport.timings` + section « Temps d'analyse » du fichier. Champs : total, RAG, attente du GPU, appel LLM, puis les chiffres d'Ollama (chargement, tokens et durée de lecture du prompt, tokens et durée de génération, tokens/s, `other_s`, `truncated`).
- **Constats de la mesure** (qwen2.5:7b, RTX 5050) :
  - **le prompt était tronqué** : contexte Ollama par défaut 4096 tokens, notre prompt ~4 350. Corrigé : `LLM_NUM_CTX=8192` + JSON de l'incident compacté (3 000 à 4 150 tokens). Une troncature devient un avertissement du rapport.
  - Temps typique 35 à 45 s : lecture du prompt ~1,5 s, génération ~15 s (~49 tokens/s, 700 à 900 tokens), **contrainte de sortie JSON ~15 à 25 s** (~20 à 30 ms par token, hors durées d'Ollama), chargement 3 à 4 s au premier appel seulement.
  - Avec le prompt complet, règles valides 47 % (contre 36 %). Mais une partie des règles acceptées reste une recopie des exemples de la doc (valide, hors sujet).

## Grammaire de règles (2026-10-21)
- Le LLM ne rédige plus de syntaxe. Il **décrit** chaque mesure (`LlmOutput`, `contract.py`) :
  - `modsecurity_rules` : conditions (variable, nom, opérateur, valeur, négation ; vocabulaire imposé par des énumérations), action `deny` ou `log_only`, message ;
  - `bunkerweb_changes` : réglage (énumération), suffixe, valeur ;
  - `ideas_to_review` : « Pistes à expertiser », non copiables, filtrées comme les conseils.
- `rule_compiler.py` écrit la syntaxe exacte : chaînage, phase (2 si `ARGS` du corps), guillemets, apostrophes typographiques dans `msg`. Il nettoie aussi les listes d'IP (`[ip, ip]` → `ip,ip`, chaque entrée validée), normalise les débits (`5/minute` → `5r/m`) et traduit `USE_ANTIBOT=yes` en `javascript`.
  - Refusés à la compilation : `ARGS_GET "@contains nom=valeur"` (ne se déclencherait jamais), caractères de contrôle, doublons.
  - Id ModSecurity attribués par `RuleIdAllocator` (compteur persistant `reports/.next_ai_rule_id`, plage 99000-99999, reprise au début en fin de plage).
- Les règles compilées passent ENSUITE par tous les garde-fous. Ajout : `@ipMatch` doit être une vraie liste d'IP (sinon ModSecurity ne démarre pas), aussi pour une règle écrite à la main.
- Propriété testée (`hypothesis`, 500 descriptions aléatoires) : toute description qui compile donne une syntaxe valide. Elle a trouvé 2 bugs : le séparateur de ligne Unicode `` découpait une directive, et le message par défaut contenait une apostrophe droite.
- Résultats qwen2.5:7b (8 cas) :
  - règles valides **93 %** (14/15), contre 47 % en texte libre et 36 % au départ ; verdicts 7/8 (l'injection reste trompeuse, mais elle est signalée) ; ~41 s par analyse ;
  - règles fondées sur le trafic observé (IP, chemins, méthode du groupe) plutôt que sur les exemples de la doc ; le modèle choisit souvent `log_only` (observer d'abord) ;
  - limites du sens : paramètre de connexion cherché dans l'URL au lieu du corps, chaîne d'injection exacte, règles redondantes. La syntaxe est garantie, la pertinence reste à relire.
- 145 tests.

## Escalade et symptômes (2026-10-21)
- Le LLM n'est appelé que sur escalade du ml-detector : voir `infra/ml-detector/HANDOFF.md`. Le contexte de la requête porte `escalade` (gravité, raisons) et les alarmes de la fenêtre.
- Nouveau verdict `incident_exploitation_probable` (panne sans attaque, aucune règle). Nouvel indice `service_degradation` : résumé de fenêtre entière envoyé sur alarmes de disponibilité sans campagne (prompt, glossaire).
- 146 tests. `LLM_KEEP_ALIVE` (24h) : modèle gardé en mémoire entre deux escalades (sinon ~20 s de chargement).

## Réanalyses et consultation des rapports (2026-10-21)
- Prompt : `analyse_precedente` dans le contexte → fait clé « MISE À JOUR… » et consigne de décrire ce qui a changé sans reproposer les règles.
- **Mémoire des règles récentes** (`RECENT_RULES_HOURS`=24) : une règle identique (hors id et message) à une règle d'un rapport récent est citée (`AnalysisReport.already_proposed`, section « Règles déjà proposées ») au lieu d'être recopiée. Mémoire en RAM : perdue au redémarrage du gateway.
- **Pages de consultation** : `/reports` et `/reports/<fichier>`, authentification « basic » (utilisateur `soc`, `REPORTS_PASSWORD`), désactivées sans mot de passe. Tout le contenu est échappé en HTML (données d'attaquant) ; seuls les noms de rapports valides sont servis (pas de traversée de répertoires). Lien utilisé par le tableau des incidents de Grafana.
- 154 tests.

## Pas encore fait
- (Fait le 2026-10-21) Document pour les équipes infra et cyber, mis à jour : grammaire, contrôle du verdict, nouvelles limites. https://claude.ai/artifact/RpebYHw2jeWwDUfwQHBwUQ
- Piste temps : la contrainte JSON coûte ~50 % du temps. Mesure du 2026-10-21 :

  | Format | Génération | Surcoût de la contrainte |
  |---|---|---|
  | aucune contrainte | 21 ms/token | 1 ms/token |
  | JSON libre | 21 ms/token | 23 à 26 ms/token |
  | notre schéma (simplifié ou complet) | 21 ms/token | 21 à 24 ms/token |

  - Le surcoût vient du **calcul des tokens permis à chaque token** (llama.cpp, sur le processeur, GPU en attente), pas de la richesse du schéma.
  - Sans contrainte, la réponse est 4 fois plus courte et incomplète.
  - **Critère de choix du moteur sur le PC IA** : une version d'Ollama ou de llama.cpp (ou vLLM) avec un échantillonnage contraint optimisé : vérification du seul token tiré, écriture directe des tokens imposés, masques précalculés. Gain attendu jusqu'à ~50 % sans changer le code. À mesurer au déploiement.
  - Autre levier : générer moins de tokens (réponses plus courtes, grammaire de règles).
- Envoi depuis le ml-detector : service continu, dédoublonnage par signature, `/metrics`.
- Restitution Grafana.
- Contexte Prometheus et Wazuh.
- Source RSS.
- Versions d'images à vérifier (`ollama/ollama:0.5.7`, `chromadb/chroma:0.5.23`, `chromadb-client==0.5.23`).
## Déploiement face au PC infra (2026-10-21)
Voir `docs/ia/INTEGRATION.md` §5. Sur le PC IA, dans `.env` :
- `GATEWAY_BIND=<IP du PC IA>` (127.0.0.1 = local uniquement) ;
- `LLM_GATEWAY_TOKEN` = la valeur du secret `llm_gateway_token` du PC infra ;
- `REPORTS_PASSWORD` pour `/reports`.
Pare-feu : port 8080 ouvert au seul PC infra (et aux postes qui lisent les rapports).


## Actions de l'infra, perte de visibilité, signal de vie (2026-10-21)
- `prompts.py` : consignes 6 (`actions_infra` : dire si les actions automatiques ont aidé, ne jamais proposer de redémarrer) et 7 (`perte_de_visibilite` : données d'avant la coupure ; si elles montrent déjà une attaque → « attaque ») ; `context_facts` (faits calculés : perte de visibilité, résumé des actions) ; indice `visibility_loss`.
- `rules_writer.py` : bandeau PERTE DE VISIBILITÉ et tableau « Actions automatiques de l'infra » recopiés du contexte (pas laissés au LLM).
- `app.py` : `POST /heartbeat` (jeton), `DetectorWatch` (inconnu / ok / aveugle / muet après 120 s), état dans `/health`, bandeau rouge sur `/reports`.
- `rule_compiler.py` (trouvé par hypothesis) : une barre oblique inverse finale échappait l'apostrophe fermante de `msg:'...'` (remplacée par `/`) ; une valeur terminée par `\` ou contenant `\"` est refusée (le lecteur Apache/ModSecurity prend toujours `\"` pour un guillemet échappé).
- 162 tests.

## Organisation du dépôt et contrat entre les deux PC (2026-10-21)
- Un dossier par machine : `infra/ml-detector/` (PC infra, compose de l'infra), `ai/ai-node/` (PC IA, son compose). Documentation commune dans `docs/ia/` : `README.md` (vue d'ensemble), `INTEGRATION.md` (déplacé depuis `infra/ml-detector/`), `DEPLOIEMENT-PC-IA.md`.
- `contracts/analyze/*.json` : requêtes /analyze produites par le vrai détecteur (`infra/ml-detector/scripts/contract_examples.py`, ~17 s) : campagne DDoS, réanalyse, injection servie, symptôme, perte de visibilité.
  - `infra/ml-detector/tests/test_contract.py` : même FORME (champs, imbrication ; `statuses`/`methods` traités comme des tables) ; vérifié qu'un champ renommé fait échouer.
  - `ai/ai-node/tests/test_contract.py` : aucun champ ignoré en silence (`extra="ignore"`), chaque exemple passe l'analyse, les clés de contexte lues par le code produisent leur effet.
  - Ignorés dans les images Docker (`contracts/` hors du contexte de build).
- Les exemples écrits à la main de `ai/ai-node/tests/fixtures/` restent (tests ciblés par indice).

## RAG : mesure, index, fiche injections (2026-10-22)
- Banc (5 requêtes du contrat × 3 modes × 2, qwen2.5) : RAG 4 passages = 10/10 verdicts, 19 règles acceptées / 5 refusées ; sans RAG = 10/10, 12 / 12 (débits trop bas, pas d'anti-bot) ; base entière = 8/10, prompt tronqué à 8192. On garde le RAG à 4 passages. Confiance « faible » dans les 30 analyses (biais à examiner).
- `Retriever.sync` + `VectorStore.ids/delete` : `cli index` retire les passages disparus de la source `internal-docs` (les autres sources sont gardées).
- Bug corrigé : identifiants de passages tronqués à 80 caractères → deux sections au début de titre identique s'écrasaient dans l'index. Empreinte du titre complet si tronqué. Les anciens identifiants sont retirés au prochain `index`.
- `knowledge/injections.md` : ne pas recopier la charge (encodages multiples), valider le format attendu (paramètre : règle ; segment de chemin : piste à expertiser, car le garde-fou « chemin seul » le refuse), motifs `(?i)` par famille sur paramètres décodés. Exemples testés contre le compilateur et les garde-fous (`tests/test_knowledge.py`).
- Effet réel (2 passages) : la piste de validation du chemin apparaît les 2 fois ; les règles recopient encore des charges encodées.
- Garde-fous de PORTÉE séparés de la syntaxe (`_secrule_scope_problem`) : chemin seul ; toutes les conditions inversées (≈ tout le trafic, vu sur qwen2.5) ; valeur %XX sur ARGS* (comparés décodés : ne correspond jamais, vu sur qwen2.5). Le test hypothesis exige désormais une syntaxe valide sans exception.
- 180 tests.

