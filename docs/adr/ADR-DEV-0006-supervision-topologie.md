# ADR-DEV-0006 — Supervision : watchdog de topologie et dashboard temps réel

- **Statut** : accepté
- **Date** : 2026-10-21
- **Domaine** : Dev
- **Contrats modifiés** : `openapi-remediation.yaml` (0.3.0 : schéma `Topology`), `service-conventions.md` (0.4 : `info`, vérifications parallèles)

## Contexte

Le dashboard doit montrer au minimum **l'état de chaque service** (healthcheck) et **l'état des connexions** entre les
services. Le navigateur ne peut pas sonder lui-même les services, et ne doit pas pouvoir le faire : `/health`, `/ready`
et les bases ne sont joignables que sur le réseau interne. Le moteur de remédiation, lui, doit de toute façon surveiller
la plateforme (watchdog, ADR-DEV-0004).

## Décision

1. **Le watchdog du moteur de remédiation mesure une topologie** toutes les 5 s : 7 composants et 7 connexions, toutes
   mesurées réellement, jamais déduites :
   - `/health` et `/ready` des services ;
   - `checks.database` et `info.auth_jwks` de leur `/ready` ;
   - des appels à travers le WAF ;
   - la dernière transaction du smoke test (`GET /last`, qui ne déclenche pas de paiement).

   La fonction `evaluate()` transforme ces mesures en états. Elle est pure, donc testable sans réseau.
2. **Quatre états** : `up`, `degraded` (vivant mais pas prêt : redémarrer ne servirait à rien), `down`, `unknown`. On
   affiche `unknown` quand on ne peut pas mesurer, par exemple une base dont le service est injoignable : jamais de
   « en panne » supposé.
3. **Dépendances informatives (`info`) dans `/ready`.** Une dépendance dont le service se passe un moment (payment-api
   sans l'auth, grâce aux clés en cache) est rapportée sans rendre le service « pas prêt ». Elle n'est pas publiée à
   travers le WAF.
4. **Vérifications de `/ready` en parallèle**, avec une limite globale de 2 s. Le watchdog, lui, attend 3,5 s. Si une
   dépendance pend, on reçoit quand même la réponse détaillée (« base : down ») au lieu d'un délai dépassé.
5. **Dashboard séparé du front client** (`services/dashboard`), réservé au rôle `operator`. Il reçoit la topologie par
   SSE lu avec `fetch()` (jeton dans l'en-tête, jamais dans l'URL), avec reconnexion automatique et indicateur « flux
   interrompu ».
6. **Le flux SSE compare un numéro de version** plutôt que de recevoir des événements poussés depuis le thread du
   watchdog : pas de file partagée entre threads, au plus 1 s de retard.

## Conséquences

- **+** Le dashboard est utilisable dès maintenant et la même mesure servira à déclencher les remédiations
  (watchdog → alerte `source: watchdog`).
- **+** Chaque changement d'état est journalisé : log JSON `component_state_changed`, métrique
  `remediation_component_up`, et journal du dashboard. C'est la matière du chronomètre de reprise.
- **+** Tester la topologie a révélé que les vérifications séquentielles de `/ready` faisaient perdre l'information
  « base en panne » (délai dépassé côté watchdog). C'est corrigé par le point 4.
- **−** Le dashboard n'est pas sur le réseau du WAF : il est publié sur `127.0.0.1` du PC Hôte (réseaux `mgmt` +
  `monitoring` côté Infra), et la démo se fait donc depuis le PC Hôte.

## Alternatives écartées

- **Graphe dans Grafana** : il ne montre pas les connexions applicatives (JWKS, base vue par le service), il ne connaît
  pas nos états `degraded` / `unknown`, et il ne servira pas au moteur de remédiation.
- **Sondes lancées par le navigateur** : elles imposeraient d'exposer les sondes internes, ce qui est contraire à la
  segmentation réseau.
