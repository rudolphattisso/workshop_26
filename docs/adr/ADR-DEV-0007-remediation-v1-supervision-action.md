# ADR-DEV-0007 — Remédiation v1 : supervision (`remediation`) et action (`auto-recovery`) séparées

- **Statut** : accepté
- **Date** : 2026-10-22
- **Domaine** : Dev (avec Infra)
- **Amende** : ADR-DEV-0004 (moteur unique qui reçoit, décide, agit et vérifie) et ADR-DEV-0006 (le watchdog devait
  déclencher les remédiations)
- **Contrats modifiés** : `openapi-remediation.yaml` (0.4.0)

## Contexte

Le merge `infrastructure` → `develop` (21/10, commits `a0f8c31` et `8affbc2`) a réuni deux implémentations du même
rôle :

- **`services/remediation`** (Dev) : watchdog de topologie et API du dashboard (`/services`, `/events` en SSE). Il
  **n'agit pas** : il n'a ni le secret `remediation_token` ni le réseau `control` du docker-proxy.
- **Moteur de référence de l'Infra**, renommé `auto-recovery` : il reçoit le webhook Alertmanager, redémarre la cible
  via le docker-proxy et attend une transaction de preuve (`txprobe /check`). Arman l'a vérifié de bout en bout
  (paiement `CAPTURED`).

Le contrat 0.3.0 décrivait un seul service `remediation` avec `/alerts`, `/incidents` et `/playbooks`. Aucun de ces
endpoints n'existe. Le gel du code a lieu le 22/10 à 17h.

## Décision

1. **Pour la démo, deux services se partagent le rôle** :
   - `remediation` **surveille** et alimente le dashboard ;
   - `auto-recovery` **agit** sur les alertes Alertmanager.
2. **Le contrat dit la vérité** : version 0.4.0, avec un tableau « état de l'implémentation » et un `servers` par
   service. `/alerts`, `/incidents` et `/playbooks` sont marqués `x-implementation: v2`. Le comportement réel du
   webhook est décrit à côté de la cible.
3. **Aucun code modifié avant le gel** : on garde la chaîne déjà vérifiée plutôt que d'en réécrire une le dernier jour.
4. **Noms des composants de la topologie** : `auth-db` et `payment-db` désignent le service Compose `postgres`, et
   `smoke-test` désigne `txprobe`. La correspondance est écrite dans le contrat ; le code reste tel quel.

## Conséquences

- **+** La démo repose sur une chaîne testée : Prometheus → Alertmanager → `auto-recovery` → restart →
  `txprobe /check` OK. Aucune intervention humaine.
- **+** Le jury voit un écart **assumé et documenté**, pas un contrat qui promet des endpoints absents.
- **+** Le module IA n'est pas bloqué : il ne remédie pas (`docs/ia/INTEGRATION.md`) et n'a pas besoin de `/alerts`.
- **−** Le dashboard ne montre pas les remédiations : elles sont dans `GET /events` d'`auto-recovery`, dans Loki
  (`{service="auto-recovery"}`) et dans Grafana. Pendant la démo, il faut montrer le dashboard **et** Grafana.
- **−** La preuve de reprise v1 ne contrôle que la transaction (`txprobe /check`), sans `/ready` ni cohérence
  séparées. La transaction de bout en bout couvre déjà le critère « API joignable + transaction OK ».
- **−** L'action est lue dans le label `remediation` de l'alerte. Le risque est limité : seule `restart` existe, la
  cible est confrontée à une liste blanche et le jeton n'est partagé qu'avec Alertmanager.
- **−** `services/auto-recovery/` est dans le dossier Dev mais c'est du code Infra : il faut décider qui le maintient.

## Alternatives écartées

- **Implémenter `/alerts` + playbooks dans `remediation` avant 17h** : trop risqué. Il faudrait des réseaux et
  secrets Compose côté Infra, et la nouvelle chaîne ne serait pas répétée.
- **Laisser le contrat 0.3.0 inchangé** : il décrit des endpoints introuvables, ce qui est indéfendable devant le jury
  et piège les autres domaines.

## Suite (v2)

Fusionner les deux services : le watchdog de `remediation` envoie ses alertes (`source: watchdog`) au moteur, qui
expose `Incident` et `Playbook` et pousse les événements `incident` sur le SSE du dashboard.
