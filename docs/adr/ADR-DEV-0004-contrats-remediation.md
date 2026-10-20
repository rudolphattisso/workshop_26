# ADR-DEV-0004 — Moteur de remédiation : format d'alerte, playbooks et preuve de reprise

- **Statut** : accepté (la table des playbooks dépend encore du mode d'action sur les conteneurs, à arbitrer avec Infra et Cyber)
- **Date** : 2026-10-20
- **Domaine** : Dev
- **Contrats créés** : `contracts/alert.schema.json` (0.1.0), `contracts/openapi-remediation.yaml` (0.1.0)

## Contexte

Le moteur de remédiation est la pièce notée sur 5 : **toute intervention manuelle pendant la démo vaut 0**.
Il reçoit des alertes de trois domaines (IA, Infra via Prometheus, Cyber via WAF et SIEM), qui travaillent en
parallèle. Il faut donc figer tôt :

- le format d'alerte ;
- la façon dont une alerte devient une action ;
- ce qui prouve la reprise.

Rappel du sujet : « un conteneur qui redémarre » n'est pas une preuve de reprise.

## Décision

1. **Un seul format d'alerte** (`alert.schema.json`), strict (`additionalProperties: false`).
   - `incident_type` est une liste fermée de 6 valeurs.
   - L'émetteur **décrit** l'incident ; il ne **choisit jamais** l'action. Un champ « action » est refusé.
   - Le jeton d'alerte (`REMEDIATION_ALERT_TOKEN`) permet seulement de signaler : un émetteur compromis ne
     peut pas faire exécuter une commande arbitraire.
2. **Alertmanager est accepté dans son format natif** (`POST /alerts/alertmanager`). Les labels
   `incident_type`, `target` et `severity` sont posés dans la règle Prometheus. L'Infra n'a donc aucun
   traducteur à écrire.
3. **Table de décision explicite et versionnée** : un `incident_type` correspond à un playbook. Elle est publiée
   par `GET /playbooks` et documentée dans le contrat. Il n'y a ni logique cachée ni score caché : le jury
   peut lire la règle appliquée.
4. **Preuve de reprise en trois points**, tous obligatoires pour passer à `RESOLVED` :
   - `/ready` de payment-api et auth ;
   - une **nouvelle transaction fictive** via le smoke test ;
   - `GET /operations/consistency` renvoie `consistent: true`.
5. **Pas de boucle de remédiation** :
   - déduplication par `alert_id` ;
   - cooldown de 120 s par couple (`incident_type`, `target`) ;
   - 3 tentatives au plus, puis `ESCALATED`.
6. **Watchdog intégré** : le moteur sonde lui-même `/health` et `/ready` toutes les 5 s, et la cohérence toutes
   les 30 s. Il émet ses propres alertes (`source: watchdog`).
7. **Aucun endpoint d'action manuelle** : le dashboard est en lecture seule (`GET` + SSE), avec un JWT opérateur.
   Le flux SSE est lu avec `fetch()`, pour que le jeton ne finisse jamais dans une URL.

## Conséquences

- ✅ Les trois domaines producteurs peuvent développer et tester leur émission d'alertes dès maintenant,
  contre le schéma (validation JSON Schema), sans attendre le moteur.
- ✅ Le watchdog garantit qu'au moins le scénario « service tombé » se remédie, même si l'intégration
  ML / Prometheus n'est pas prête jeudi. C'est le scénario « 100 % fiable » à sécuriser en premier.
- ✅ Chaque étape est horodatée dans `steps`, ce qui donne une chronologie lisible sur le dashboard, le temps
  de reprise mesuré (`time_to_recover_seconds`) et des preuves pour le dossier.
- ⚠️ Plusieurs playbooks dépendent d'autres domaines :
  - redémarrer ou recréer un conteneur : mode d'action Docker, Infra + Cyber, **bloquant** ;
  - bloquer une IP : API du WAF, Cyber ;
  - restaurer la base : procédure de sauvegarde, Infra.
  Tant qu'une dépendance manque, le playbook concerné journalise l'action prévue sans l'exécuter, et l'incident
  passe en `ESCALATED`.
- ⚠️ Le cooldown de 120 s peut masquer une seconde attaque identique et rapprochée. C'est acceptable : une
  alerte rattachée reste visible dans l'incident, et la vérification de reprise porte sur l'état réel.

## Alternatives écartées

- **Laisser l'émetteur choisir l'action** (`"action": "restart"`) : c'est plus simple pour lui, mais un jeton
  d'alerte volé deviendrait un levier d'attaque (redémarrages en boucle = déni de service). Le moteur perdrait
  aussi son rôle de décision.
- **Décision par score / ML dans le moteur** : imprévisible en démo et difficile à expliquer au jury.
  Le ML détecte, la table décide.
- **Considérer « conteneur redémarré » comme une reprise** : explicitement refusé par le sujet.
- **Un endpoint « relancer la remédiation » sur le dashboard** : ce serait une intervention humaine, donc 0/5.
