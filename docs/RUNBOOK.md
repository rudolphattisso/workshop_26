# Runbook d'exploitation — Resilience-Alpha

Procédures opérateur. Chaque procédure indique **quand** l'appliquer, **quoi** lancer et
**comment vérifier**. Ce document est aussi indexé par l'assistant RAG des opérateurs.

Toutes les commandes se lancent depuis la racine du dépôt sur le PC Hôte
(`scripts\ops.ps1` sous Windows, `scripts/ops.sh` sous Linux/WSL).

---

## PROC-01 — Installer la plateforme sur un PC Hôte vierge
**Quand** : première installation, changement de PC, démo sur une autre machine.
1. Installer Docker Desktop (backend WSL2), le démarrer ; Paramètres → Resources : ≥ 6 Go RAM.
2. Récupérer le dépôt (clone Git ou archive `Workshop2026-M2-G<n>-Code.zip`).
3. `.\scripts\ops.ps1 deploy`
4. **Vérification** : le playbook se termine par le bloc « Vérif | Rapport » sans erreur.
5. Ouvrir http://127.0.0.1:3000 → dashboard *Resilience-Alpha — Vue d'ensemble* : tout est vert.

## PROC-02 — Préparer la démonstration (J-0)
1. Activer le point d'accès mobile Windows (`RESILIENCE-G<n>`), noter l'IP (192.168.137.1).
2. Optionnel : dans `.env`, `PUBLIC_BIND_ADDR=192.168.137.1` pour ne publier le WAF que sur le hotspot,
   puis `.\scripts\ops.ps1 deploy`.
3. Autoriser le port 80 entrant dans le pare-feu Windows (profil du hotspot uniquement).
4. `.\scripts\ops.ps1 backup` — sauvegarde de référence saine.
5. `.\scripts\ops.ps1 verify` — doit être entièrement vert.
6. Depuis le PC Attaquant : `curl http://192.168.137.1/healthz` → `ok`.
7. Répétition : `.\scripts\ops.ps1 chaos` → noter le temps de reprise affiché.

## PROC-03 — Relancer après un redémarrage du PC
Les conteneurs ont `restart: unless-stopped` : ils redémarrent avec Docker Desktop.
1. Démarrer Docker Desktop, attendre « Engine running ».
2. `.\scripts\ops.ps1 verify`. En cas d'échec : `.\scripts\ops.ps1 deploy` (idempotent).

## PROC-04 — Un service métier est indisponible
**Symptômes** : alerte `PaymentApiUnavailable`, `AuthUnavailable`, `FrontendUnavailable`, `WafDown`
ou `PostgresDown` ; panneau « Transaction synthétique » rouge.
**Réponse automatique** : le moteur de remédiation redémarre le service visé (liste blanche),
puis attend une transaction synthétique réussie. Rien à faire si l'événement
`remediation_succeeded` apparaît (http://127.0.0.1:8090/events ou panneau « Journal du moteur »).
**Si la remédiation échoue** (`remediation_failed`, alerte `RemediationFailed`) :
1. Logs du service : Grafana → Explore → Loki → `{service="payment-api"}`.
2. `docker compose ps` pour l'état, `docker compose logs --tail 100 <service>`.
3. Reconstruction : `.\scripts\ops.ps1 recover`.

## PROC-05 — Attaque applicative détectée par le WAF
**Symptômes** : alerte `WafAttackBurst`, panneau « Détections WAF » en hausse,
logs `{service="waf"} |= "ModSecurity"`.
**Réponse automatique** : les requêtes malveillantes sont bloquées (HTTP 403) par l'OWASP CRS.
**Investigation** :
1. IP source : `{service="waf"} | json | status = 403` dans Loki.
2. Vérifier qu'aucune requête malveillante n'a obtenu de 2xx :
   `{service="waf"} | json | status < 400 |~ "(?i)(union|select|<script|\\.\\./)"`.
3. Si une requête a abouti → traiter comme une **compromission** (PROC-07).

## PROC-06 — Déni de service / flood
**Symptômes** : alerte `RequestFlood`, latence p95 en hausse, réponses HTTP 429 dans les logs WAF.
**Réponse automatique** : limitation de débit par IP au WAF (API 20 r/s, login 5 r/s) ; limites
mémoire/CPU des conteneurs pour qu'un service saturé n'entraîne pas les autres ; si un service ne
répond plus, PROC-04 s'applique.
**Ajustement** : abaisser `WAF_API_RATE` dans `.env` puis `.\scripts\ops.ps1 deploy`.

## PROC-07 — Compromission suspectée (conteneur ou données altérés)
Un redémarrage **ne suffit pas** : il faut repartir d'un état sain connu.
1. Si possible, conserver les preuves : `docker compose logs > incident-<date>.log`
   (les logs restent aussi dans Loki 7 jours).
2. Conteneurs seuls suspects : `.\scripts\ops.ps1 recover -e no_cache=true`
   (images reconstruites depuis les sources, conteneurs recréés, données conservées).
3. Données suspectes : `.\scripts\ops.ps1 recover -e wipe_data=true -e restore_file=<dump antérieur à l'incident>`
   (volume détruit, base restaurée depuis la sauvegarde choisie, intégrité SHA-256 vérifiée).
4. Secrets potentiellement exposés : supprimer les fichiers concernés dans `secrets\`, puis
   `.\scripts\ops.ps1 recover -e wipe_data=true` (les secrets manquants sont régénérés).
5. **Vérification** : le playbook se termine par une transaction E2E réussie et affiche le RTO mesuré.

## PROC-08 — Sauvegarder / restaurer la base
- Sauvegarde : `.\scripts\ops.ps1 backup` → `backups\payments-<horodatage>.dump` + `.sha256`
  (10 dernières conservées).
- Restauration de la dernière : `.\scripts\ops.ps1 restore`.
- Restauration d'une sauvegarde précise : `.\scripts\ops.ps1 restore -e restore_file=payments-20261021T090000Z.dump`.
- Pendant la restauration, un **silence Alertmanager** est posé pour que la remédiation
  automatique ne redémarre pas les services volontairement arrêtés ; il est levé à la fin.
- Perte de données maximale (RPO) = temps écoulé depuis la dernière sauvegarde.

## PROC-09 — Tester la résilience (recette, chaos engineering)
`.\scripts\ops.ps1 chaos -e target=<waf|frontend|auth|payment-api|postgres> -e fault=<stop|kill>`
Le playbook vérifie l'état initial, injecte la panne, mesure le délai de **détection** et de
**reprise vérifiée**, refait une transaction E2E et écrit un rapport JSON dans `reports\`.

## PROC-10 — Modifier une règle d'alerte ou un dashboard
1. Éditer `infra/prometheus/rules/alerts.yml`, `infra/loki/rules/fake/security.yml`,
   `infra/alertmanager/alertmanager.yml` ou `infra/grafana/dashboards/*.json`.
2. `.\scripts\ops.ps1 reload` (valide avec promtool/amtool avant de recharger).

## PROC-11 — Arrêter la plateforme
- Arrêt en conservant les données : `.\scripts\ops.ps1 teardown`
- Remise à zéro complète : `.\scripts\ops.ps1 teardown -e purge=true`

---

## Annexe — Objectifs de reprise du démonstrateur

| Scénario | Mécanisme | RTO visé | RPO |
|---|---|---|---|
| Service métier arrêté / planté | remédiation automatique | < 60 s | 0 (base intacte) |
| Base de données arrêtée | remédiation automatique | < 60 s | 0 (WAL PostgreSQL) |
| Conteneur compromis | `recover` (Ansible) | < 5 min | 0 |
| Données corrompues / chiffrées | `recover -e wipe_data=true` | < 5 min | dernière sauvegarde |
| Perte du PC Hôte | PROC-01 sur un autre PC + restauration d'une sauvegarde copiée | < 30 min | dernière sauvegarde copiée hors du PC |

Les durées réellement mesurées sont dans `reports\` (playbook `chaos`) et dans la sortie de `recover`.
