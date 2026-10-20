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
`remediation_succeeded` apparaît (http://127.0.0.1:18090/events ou panneau « Journal du moteur »).
**Si la remédiation échoue** (`remediation_failed`, alerte `RemediationFailed`) :
1. Logs du service : Grafana → Explore → Loki → `{service="payment-api"}`.
2. `docker compose ps` pour l'état, `docker compose logs --tail 100 <service>`.
3. Reconstruction : `.\scripts\ops.ps1 recover`.

## PROC-05 — Attaque applicative (XSS / SQLi) détectée par le WAF
**Symptômes** : alertes `XssAttackDetected` / `WafAttackBlocked` / `WazuhXssDetected` dans Grafana ; **Wazuh** : règles 100101
(XSS), 100102 (SQLi), 100103 (campagne) ; panneau « Sécurité » de Grafana en hausse.
**Réponse automatique** : BunkerWeb (ModSecurity + OWASP CRS v4) bloque les requêtes (HTTP 403).
**Investigation** :
1. Grafana → section **SIEM Wazuh** (ou Explore/Loki) : `{service="wazuh"} | json | rule_id=~"100101|100102"`.
2. Loki/Grafana : `{service="bunkerweb"} |= "ModSecurity: Access denied"` (IP source, URI, règle CRS).
3. Vérifier qu'aucune charge n'a abouti (2xx) : `{service="bunkerweb"} |~ "attack-xss|attack-sqli"`.
   Si une requête malveillante a reçu un 2xx → traiter comme une **compromission** (PROC-07).

## PROC-06 — Déni de service / flood (DDoS)
**Symptômes** : alerte Loki `RequestFlood` + `WafAutoBan` ; **Wazuh** règle DDoS (100112) ;
réponses HTTP 429 puis 403 dans les logs BunkerWeb ; panneau « Requêtes/s reçues par le WAF ».
**Réponse automatique** : BunkerWeb **limite le débit** (429) puis **bannit automatiquement** l'IP
« bad behavior » (403, 5 min) ; les limites mémoire/CPU des conteneurs évitent la contagion. La
**transaction synthétique interne reste verte** : le service tient. Si un service tombe, PROC-04.
**Investigation** : `{service="bunkerweb"} |~ "is banned|BADBEHAVIOR"` (IP bannies).
**Ajustement** : `WAF_API_RATE`, `WAF_BADBEHAVIOR_THRESHOLD`, `WAF_BAN_TIME` dans `.env` puis `ops reload`.
**Rappel NAT** : en lab, le bannissement touche aussi les clients partageant l'IP NAT (voir INFRA §8).

## PROC-05bis — Lancer / rejouer la démo d'attaque
Depuis le **PC Attaquant** (voir `attack/README.md`) :
```bash
DEMO_PASSWORD=<mdp alice> ./attack/run_demo.sh http://192.168.137.1
```
Démo « avant/après » du WAF : `WAF_RULE_ENGINE=DetectionOnly` dans `.env` + `ops reload` (les XSS
passent mais sont journalisées), puis `=On` + `ops reload` (les XSS sont bloquées).

## PROC-05ter — SIEM Wazuh : plus d'alertes dans Grafana
**Symptômes** : la section « SIEM Wazuh » du dashboard reste vide malgré une attaque.
1. État : `docker compose ps wazuh.manager wazuh-agent logshipper alloy`.
2. Agent inactif : `docker exec resilience-wazuh.manager-1 /var/ossec/bin/agent_control -l`.
3. Le forwarder écrit-il ? `docker logs resilience-logshipper-1`.
4. Le manager émet-il ? `docker exec resilience-wazuh.manager-1 /var/ossec/bin/wazuh-control status | grep csyslogd` (doit tourner).
5. Test d'une règle : `echo '<ligne de log>' | docker exec -i resilience-wazuh.manager-1 /var/ossec/bin/wazuh-logtest`.
6. Le SIEM est hors de la boucle de remédiation : son indisponibilité ne bloque pas le service métier.

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

## PROC-12 — Vault scellé ou indisponible
**Symptômes** : alerte `VaultDown` / `VaultSealed`, `http://127.0.0.1:18200` ne répond pas.
**Réponse automatique** : `VaultDown` → redémarrage par le moteur de remédiation ; le sidecar
`vault-unsealer` redescelle ensuite seul. Les services en cours **ne sont pas affectés** (ils lisent leurs Docker secrets).
**Si Vault reste scellé** : `docker logs resilience-vault-unsealer-1` puis `docker compose restart vault-unsealer`.
**Perte du dossier `secrets/`** : `.\scripts\ops.ps1 deploy` le reconstruit depuis Vault (les valeurs sont conservées).
**Perte du volume Vault** : les secrets sont régénérés au prochain `deploy` ; les mots de passe de la base ne
correspondent plus → `.\scripts\ops.ps1 recover -e wipe_data=true` (restaure ensuite depuis une sauvegarde).

## PROC-13 — Console BunkerWeb (voir et débannir une IP)
Console : http://127.0.0.1:17000 (utilisateur `admin`, mot de passe = `BW_UI_PASSWORD` dans `.env`).
- **Bannissements** : menu *Bans* — liste des IP bannies (bad behavior / DDoS) ; on peut en lever un avant son expiration (5 min par défaut).
- **Instances** : menu *Instances* — état de l'instance WAF (UP/DOWN).
- Les réglages (débit, seuils, ModSecurity) viennent du `docker-compose.yml` / `.env` : les modifier dans la console serait écrasé au prochain `ops deploy`.
