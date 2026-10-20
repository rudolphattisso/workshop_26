# PCA / PRA — Resilience-Alpha

> **Statut : brouillon technique, fondé sur l'infrastructure réellement construite et testée.**
> Ce document couvre ce que l'infra peut démontrer (scénarios, procédures, durées mesurées,
> risques résiduels constatés). Il NE COUVRE PAS l'analyse EBIOS RM, la hiérarchisation des
> services critiques par enjeu métier, ni la correspondance NIS2/DORA : ces parties relèvent de
> décisions du pôle Gouvernance que je ne peux pas inventer à la place de l'équipe. Les sections
> marquées **[À COMPLÉTER — Gouvernance]** attendent ce travail avant intégration au dossier final.

## 1. Objet et périmètre

Ce document décrit comment PROJECT RESILIENCE-ALPHA (plateforme de paiement fictive) continue
de fonctionner ou se rétablit après un incident, et dans quelles conditions une intervention
humaine reste nécessaire. Il s'appuie sur l'architecture décrite dans `docs/INFRA.md` et sur les
procédures opérationnelles de `docs/RUNBOOK.md`.

Environnement : un seul PC Hôte (Windows, Docker Desktop), 25 conteneurs, aucune redondance
matérielle. **Ceci est la limite structurante de tout ce document** : ce PCA/PRA traite la
continuité *applicative* sur une machine qui reste en vie, pas la continuité en cas de panne du
PC Hôte lui-même (couverte séparément, §5).

## 2. Services et leur rôle dans la continuité

| Service | Rôle | Catégorie |
|---|---|---|
| `bunkerweb` (WAF) | Point d'entrée unique, filtrage, chiffrement TLS | Critique — son indisponibilité coupe l'accès à tout le reste |
| `auth`, `payment-api` | Authentification et paiements fictifs | Critique — cœur du service métier |
| `postgres` | Données (comptes, transactions) | Critique — perte = perte de données |
| `vault` | Source de vérité des secrets | Critique — sans lui, aucun service ne peut (re)démarrer avec les bons mots de passe |
| `remediation`, `docker-proxy` | Détection → décision → action automatique | Important — leur panne désactive la reprise automatique, pas le service lui-même |
| `prometheus`, `alertmanager`, `loki`, `grafana`, `wazuh.*` | Observation et alerte | Important pour la détection, pas pour le service rendu |
| `frontend`, `txprobe`, console BunkerWeb, Wazuh-agent | Secondaires | Leur panne ne coupe pas le paiement |

**[À COMPLÉTER — Gouvernance]** : cette hiérarchisation technique devrait être confrontée à une
analyse d'impact métier (combien coûte une minute d'indisponibilité de `payment-api` ? de `auth` ?)
issue de l'EBIOS RM, qui peut la nuancer ou la confirmer.

## 3. Scénarios couverts

| # | Scénario | Déclenchement possible | Mécanisme de reprise | Humain requis ? |
|---|---|---|---|---|
| S1 | Un service applicatif plante ou est arrêté (`auth`, `payment-api`, `frontend`, `bunkerweb`) | Bug, ressource épuisée, DDoS qui sature le WAF | Détection (Prometheus, ≤ 10 s) → redémarrage automatique → vérification par transaction réelle | Non |
| S2 | Vault devient indisponible | Plantage, redémarrage Docker Desktop | Détection → redémarrage automatique ; le sidecar `vault-unsealer` le redescelle seul | Non |
| S3 | Attaque applicative (XSS, injection SQL) | PC Attaquant, via le WAF | Bloquée en amont (403) par ModSecurity/OWASP CRS ; aucune reprise à faire | Non (rien n'est jamais indisponible) |
| S4 | DDoS distribué | PC Attaquant (volumétrie) | Limitation de débit + bannissement automatique de l'IP source ; si le WAF est tout de même saturé : S1 s'applique | Non |
| S5 | Compromission (conteneur altéré, données corrompues) | Faille exploitée, erreur humaine | **PRA** : reconstruction des images + option de restauration depuis une sauvegarde antérieure | Oui — décision de déclencher le PRA |
| S6 | Perte du dossier de secrets (`./secrets/`) | Erreur humaine, disque corrompu | Reconstruit automatiquement depuis Vault au prochain déploiement | Non, si Vault est intact |
| S7 | Perte du volume Vault (secrets ET clés de descellement) | Panne disque, suppression accidentelle | Restauration depuis la sauvegarde Vault la plus récente | Oui — identifier et lancer la restauration |
| S8 | Perte du PC Hôte (machine entière) | Panne matérielle | Réinstallation sur un autre PC + restauration des sauvegardes copiées **hors** du PC Hôte | Oui — intégralement |

**Hors périmètre, explicitement** : panne réseau du campus, attaque contre une tierce partie,
perte simultanée du PC Hôte et de ses sauvegardes (si les sauvegardes ne sont jamais copiées
ailleurs, S8 n'est pas réellement couvert — voir risque résiduel R3, §6).

## 4. Objectifs de reprise (RTO / RPO)

### 4.1 Mesurés en test (valeurs réelles, pas des cibles théoriques)

| Scénario | RTO mesuré | RPO | Preuve de reprise exigée |
|---|---|---|---|
| S1 — `payment-api` arrêté | détection 22,0 s + reprise 25,8 s | 0 (base non touchée) | Transaction réelle (login → paiement → relecture) |
| S1 — `auth` tué | détection 20,7 s + reprise 33,1 s | 0 | idem |
| S1 — `bunkerweb` arrêté | détection 16,1 s + reprise 56,7 s | 0 | idem |
| S1 — `bunkerweb` saturé par surcharge réseau réelle (DDoS distribué simulé) | détection quasi immédiate + reprise 16,7 à 43,2 s (3 essais) | 0 | idem |
| S2 — Vault tué | détection 24,9 s + reprise 28,7 s | 0 (Vault redescellé avec ses données existantes) | API Vault répond, descellée |
| S5 — reconstruction complète (PRA, conteneurs recréés) | 119,8 s | 0 si les données ne sont pas détruites | Transaction réelle après reconstruction |
| S5 — PRA avec destruction + restauration de la base | 155,8 s | temps écoulé depuis la dernière `ops backup` | idem |
| S7 — restauration de Vault | non chronométrée formellement ; de l'ordre de la minute | temps écoulé depuis la dernière sauvegarde Vault | Secrets identiques à ceux d'avant l'incident (vérifié : 5/5 identiques en test) |

### 4.2 Objectifs retenus pour la démonstration

| Scénario | RTO visé | RPO visé |
|---|---|---|
| Panne d'un service (S1) | < 60 s | 0 |
| Panne de Vault (S2) | < 60 s | 0 |
| Attaque bloquée en amont (S3, S4) | 0 (jamais indisponible) | 0 |
| Compromission (S5) | < 5 min | 0 si conteneurs seuls altérés ; sinon = dernière sauvegarde |
| Perte du dossier de secrets (S6) | < 2 min (un déploiement) | 0 |
| Perte du volume Vault (S7) | < 5 min | temps depuis la dernière sauvegarde Vault |
| Perte du PC Hôte (S8) | de l'ordre de l'heure (réinstallation) | temps depuis la dernière sauvegarde copiée hors du PC |

**[À COMPLÉTER — Gouvernance]** : ces RTO/RPO sont des constats techniques, pas des engagements
négociés avec un commanditaire. L'EBIOS RM devrait dire si ces durées sont *acceptables* au
regard de l'impact métier (ex. : 60 s d'indisponibilité du paiement a-t-il un coût que
l'organisation juge tolérable ?).

## 5. Deux boucles de reprise, deux finalités différentes

Point à bien expliciter devant le jury (le sujet y insiste) :

- **PCA (continuité) — boucle automatique** : un service tombe, le système le redémarre et
  vérifie par une vraie transaction. Traite une perte de **disponibilité**. Aucune décision
  humaine, aucune perte de données (le service repart avec les mêmes données).
- **PRA (reprise après sinistre) — `ops recover`, décision humaine de déclenchement** : un
  conteneur est *altéré* (pas seulement arrêté) ou des données sont corrompues. Un redémarrage
  ne corrigerait rien : il faut reconstruire les images depuis les sources versionnées et,
  si nécessaire, restaurer les données depuis une sauvegarde antérieure à l'incident.

Confondre les deux est le piège classique : redémarrer un conteneur compromis le laisse
compromis si l'altération vit dans un volume persistant.

## 6. Risques résiduels (constatés, pas supposés)

| # | Risque | Constat | Mitigation actuelle | Mitigation en production |
|---|---|---|---|---|
| R1 | Un seul PC Hôte, aucune haute disponibilité | Par construction (contrainte du sujet) | Aucune | Plusieurs nœuds, réplication de la base, bascule automatique |
| R2 | Bannissement d'IP touche aussi les clients légitimes | Docker Desktop traduit tout le trafic externe vers une IP unique (NAT) ; confirmé en test | La preuve de continuité repose sur la transaction synthétique interne, pas sur l'accès de l'attaquant | `USE_REAL_IP` + équilibreur transmettant l'IP cliente réelle |
| R3 | Sauvegardes (base + Vault) stockées sur le même disque que la plateforme | Par défaut, `ops backup` écrit dans `./backups/` sur le PC Hôte | Rotation + SHA-256, mais pas de copie externe | Copie régulière vers un support externe ou un autre site (hors de ce PC) |
| R4 | L'archive de sauvegarde Vault contient aussi les clés de descellement | Nécessaire pour une reprise autonome sans ressaisie manuelle de clés | Fichier en permissions 0600, jamais versionné | Auto-unseal via KMS/HSM ; clés Shamir réparties entre plusieurs porteurs |
| R5 | Secrets Docker lisibles par tout utilisateur du PC Hôte | Contrainte de Docker Compose (pas de remappage d'UID sur les secrets fichier) | Repose sur les droits du profil Windows | Docker Swarm/Kubernetes secrets, ou agent Vault injectant en mémoire |
| R6 | Ports d'administration dépendants de plages réservées par Windows, qui changent à chaque redémarrage | Observé à plusieurs reprises en conditions réelles (Vault, remédiation) | Détection automatique du conflit et bascule sur un port libre (`ops deploy`) | Non applicable hors environnement Windows/Docker Desktop de lab |
| R7 | Pas de redondance pour `bunkerweb`, point d'entrée unique | Par construction | Redémarrage automatique en cas de panne (mesuré : 17-57 s d'indisponibilité) | Plusieurs instances WAF derrière un équilibreur |
| R8 | Le score d'anomalie IA (`aiops_anomaly_score`) n'est alimenté par aucun modèle | Branchement prêt côté infra, rien ne l'alimente actuellement | Détection par seuils (Prometheus/Loki) et règles Wazuh, qui couvrent les scénarios testés | Modèle de détection d'anomalies à livrer par le pôle IA |

## 7. Procédures (renvoi vers RUNBOOK.md)

Le détail opérationnel de chaque scénario est déjà écrit et testé dans `docs/RUNBOOK.md` :

| Scénario | Procédure |
|---|---|
| S1 (service en panne) | PROC-04 |
| S3 (XSS/SQLi) | PROC-05 |
| S4 (DDoS) | PROC-06 |
| S4 bis (démo DDoS distribué avec reprise réelle) | PROC-05bis |
| S5 (compromission, PRA) | PROC-07 |
| S6/S7 (secrets, Vault) | PROC-12 |
| Sauvegarde / restauration (S5, S7) | PROC-08 |
| Vérification de santé générale | `ops verify`, à exécuter avant toute démonstration |

## 8. Responsabilités (à nommer par l'équipe)

**[À COMPLÉTER — équipe]** — remplacer par les prénoms réels avant intégration au dossier :

| Rôle | Responsabilité | Qui |
|---|---|---|
| Décideur incident | Juge si un redémarrage automatique suffit ou si le PRA doit être déclenché | ? |
| Opérateur infra | Exécute `ops recover` / `ops restore`, surveille Grafana | ? (pôle Infra) |
| Opérateur sécurité | Analyse une alerte Wazuh/WAF, confirme qu'il s'agit bien d'une attaque bloquée et non d'une compromission réussie | ? (pôle Cyber) |
| Communication | Prévient le reste de l'équipe / le jury en cas d'incident pendant la démonstration | ? |

## 9. Ce qui ne peut pas être démontré par un prototype de 4 jours

À dire explicitement au jury plutôt que de le laisser deviner :
- Pas de test de charge représentatif d'un trafic de production réel.
- Pas de validation par un tiers (pentest externe, audit de conformité).
- Pas de plan de communication de crise, pas de procédure juridique de notification d'incident
  (obligations NIS2/DORA de notification sous 24h/72h non implémentées, seulement mentionnées).
- Les durées de reprise mesurées le sont sur une seule machine de développement, sans charge
  concurrente réaliste : elles donnent un ordre de grandeur, pas un engagement de service.

## 10. NIS2 / DORA — à compléter

**[À COMPLÉTER — Gouvernance].** Pistes techniques déjà disponibles pour nourrir cette section
(sans s'y substituer) :
- Traçabilité : tous les événements de remédiation et les alertes de sécurité sont journalisés
  avec horodatage (`/events`, Loki, Wazuh) — utile pour une obligation de notification motivée.
- Gestion des secrets centralisée (Vault) et moindre privilège (politique `ansible-ops` limitée
  à `resilience/*`) — pertinent pour les exigences de gestion des risques liés aux tiers/fournisseurs.
- Tests de résilience réguliers et reproductibles (`ops chaos`, `ops ddos_demo`) — pertinent pour
  les obligations de test de résilience opérationnelle numérique de DORA.
- Ce qui manque : analyse de risques formelle (EBIOS RM), registre des incidents, procédure de
  notification aux autorités, évaluation des prestataires tiers.
