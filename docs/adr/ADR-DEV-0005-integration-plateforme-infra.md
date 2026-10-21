# ADR-DEV-0005 — Intégration des services Dev à la plateforme de l'Infra

- **Statut** : accepté
- **Date** : 2026-10-20
- **Domaine** : Dev
- **Amende** : ADR-DEV-0004, point 2 (chemin et format du webhook Alertmanager), et tranche son point ouvert
  sur le mode d'action sur les conteneurs
- **Contrats modifiés** : `openapi-payment.yaml` (0.4.0), `alert.schema.json` (0.2.0),
  `openapi-remediation.yaml` (0.2.0), `service-conventions.md` (0.3)

## Contexte

L'Infra a livré sur sa branche `infrastructure` une plateforme complète : Compose durci, WAF BunkerWeb,
Prometheus, Alertmanager, Loki, Vault, Wazuh, plus Ansible pour le PRA. Elle y a placé des services provisoires
pour faire tourner la chaîne ; ce sont nos services qui les remplacent.

Ses choix d'infrastructure fixent l'interface avec nos services, et quatre points étaient incompatibles avec notre code :

1. Le WAF transmet l'URI **sans réécriture** : `/api/auth/*` → `auth`, `/api/payments*` → `payment-api`. Ses
   sondes boîte noire testent `/api/auth/ready` et `/api/payments/ready` à travers le WAF.
2. Les secrets sont des **fichiers** `/run/secrets/<nom>` (Docker secrets, alimentés par Vault), jamais des
   variables d'environnement. La base est décrite par `DB_HOST`, `DB_NAME` et `DB_USER`.
3. Les noms de services Compose sont `postgres` (une seule instance), `frontend`, `bunkerweb` et `vault`.
4. Alertmanager appelle déjà `POST /webhook/alertmanager` avec les labels `remediation` (`restart` | `none`) et
   `target`. Le moteur n'agit que via un **docker-socket-proxy** limité à la lecture et à `start`/`stop`/`restart`.

## Décision

1. **Préfixe `/api` dans nos routes** (et non une réécriture au WAF) :
   - `/api/auth/*`, `/api/accounts*`, `/api/payments*` ;
   - `/api/operations/*` existe, mais le WAF ne le publie pas : c'est un usage interne, réservé au moteur.

   `create_app(..., public_prefix=...)` sert aussi `/health` et `/ready` sous le préfixe du service, mais
   **jamais `/metrics`**, qui reste à la racine sur le réseau interne. Ces sondes sont enregistrées avant les
   routes métier, pour que `/api/payments/ready` ne soit pas pris pour `/api/payments/{id}`.
2. **Secrets en convention `<NOM>_FILE`**, celle des images officielles (`POSTGRES_PASSWORD_FILE`…). Elle est
   implémentée une seule fois dans `resilience_common.config` :
   - `secret()` lit le fichier, et à défaut la variable `<NOM>` (développement local) ;
   - `database_url()` prend `DATABASE_URL` s'il est défini, sinon l'assemble depuis `DB_*` et `DB_PASSWORD_FILE`.

   Un fichier de secret absent fait échouer le démarrage : on n'utilise jamais un mot de passe vide.
3. **Les cibles d'alerte sont les noms de services Compose** de l'Infra :
   `payment-api`, `auth`, `postgres`, `frontend`, `bunkerweb`, `vault`. Cette énumération sert aussi de liste
   blanche des conteneurs sur lesquels le moteur peut agir.
4. **Webhook Alertmanager sur `/webhook/alertmanager`**, le chemin déjà configuré par l'Infra. Le label
   `incident_type` reste prioritaire. À défaut :
   - `remediation: restart` est lu comme `SERVICE_DOWN` ;
   - `remediation: none` est seulement observé (événement publié, aucune action).
5. **Actions par le docker-proxy uniquement : `restart`, puis `stop` + `start` à la 2ᵉ tentative.** On ne recrée
   jamais de conteneur. La révocation des jetons (`TOKEN_COMPROMISE`) reste possible, car redémarrer `auth`
   régénère sa clé éphémère (ADR-DEV-0003).

## Conséquences

- **+** Nos services se branchent sur la plateforme de l'Infra en changeant seulement `build:` et quelques
  variables dans son Compose. Ses sondes, alertes et tableaux de bord restent valables.
- **+** Aucun secret ne passe dans l'environnement du processus, donc rien n'apparaît dans `docker inspect`.
- **+** Le point 4 respecte toujours la règle de l'ADR-DEV-0004 : l'émetteur n'impose pas d'action arbitraire.
  `remediation: restart` ne débloque rien de plus que `SERVICE_DOWN`, qui est déjà dans la table. La liste
  blanche des cibles s'applique toujours.
- **−** La restauration des données (`DATA_TAMPERING`) ne peut pas passer par le docker-proxy. Chez l'Infra, elle
  est une procédure Ansible lancée par un humain. **C'est le seul playbook encore bloqué** : il faut un
  déclencheur automatique fourni par l'Infra.
- **−** L'Infra doit ajouter la route WAF `/api/accounts` (une entrée `REVERSE_PROXY_URL_<n>`).

## Alternatives écartées

- **Réécriture d'URL au WAF** (`/api/payments` → `/payments`) : ce serait de la configuration en plus côté Cyber
  et Infra, et les chemins des logs différeraient de ceux des requêtes réelles. Le préfixe dans le code se teste
  avec pytest.
- **Lire `/run/secrets/<nom>` en dur** : nos services dépendraient des noms de secrets de l'Infra
  (`demo_user_password`…). Avec `<NOM>_FILE`, c'est le Compose qui fait le lien.
- **Garder `/alerts/alertmanager` et faire changer l'Alertmanager** : le chemin seul ne justifie pas un aller-retour
  entre équipes.
