# Domaine DEV — `services/`

> Complète le `CLAUDE.md` racine. Responsable : Rudolph.

---

## 🎯 Périmètre

| Composant | Dossier | Rôle |
|-----------|---------|------|
| **API métier** | `services/payment-api/` | Comptes et transactions fictives |
| **Service d'auth** | `services/auth/` | Login, émission/validation de JWT, rôles |
| **Frontal web** | `services/web/` | Interface utilisateur pour initier un paiement |
| **Moteur de remédiation** | `services/remediation/` | Reçoit les alertes, décide, agit, vérifie la reprise |
| **Dashboard de supervision** | `services/dashboard/` | React + Tailwind : composants, événements, alertes, progression de la reprise |
| **Smoke test métier** | `services/smoke-test/` | Transaction de bout en bout réutilisée par la remédiation et la démo |
| **Socle commun** | `services/common/` | Package Python partagé : logs JSON, trace_id, probes, métriques, erreurs |

Base de données : PostgreSQL (le schéma appartient au Dev, le conteneur et les sauvegardes à l'Infra).

Hors périmètre Dev : `docker-compose.yml`, Ansible, Prometheus/Grafana/Loki, WAF, Vault, modèle ML, RAG.
On **consomme** ces briques via les contrats de `contracts/`.

---

## 🏗️ Choix techniques

| Sujet | Choix | Statut |
|-------|-------|--------|
| Application | Portefeuille de paiement : clients → marchands (comptes fictifs) | acté — ADR-DEV-0001 |
| Langage des services | Python 3.12 + FastAPI, code synchrone, Uvicorn | acté — ADR-DEV-0001 |
| Socle commun | `services/common` : logs JSON, trace_id, health/ready/metrics, erreurs RFC 9457 | acté — ADR-DEV-0001 |
| Base / ORM / migrations | PostgreSQL 16 · SQLAlchemy 2 · Alembic | acté — ADR-DEV-0001 |
| Auth | Service maison, PyJWT RS256 + JWKS, argon2 | acté — ADR-DEV-0001 |
| Paiement | Synchrone, une transaction SQL, `Idempotency-Key` | acté — ADR-DEV-0002 |
| État du moteur de remédiation | SQLite propre au moteur (indépendant de PostgreSQL) | acté — ADR-DEV-0001 |
| Fronts | 2 apps Vite + React + Tailwind (`web`, `dashboard`) servies par Nginx | acté — ADR-DEV-0001 |
| Temps réel dashboard | Server-Sent Events depuis le moteur de remédiation | acté — ADR-DEV-0001 |
| Tests | pytest + TestClient (API) · Vitest (React) | acté — ADR-DEV-0001 |
| Action sur les conteneurs | Docker API via **docker-socket-proxy** (droits restreints) ou playbooks Ansible | **à arbitrer avec Infra/Cyber** |

---

## 🔁 Moteur de remédiation — principes

C'est la pièce centrale de la démo. Il doit être **déterministe, observable et sûr**.

```
Alerte reçue → DETECTED → DECIDED → ACTING → VERIFYING → RESOLVED
                                                    └──→ ESCALATED (échec après N tentatives)
```

- **Entrée** : alertes conformes à `contracts/alert.schema.json` (sources : ML, Alertmanager, WAF)
- **Décision** : table « type d'incident → playbook » explicite et versionnée (pas de logique cachée)
- **Actions possibles** : redémarrer / recréer un conteneur depuis une image saine, bloquer une IP au WAF,
  restaurer un état de données, révoquer des tokens — distinguer **disponibilité** et **compromission**
- **Vérification** : la reprise n'est validée que si `/ready` est OK **et** que le smoke test réussit une transaction
- **Idempotence + cooldown** : une même alerte ne déclenche pas deux remédiations en boucle
- **Traçabilité** : chaque étape émet un log JSON et un événement SSE pour le dashboard
- **Sécurité** : endpoint d'alertes authentifié (token de service), aucune interface d'admin exposée,
  privilèges minimaux sur Docker

---

## ✅ Definition of Done (Dev)

- Endpoint documenté dans l'OpenAPI de `contracts/` et testé
- `/health`, `/ready`, `/metrics` et logs JSON présents sur chaque service
- Aucun secret en dur · Dockerfile non-root, image slim
- Progression notée dans `docs/progression/dev.md`, ADR si décision structurante

---

## 🚀 Ordre de réalisation

```
Lundi    →  Contrats : openapi-payment, alert.schema, openapi-remediation, service-conventions
            Squelette FastAPI commun (health/ready/metrics/logs) + ADR-DEV-0001
Mardi    →  auth + payment-api + schéma DB + smoke-test · moteur de remédiation v0 (1 playbook)
Mercredi →  Branchement alertes réelles (ML/Prometheus/WAF) · dashboard React · tests de restauration
Jeudi    →  Fiabilisation (répéter la démo 10×) · tests · doc API · gel 17h
```

Principe directeur : **un scénario complet qui marche à 100 %** avant d'en ajouter un deuxième.
