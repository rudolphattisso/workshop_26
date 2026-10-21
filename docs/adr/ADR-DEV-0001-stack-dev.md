# ADR-DEV-0001 — Stack du domaine Dev

- **Statut** : accepté
- **Date** : 2026-10-20
- **Domaine** : Dev
- **Liés** : ADR-DEV-0002 (paiement synchrone et idempotent)

## Contexte

Le 3.1 exige un SI de paiement fictif en microservices conteneurisés : base de données, API métier, service
d'authentification, frontal web, moteur de remédiation et interface de supervision. Les services sont écrits
en **Node.js, Python/FastAPI ou Go**, et le tableau de bord en **React + Tailwind**.

Contraintes : 4 jours de sprint, un seul développeur sur le 3.1, une démo live où toute intervention manuelle
coûte 0/5, un PC Hôte limité à 16 Go de RAM, et chaque ligne doit pouvoir être défendue devant le jury.

## Décision

**Application** : un portefeuille de paiement. Les clients disposent d'un compte fictif approvisionné et
paient des marchands (comptes pré-créés). Pas de catalogue, de panier ni de carte bancaire.

| Brique | Choix |
|---|---|
| Services (auth, payment-api, remediation, smoke-test) | **Python 3.12 + FastAPI**, code **synchrone**, servi par Uvicorn |
| Base de données | **PostgreSQL 16** (conteneur et sauvegardes : Infra) |
| Accès aux données | **SQLAlchemy 2** (ORM) + migrations **Alembic** |
| Authentification | Service maison : **PyJWT RS256** (JWKS), mots de passe hachés en **argon2** |
| Socle commun | Package **`services/common`** : logs JSON, `trace_id`, `/health`, `/ready`, `/metrics`, erreurs RFC 9457 |
| Communication entre services | **REST / JSON** (httpx) |
| État du moteur de remédiation | **SQLite** propre au moteur, indépendant de la base PostgreSQL |
| Temps réel du dashboard | **Server-Sent Events** |
| Interfaces | **2 applications** Vite + React + Tailwind servies par Nginx : `web` (client) et `dashboard` (opérateur) |
| Tests | **pytest** + TestClient (API) · **Vitest** (React) |
| Images | `python:3.12-slim`, utilisateur non-root |

## Justification

- **Un seul langage back** : le socle commun est écrit une seule fois, avec une chaîne de tests unique et une
  montée en compétence ciblée. Python est aussi partagé avec l'équipe IA.
- **FastAPI** valide les entrées par les types (Pydantic), filtre les réponses selon le modèle déclaré et
  génère la documentation OpenAPI (livrable du `Code.zip`). L'injection de dépendances (`Depends`) centralise
  l'authentification.
- **Code synchrone** : le paiement l'est déjà (ADR-DEV-0002). On évite ainsi la complexité d'async/await sans
  perte utile à l'échelle d'une démo.
- **PostgreSQL** garantit l'atomicité du débit et du crédit. **SQLAlchemy** produit des requêtes paramétrées
  (pas d'injection SQL) et **Alembic** rend le schéma rejouable lors d'une restauration.
- **Auth maison plutôt que Keycloak** : Keycloak est trop gourmand pour le PC Hôte et difficile à expliquer.
  RS256 + JWKS évite tout secret partagé entre services.
- **SQLite pour le moteur** : le moteur ne doit pas dépendre de la base qu'il est chargé de réparer.
- **Deux fronts séparés** : le dashboard survit à l'incident du frontal attaqué, ce qui préserve la vue du
  jury et le Clip Chrono, et il peut être isolé côté réseau.
- **SSE plutôt que WebSocket** : le flux va dans un seul sens (serveur → navigateur), la reconnexion est
  native et l'implémentation est plus simple.

## Conséquences

- ✅ Une stack homogène, conforme au cahier des charges et entièrement explicable.
- ✅ `/docs` (Swagger UI) est disponible sur chaque service pendant le développement.
- ⚠️ Le contexte de build Docker des services Python est `services/`, pour embarquer `services/common`.
  À reporter par l'Infra dans `docker-compose.yml`.
- ⚠️ Mode d'action du moteur sur les conteneurs (docker-socket-proxy limité ou playbooks Ansible) :
  **non tranché ici**, à arbitrer avec Infra et Cyber (ADR dédié).

## Alternatives écartées

- **Go pour le moteur de remédiation** : binaire léger, mais un second langage et une seconde chaîne de tests en 4 jours.
- **Node.js partout** : validation et génération OpenAPI à ajouter à la main.
- **Une seule app React à deux espaces** : si le conteneur tombe, la vue de supervision tombe avec lui.
- **Keycloak** : coût mémoire et complexité de configuration disproportionnés pour la démo.
