# Instructions du projet — PROJECT RESILIENCE-ALPHA (Workshop EPSI M2 2026)

> Fichier **commun à toute l'équipe**. Toute modification passe par une PR relue par au moins un autre domaine.
> Les consignes propres à un domaine sont dans le `CLAUDE.md` de son dossier.
> Les préférences personnelles (posture de Claude, rôle) vont dans `CLAUDE.local.md` (non versionné).

---

## 🧭 Contexte

Démonstrateur de **cyber-résilience** : une plateforme de paiement **fictive** conteneurisée subit une attaque
lancée depuis un PC Attaquant, détecte l'anomalie (ML), décide et exécute une remédiation **sans intervention
humaine**, puis prouve le retour du service par une **nouvelle transaction fictive réussie**.

- Sprint : lundi 19 → jeudi 22 octobre 2026 · **gel du code jeudi 17h** · rendus jeudi 23h59 · jury vendredi
- Critère décisif : intervention manuelle pendant la démo live ⇒ **0/5** sur la remédiation
- « Un conteneur qui redémarre » n'est **pas** une preuve de reprise : API joignable + transaction OK + données cohérentes
- Aucune donnée bancaire réelle · aucune action offensive hors de notre SI · aucun secret en clair dans le dépôt

---

## 🏗️ Stack imposée

| Domaine | Technologies |
|---------|--------------|
| **Dev** | Microservices Node.js / Python-FastAPI / Go · dashboard React + Tailwind |
| **Infra** | Docker Compose · Ansible · Prometheus · Grafana · Loki (pas d'Elastic) |
| **IA / Data** | ML de détection d'anomalies · assistant RAG Ollama + LangChain (≤ 8B params) |
| **Cyber** | WAF · SIEM / fonction SOC · durcissement · HashiCorp Vault ou SOPS · Red Team |
| **Gouvernance** | EBIOS RM · PCA/PRA · NIS2 / DORA |

Machines : **PC Hôte** (tout le SI, Docker Desktop WSL2, `192.168.137.1`) · **PC Attaquant** (outils Red Team
uniquement) · **PC IA** optionnel (Ollama seul). Réseau : point d'accès mobile Windows `RESILIENCE-G<n>`.

---

## 👥 Domaines & propriété des dossiers

Chaque domaine **possède** son dossier : on n'y modifie rien sans prévenir son responsable.

| Domaine | Dossier | Responsable |
|---------|---------|-------------|
| Dev | `services/` | Rudolph |
| Infra | `infra/` (+ `docker-compose.yml` racine) | _à compléter_ |
| IA / Data | `ai/` | _à compléter_ |
| Cyber | `security/` | _à compléter_ |
| Gouvernance | `governance/` | _à compléter_ |
| **Commun** | `contracts/`, `docs/`, `CLAUDE.md`, `README.MD` | toute l'équipe (PR obligatoire) |

---

## 🤝 Contrats entre domaines — `contracts/`

Les domaines travaillent en parallèle **en s'appuyant sur des contrats figés tôt** (lundi). Un contrat ne
change que par PR validée par tous les domaines concernés.

| Contrat | Fichier | Producteur → Consommateur |
|---------|---------|---------------------------|
| API métier (auth, paiements) | `contracts/openapi-payment.yaml` | Dev → Front, Red Team, tests |
| Format d'alerte | `contracts/alert.schema.json` | IA / Prometheus / WAF → moteur de remédiation |
| API du moteur de remédiation | `contracts/openapi-remediation.yaml` | Dev → Dashboard, IA, Infra |
| Conventions de service | `contracts/service-conventions.md` | Dev → Infra (scraping, logs), IA (features) |
| Ports & réseaux exposés | `contracts/network.md` | Infra + Cyber → tous |

**Conventions minimales de tout service** (détail dans `contracts/service-conventions.md`) :
- `GET /health` (vivant) · `GET /ready` (prêt, dépendances OK) · `GET /metrics` (format Prometheus)
- Logs **JSON sur stdout** avec `timestamp`, `level`, `service`, `trace_id`, `event`
- Configuration par variables d'environnement · secrets fournis par Vault/SOPS, jamais en dur

---

## 🌿 Workflow Git

- `main` doit **toujours** pouvoir démarrer (`docker compose up`). Pas de push direct.
- Branches : `<domaine>/<sujet>` — ex. `dev/payment-api`, `infra/loki`, `ai/isolation-forest`
- Petites PR, mergées souvent (au moins 2× par jour) pour éviter l'intégration « big bang » de mercredi
- Messages de commit : `<domaine>: <action>` — ex. `dev: ajoute endpoint POST /payments`
- Avant de modifier un fichier hors de son dossier → prévenir le propriétaire

---

## 📝 Traçabilité (règles appliquées automatiquement)

### `docs/progression/<domaine>.md`
- Un fichier **par domaine** (évite les conflits de merge)
- À mettre à jour à chaque fin de bloc : date, fichiers créés/modifiés, décisions, problèmes rencontrés, ADR associés
- Sert de matière première au dossier PDF (contribution de chacun exigée)

### `docs/adr/`
- Un ADR par décision technique significative
- Format : `ADR-<DOMAINE>-NNNN-titre-court.md` (ex. `ADR-DEV-0001-choix-fastapi.md`) — préfixe par domaine pour
  éviter les collisions de numéros en parallèle
- Index tenu à jour dans `docs/adr/README.md` · un ADR ne se modifie pas, il se supersède

---

## 🚦 Règles pour Claude (tous les membres)

- **Rester dans le domaine** du dossier courant ; si une tâche impacte un contrat ou un autre domaine, le signaler
  au lieu de le modifier directement
- Respecter strictement la stack imposée ci-dessus — ne jamais proposer d'alternative hors cahier des charges
- Ne jamais écrire de secret, mot de passe ou token en clair (utiliser `.env.example` avec des valeurs factices)
- Ne jamais exposer base de données, Vault, Docker socket ou interfaces d'admin hors du réseau interne
- Privilégier ce qui fonctionne de façon **fiable en démo** plutôt que ce qui est ambitieux
- Expliquer les choix : chaque membre doit pouvoir défendre son code devant le jury
