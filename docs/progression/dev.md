# Progression — dev

<!-- Une entrée par bloc de travail : date, fichiers, décisions, problèmes, ADR -->

## 2026-10-19 — Kick-off : organisation et cadrage du périmètre 3.1

**Fait**
- Lecture du sujet (PDF) et correction du `.gitignore` (chemin avec `\` non reconnu par Git)
- Mise en place de l'organisation Claude Code de l'équipe : `CLAUDE.md` racine (commun), `services/CLAUDE.md` (domaine Dev), `CLAUDE.local.md` personnel (non versionné)
- Squelette partagé : `contracts/`, `docs/adr/README.md`, `docs/progression/<domaine>.md`
- Brainstorm de cadrage du 3.1 à partir de l'archi cible de l'équipe (`doc/private/2026-10-19_15h01_47.png`)

**Fichiers créés / modifiés**
- `.gitignore`, `CLAUDE.md`, `services/CLAUDE.md`, `contracts/README.md`, `docs/adr/README.md`, `docs/progression/*.md`

**Décisions actées**
- Je couvre seul l'intégralité du 3.1 : DB, API métier, auth, frontal web, moteur de remédiation, dashboard React/Tailwind. Tous les composants sont jugés importants.
- Chaque profil reste dans son couloir (sections 3.1 à 3.5 du sujet).
- Le métier simulé est le **prestataire de paiement** (l'entreprise financière exploite la plateforme), pas une boutique : catalogue, panier et stock sont hors périmètre ; un marchand se réduit à une commande pré-créée ou un appel API.
- Principe du moteur de remédiation : relancer automatiquement les services quand l'applicatif tombe (scénario de référence : DDoS).

**Orientations proposées (non encore actées)**
- Moteur en trois temps : contenir → rétablir → vérifier par une transaction fictive, avec anti-boucle de redémarrage
- Deux rôles : client et opérateur (accès au dashboard de supervision)
- Cohérence vérifiable : somme des soldes constante, aucun paiement capturé sans débit/crédit correspondants

**Écarts relevés dans l'archi cible (à remonter à l'équipe)**
- Moteur de remédiation absent du schéma (le ML détecte, mais personne n'agit ni ne vérifie la reprise)
- « Applicatif front/back » en un seul bloc alors que le 3.1 exige frontal, API métier et auth séparés
- Grafana utilisé comme dashboard alors que le 3.1 impose une interface React/Tailwind (les deux peuvent coexister)
- Hors couloir Dev : le RAG qui modifie les règles WAF/SIEM contredit le 3.3 ; le ML sur le serveur secondaire contredit la section 4 (le PC de délestage n'héberge qu'Ollama)

**Questions ouvertes**
- Frontière moteur de remédiation ↔ WAF (Cyber) pour l'étape « contenir » — reportée
- Traitement du paiement en une requête ou en deux temps (`EN_ATTENTE` → traité)
- Langage des services (FastAPI proposé, ADR-DEV-0001 à rédiger)

**Prochain démarrage** : trancher le traitement du paiement (une requête ou deux temps), puis rédiger le contrat `contracts/openapi-payment.yaml`.
