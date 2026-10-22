# Index des ADR

Format : `ADR-<DOMAINE>-NNNN-titre-court.md` — domaines : DEV, INFRA, AI, SEC, GOV.

| ADR | Titre | Domaine | Statut | Date |
|-----|-------|---------|--------|------|
| [ADR-DEV-0001](ADR-DEV-0001-stack-dev.md) | Stack du domaine Dev | DEV | accepté | 2026-10-20 |
| [ADR-DEV-0002](ADR-DEV-0002-paiement-synchrone-idempotent.md) | Paiement synchrone et idempotent | DEV | accepté | 2026-10-20 |
| [ADR-DEV-0003](ADR-DEV-0003-auth-jwt-rs256-jwks.md) | Service d'auth : JWT RS256, JWKS en cache, clé éphémère | DEV | accepté | 2026-10-20 |
| [ADR-DEV-0004](ADR-DEV-0004-contrats-remediation.md) | Moteur de remédiation : format d'alerte, playbooks et preuve de reprise | DEV | accepté | 2026-10-20 |
| [ADR-DEV-0005](ADR-DEV-0005-integration-plateforme-infra.md) | Intégration à la plateforme Infra : préfixe `/api`, secrets `_FILE`, cibles Compose, docker-proxy (amende ADR-DEV-0004) | DEV | accepté | 2026-10-20 |
| [ADR-DEV-0006](ADR-DEV-0006-supervision-topologie.md) | Supervision : watchdog de topologie (services + connexions) et dashboard temps réel | DEV | accepté | 2026-10-21 |
| [ADR-AI-0001](ADR-AI-0001-ia-sans-remediation.md) | Le module IA détecte et recommande, il ne déclenche aucune remédiation | AI | accepté | 2026-10-22 |
