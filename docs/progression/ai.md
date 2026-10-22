# Progression — ai

<!-- Une entrée par bloc de travail : date, fichiers, décisions, problèmes, ADR -->

## 2026-10-19 → 20 — Détecteur ML et premier nœud LLM

- **Fichiers** : `infra/ml-detector/` (alors `services/ml-detector/`), `ai/ai-node/` (alors `ai-node/`).
- **Décisions** :
  - le détecteur cherche **ce que le WAF laisse passer** : aucune feature n'encode une décision du WAF (statuts 403/429/444 masqués), mesure principale = rappel sur ce que le WAF ne bloque pas ;
  - IsolationForest + DBSCAN sur fenêtres de 60 s, 30 features ; simulateur de trafic normal et d'attaques (DDoS sous les seuils par IP, contournement de cache, exports coûteux, injections) ;
  - LLM sur un PC séparé (Ollama, qwen2.5 7B choisi après comparaison avec llama3.1 8B et mistral), RAG sur `knowledge/`.
- **Problèmes** : parser BunkerWeb incompatible avec les vraies lignes (champ `request_id`), fuite de données dans les scénarios (IP partagées), DBSCAN quadratique (17 s → 0,3 s) ; tous corrigés et testés.

## 2026-10-21 — Escalade, service continu, intégration

- **Fichiers** : `detector/escalation.py`, `service.py`, `llm_queue.py`, `sources/loki.py`, `logs.py` ; `llm_gateway/rule_compiler.py`, `guardrails.py`, `app.py` ; `docs/ia/`.
- **Décisions** :
  - appel au LLM **déclenché** (gravité, délai de garde, plafond par minute), pas cyclique ; file d'attente fusionnant les mises à jour d'une même campagne ;
  - le LLM décrit des règles dans une grammaire structurée, **compilée** en syntaxe ModSecurity / BunkerWeb puis filtrée par des garde-fous déterministes ; rien n'est appliqué automatiquement (ADR-AI-0001) ;
  - métrique dédiée `soc_waf_anomaly_score`, jamais `aiops_anomaly_score` (ADR-AI-0001) ;
  - perte de visibilité (Loki injoignable, sondes absentes des journaux du WAF) : un rapport sort quand même ; signal de vie vers le PC IA (« détecteur muet ») ;
  - contrat `/analyze` figé par des exemples produits par le vrai détecteur (`contracts/analyze/`), vérifiés par les deux suites de tests.
- **Problèmes** : prompt tronqué (contexte Ollama 4096 → 8192), alarme critique réanalysée à chaque cycle, réseau `monitoring` sans sortie vers le PC IA (réseau dédié `ia`) ; corrigés.

## 2026-10-22 — RAG mesuré, garde-fous, fusion dans develop

- **Fichiers** : `ai/ai-node/knowledge/injections.md`, `llm_gateway/rag/`, `guardrails.py` ; `docs/adr/ADR-AI-0001-ia-sans-remediation.md`.
- **Décisions** :
  - RAG à 4 passages conservé après mesure (30 analyses) : même justesse des verdicts que sans RAG, 19 règles acceptées / 5 refusées contre 12 / 12 ; la base entière dépasse le contexte ;
  - garde-fous de portée : refus des règles dont toutes les conditions sont inversées (≈ tout le trafic) et des valeurs `%XX` sur des paramètres décodés (ne correspondent jamais) ;
  - code rangé selon les domaines : `ai/ai-node/` (PC IA), `infra/ml-detector/` (tourne dans le compose de l'infra) ; journaux et sondes alignés sur `contracts/service-conventions.md`.
- **Problèmes** : identifiants de passages RAG tronqués qui s'écrasaient ; passages supprimés gardés dans ChromaDB ; corrigés.
- **Reste à faire avec l'infra** : ajouter le bloc compose (`docs/ia/INTEGRATION.md` §1), la cible Prometheus, le tableau Grafana ; lancer `python -m detector.calibrate` au premier déploiement.
- **ADR** : ADR-AI-0001.

