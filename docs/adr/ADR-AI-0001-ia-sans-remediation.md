# ADR-AI-0001 — Le module IA détecte et recommande, il ne déclenche aucune remédiation

- **Statut** : accepté
- **Date** : 2026-10-22
- **Domaine** : AI
- **Impacte** : Infra (règle `AnomalyDetected`, cible Prometheus), Dev (moteur de remédiation, `contracts/alert.schema.json`), Cyber (WAF)

## Contexte

Le sujet prévoit une détection par ML et une remédiation sans intervention humaine. Deux points d'entrée
existent pour relier le ML à la remédiation :

- la règle Prometheus `AnomalyDetected` sur `aiops_anomaly_score`, avec `remediation: restart` ;
- `POST /alerts` du moteur de remédiation, avec `source: "ml"` (`contracts/alert.schema.json`).

Le module IA (`infra/ml-detector/` sur le PC hôte, `ai/ai-node/` sur le PC IA) analyse les journaux du WAF
et les alertes Wazuh pour **trouver ce que le WAF laisse passer**. Il signale des **attaques en cours**
(botnet sous les seuils par IP, requêtes coûteuses, injections servies par l'application), pas des pannes de
conteneur.

## Décision

1. **Le module IA n'envoie aucune alerte au moteur de remédiation**, ni par `POST /alerts` ni par
   Alertmanager.
2. **Il publie une métrique dédiée, `soc_waf_anomaly_score` (0-100)**, et **jamais** `aiops_anomaly_score`.
   `AnomalyDetected` ne se déclenche donc jamais à cause de lui.
3. **Sa réponse est une recommandation relue par un humain.** Le LLM (Ollama, qwen2.5 7B) rédige un rapport et
   des règles WAF (ModSecurity, réglages BunkerWeb). Elles sont compilées et filtrées par des garde-fous
   déterministes, puis écrites dans un fichier. Un opérateur les relit et les copie-colle.
4. Le module **lit** les actions de la remédiation (journal `{service="remediation"}`, règles Wazuh
   100210 / 100211) et les reporte dans ses rapports. Il n'y écrit jamais.

## Justification

- **Redémarrer ne répond pas à une attaque.** Un conteneur redémarré face à un DDoS reprend le même
  trafic. Si c'est le WAF qui redémarre, la protection s'interrompt : c'est l'effet recherché par
  l'attaquant. Dans l'export Wazuh du 19-20/10, les sondes voient des 503 pendant les redémarrages du WAF.
- **Un faux positif ne doit pas pouvoir dégrader la plateforme.** Une alerte ML erronée déclencherait une
  action réelle pendant la démo. Une recommandation erronée, elle, est écartée à la relecture.
- **La bonne réponse à une attaque est une règle de filtrage ciblée**, qu'aucun playbook générique ne peut
  écrire : chemin, paramètre, en-tête, IP. C'est ce que produit le LLM, sous contrôle humain.
- **La remédiation automatique garde ses déclencheurs fiables** : watchdog, sondes `/health` et `/ready`,
  Prometheus, SIEM. Le module IA ne vient pas les concurrencer.

## Conséquences

- La chaîne « ML → remédiation » n'est pas fournie par le domaine IA. La remédiation automatique repose sur
  les autres émetteurs (`watchdog`, `prometheus`, `waf`, `siem`).
- La règle `AnomalyDetected` et l'exemple de `infra/prometheus/targets/extensions.yml` (qui suppose
  `aiops_anomaly_score`) restent sans émetteur. La cible du détecteur est déclarée avec `tier: soc`.
- **À ne pas faire** : créer une alerte avec remédiation sur `soc_waf_anomaly_score`. Une alerte informative
  (`remediation: none`) est possible.
- Intégration détaillée : `docs/ia/INTEGRATION.md` (§6 pour ce choix).
