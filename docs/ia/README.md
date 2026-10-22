# Module IA SOC

Ce module trouve ce que le WAF laisse passer, puis fait rédiger par un LLM un rapport et des
**recommandations** de règles WAF. Un humain relit les règles et les copie-colle. **Le module ne
remédie jamais** : il n'applique aucune règle, n'appelle pas le webhook de remédiation et ne
redémarre rien.

## Deux machines, deux déploiements

| | PC infra | PC IA |
|---|---|---|
| Code | `infra/ml-detector/` | `ai/ai-node/` |
| Lancé par | le `docker-compose.yml` de l'infra (bloc à coller : [INTEGRATION.md](INTEGRATION.md)) | son propre `ai/ai-node/docker-compose.yml` ([DEPLOIEMENT-PC-IA.md](DEPLOIEMENT-PC-IA.md)) |
| Rôle | lit le WAF, Wazuh et la remédiation dans Loki toutes les 10 s, détecte, décide d'escalader | llm-gateway : rapport et règles (Ollama qwen2.5, RAG ChromaDB) |
| Expose | `/metrics` et `/health` sur 8000 (réseau `monitoring`) | `POST /analyze`, `POST /heartbeat`, `/reports` et `/health` sur 8080 |
| Besoins | CPU, 512 Mo | GPU NVIDIA |

```
 PC INFRA                                                     PC IA
 Loki ──> ml-detector ──── POST /analyze (jeton) ────────────> llm-gateway ──> Ollama
            │        └──── POST /heartbeat toutes les 30 s ──>     │           ChromaDB
            └─> /metrics (Prometheus) et journal JSON (Loki)       └──> reports/*.md, pages /reports
                  └─> Grafana : panneau « Module IA » (vue infra)               (règles à copier-coller)
```

Le seul lien entre les deux machines est HTTP sur le port 8080 du PC IA, authentifié par le jeton
`llm_gateway_token`.

## Le contrat entre les deux : `contracts/analyze/`

Ce dossier contient des exemples de requêtes `POST /analyze`, une par situation :
- campagne DDoS ;
- réanalyse après aggravation ;
- injection servie par l'application ;
- symptôme sans campagne ;
- perte de visibilité.

Ils sont **produits par le vrai détecteur** sur les scénarios simulés
(`infra/ml-detector/scripts/contract_examples.py`) et versionnés.

- La suite du détecteur vérifie qu'il produit toujours cette forme.
- La suite de la gateway vérifie qu'aucun champ n'est ignoré en silence. La gateway ignore les
  champs inconnus : un champ renommé d'un côté disparaîtrait sans erreur.

Pour changer volontairement le format :

```sh
cd infra/ml-detector && python -m scripts.contract_examples   # régénère les exemples
# relire le diff de contracts/, adapter ai/ai-node/llm_gateway/contract.py, puis lancer les deux suites
```

## Tests

```sh
cd infra/ml-detector && python -m pytest -q    # détecteur, escalade, sources, contrat
cd ai/ai-node && python -m pytest -q                 # gateway, garde-fous, compilateur de règles, contrat
```

Les tests de contrat lisent `contracts/` à la racine du dépôt. Dans les images Docker (cible
`dev`), ce dossier est absent : ces tests sont alors ignorés et les autres s'exécutent.

## Documents

| Document | Pour qui | Contenu |
|---|---|---|
| [INTEGRATION.md](INTEGRATION.md) | pôles infra et cyber | blocs compose, secret, Prometheus, Grafana, sélecteurs Loki, choix de la métrique, calibrage, fusion git |
| [DEPLOIEMENT-PC-IA.md](DEPLOIEMENT-PC-IA.md) | qui installe le PC IA | installation, modèles, vérifications |
| `infra/ml-detector/HANDOFF.md`, `ai/ai-node/HANDOFF.md` | pôle IA | journal de travail : décisions, mesures, état, suite |
