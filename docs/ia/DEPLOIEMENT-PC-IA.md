# Déploiement du PC IA

Le PC IA fait tourner le llm-gateway, Ollama (sur le GPU) et ChromaDB, avec son propre compose
(`ai/ai-node/docker-compose.yml`), indépendant de celui de l'infra.

## Prérequis

- Docker avec le GPU NVIDIA accessible aux conteneurs (NVIDIA Container Toolkit).
- Environ 6 Go de disque pour les modèles (qwen2.5 7B : 4,7 Go ; nomic-embed-text : 0,3 Go).
- Une adresse IP joignable depuis le PC infra.
- Un accès Internet, au premier lancement seulement (téléchargement des modèles).

## Installation

```sh
git clone <dépôt> && cd workshop_26/ai/ai-node
cp .env.example .env
```

Dans `.env` :

| Variable | Valeur |
|---|---|
| `LLM_GATEWAY_TOKEN` | **la même valeur** que `secrets/llm_gateway_token` sur le PC infra (≥ 32 caractères) |
| `GATEWAY_BIND` | l'IP du PC IA sur le réseau partagé avec le PC infra (`127.0.0.1` : local uniquement) |
| `REPORTS_PASSWORD` | mot de passe des pages `/reports` (utilisateur `soc`) ; vide : pages désactivées |
| `OLLAMA_MODEL` | `qwen2.5:7b-instruct` (choisi après comparaison, voir `ai/ai-node/HANDOFF.md`) |

```sh
docker compose up -d ollama chroma
docker compose exec ollama ollama pull qwen2.5:7b-instruct
docker compose exec ollama ollama pull nomic-embed-text
docker compose run --rm index            # indexe knowledge/ dans ChromaDB (à relancer après chaque
                                         # modification : retire aussi les passages supprimés)
docker compose up -d llm-gateway
docker compose run --rm tests            # facultatif : tests sans GPU ni réseau
```

## Réseau

- Seul le llm-gateway publie un port : 8080, sur `GATEWAY_BIND`. Ollama et ChromaDB ne sont
  joignables que par lui (réseau `ai-backend`, sans sortie).
- Ollama n'a un accès sortant (réseau `ai-egress`) que pour télécharger les modèles.
- Pare-feu du PC IA : n'ouvrir le port 8080 qu'au PC infra et aux postes qui lisent les rapports.

## Vérifications

```sh
curl http://<IP_PC_IA>:8080/health
#   {"status":"ok","model":"qwen2.5:7b-instruct","detecteur":"ok"}
```

| `detecteur` | Signification |
|---|---|
| `inconnu` | aucun signal depuis le démarrage de la gateway (détecteur pas encore lancé) |
| `ok` | signal de vie reçu depuis moins de 2 min, et le détecteur lit ses journaux |
| `aveugle` | le détecteur tourne mais ne lit plus ses journaux (Loki injoignable) |
| `muet` | aucun signal depuis plus de 2 min : PC infra arrêté, réseau coupé ou détecteur tombé |

Ces deux derniers états affichent aussi un bandeau rouge sur `/reports`.

## Où trouver les résultats

- `ai/ai-node/reports/*.md` : un rapport par analyse (diagnostic, règles prêtes à copier avec leur
  emplacement, effets de bord, actions de l'infra, incertitudes).
- `http://<IP_PC_IA>:8080/reports` : les mêmes rapports dans un navigateur. C'est le lien
  « Ouvrir » du tableau Grafana.
- Une analyse dure environ 30 à 40 s sur le GPU. Le premier appel après le démarrage charge le
  modèle (environ 20 s de plus), puis le modèle reste chargé 24 h (`LLM_KEEP_ALIVE`).
