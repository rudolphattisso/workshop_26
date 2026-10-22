"""Client Ollama : /api/chat avec sortie JSON contrainte par un JSON Schema (Ollama >= 0.5)."""
from __future__ import annotations

import json

import httpx

from .base import LLMClient


class LLMError(RuntimeError):
    """Ollama injoignable, délai dépassé ou réponse non JSON."""


class OllamaClient(LLMClient):
    def __init__(self, base_url: str, model: str, temperature: float = 0.1, num_ctx: int = 8192,
                 keep_alive: str = "24h"):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        # Contexte par défaut d'Ollama = 4096 tokens : notre prompt (~4 350) y était TRONQUÉ en
        # silence (mesuré le 2026-10-21). Un prompt qui atteint num_ctx est signalé (stats).
        self.num_ctx = num_ctx
        # Ollama décharge le modèle après 5 min d'inactivité ; les analyses ne partant que sur escalade,
        # chaque incident après un calme payait ~20 s de chargement (mesuré le 2026-10-21).
        self.keep_alive = keep_alive

    def generate_json(self, system: str, user: str, schema: dict, timeout_s: float = 60.0) -> dict:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "format": schema,
            "stream": False,
            "keep_alive": self.keep_alive,
            "options": {"temperature": self.temperature, "num_ctx": self.num_ctx},
        }
        self.last_stats = None
        try:
            response = httpx.post(f"{self.base_url}/api/chat", json=payload, timeout=timeout_s)
            response.raise_for_status()
            body = response.json()
            self.last_stats = _stats(body, self.num_ctx)
            return json.loads(body["message"]["content"])
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise LLMError(f"Ollama ({self.model}) : {exc}") from exc


def _stats(body: dict, num_ctx: int | None = None) -> dict:
    """Durées d'Ollama (nanosecondes) converties en secondes ; champs absents ignorés."""
    seconds = lambda key: round(body[key] / 1e9, 2) if isinstance(body.get(key), (int, float)) else None  # noqa: E731
    stats = {
        "load_s": seconds("load_duration"),                 # chargement du modèle en mémoire GPU
        "prompt_tokens": body.get("prompt_eval_count"),
        "prompt_s": seconds("prompt_eval_duration"),        # lecture du prompt
        "output_tokens": body.get("eval_count"),
        "generation_s": seconds("eval_duration"),           # écriture de la réponse
    }
    if stats["output_tokens"] and stats["generation_s"]:
        stats["tokens_per_s"] = round(stats["output_tokens"] / stats["generation_s"], 1)
    total = seconds("total_duration")
    if total is not None:
        # Hors des durées ci-dessus : surtout la contrainte de sortie JSON (~20-30 ms par token
        # généré, mesuré le 2026-10-21), qui double à peu près le temps de génération.
        stats["other_s"] = round(total - sum(stats[k] or 0 for k in ("load_s", "prompt_s", "generation_s")), 2)
    if num_ctx and stats["prompt_tokens"] is not None:
        stats["truncated"] = stats["prompt_tokens"] >= num_ctx
    return {k: v for k, v in stats.items() if v is not None}
