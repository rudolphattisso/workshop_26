"""Interface d'accès au modèle de langage (implémentation prévue : Ollama sur GPU)."""
from __future__ import annotations

from abc import ABC, abstractmethod


class LLMClient(ABC):
    # Statistiques du dernier appel, si le moteur les fournit (Ollama : chargement, tokens lus et
    # générés, durées en secondes). None sinon.
    last_stats: dict | None = None

    @abstractmethod
    def generate_json(self, system: str, user: str, schema: dict, timeout_s: float = 60.0) -> dict:
        """Renvoie la réponse du modèle sous forme de dict conforme à `schema` (JSON Schema).

        Le contenu reste NON FIABLE : l'appelant le revalide et filtre les règles dangereuses
        (whitelist d'IP, SecRuleEngine Off, désactivation du CRS...) avant de l'exposer.
        """
