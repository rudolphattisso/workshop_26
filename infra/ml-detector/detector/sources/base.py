"""Interface commune à toutes les sources de journaux WAF."""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from ..models import HttpRequestLog


class LogSource(ABC):
    """Fournit les requêtes HTTP vues par le WAF sur un intervalle de temps.

    Implémentations : SimulatedSource (développement, démo) ; LokiSource (production,
    lecture de {service="bunkerweb"} sur le réseau monitoring de l'infra).
    """

    @abstractmethod
    def fetch(self, start: datetime, end: datetime) -> list[HttpRequestLog]:
        """Requêtes dont l'horodatage est dans [start, end[, triées par date."""
