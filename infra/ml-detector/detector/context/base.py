"""Fournisseurs de contexte « en direct » joints au résumé de cluster envoyé au LLM.

Le ml-detector tourne sur le PC infra : c'est lui qui rassemble tout le contexte et l'envoie
en un seul paquet. Le PC IA reste passif (aucun accès à l'infra).

Ces données ne vont JAMAIS dans la base vectorielle : elles sont propres à un incident.
La base vectorielle (PC IA) ne contient que de la connaissance stable (docs, OWASP, RSS).
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import ClusterSummary


class ContextProvider(ABC):
    """Ajoute une section de contexte pour un cluster (ex. métriques, alertes SIEM)."""

    name: str = "context"

    @abstractmethod
    def collect(self, cluster: ClusterSummary) -> dict:
        """Renvoie un dict sérialisable en JSON ; {} si rien de pertinent."""


class PrometheusContext(ContextProvider):
    """À IMPLÉMENTER : débit, taux d'erreurs et latence p95 de payment-api / auth sur la
    fenêtre du cluster (http://prometheus:9090/api/v1/query_range)."""

    name = "prometheus"

    def collect(self, cluster: ClusterSummary) -> dict:
        raise NotImplementedError


class WazuhContext(ContextProvider):
    """À IMPLÉMENTER : alertes Wazuh ({service="wazuh"} dans Loki) des IP du cluster sur la
    même fenêtre (règles 100101 XSS, 100102 SQLi, 100110/100112 DDoS, 100201 force brute)."""

    name = "wazuh"

    def collect(self, cluster: ClusterSummary) -> dict:
        raise NotImplementedError
