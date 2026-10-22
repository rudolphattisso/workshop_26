"""Connaissance STABLE indexée dans la base vectorielle (ChromaDB).

Ne contient que des documents de référence (docs internes, OWASP, syntaxe BunkerWeb /
ModSecurity, puis flux RSS de veille). Les données d'incident (logs, métriques, alertes)
n'y entrent jamais : elles arrivent dans la requête /analyze envoyée par le ml-detector.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class Document:
    doc_id: str                  # stable : réindexer un document le remplace au lieu de le dupliquer
    text: str
    source: str                  # "internal-docs", "owasp", "rss:<flux>"...
    title: str = ""
    url: str = ""
    published: datetime | None = None
    metadata: dict = field(default_factory=dict)


class KnowledgeSource(ABC):
    """Fournit des documents à indexer. Une source = un type d'origine."""

    name: str = "source"

    @abstractmethod
    def load(self, since: datetime | None = None) -> Iterable[Document]:
        """Documents nouveaux ou modifiés depuis `since` (tous si None)."""
