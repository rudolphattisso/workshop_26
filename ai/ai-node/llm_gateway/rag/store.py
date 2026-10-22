"""Embeddings et stockage vectoriel de la connaissance.

  - OllamaEmbedder : modèle d'embedding servi par Ollama (production, GPU) ;
  - HashingEmbedder : sacs de mots hachés, sans modèle (développement sans GPU, tests) ;
  - ChromaStore : serveur ChromaDB (production, index persistant) ;
  - InMemoryStore : index en mémoire reconstruit au démarrage (développement, tests).
"""
from __future__ import annotations

import hashlib
import math
import re
from abc import ABC, abstractmethod

import httpx
import numpy as np

from .base import Document


class Embedder(ABC):
    @abstractmethod
    def embed(self, texts: list[str]) -> list[list[float]]:
        ...


class OllamaEmbedder(Embedder):
    def __init__(self, base_url: str, model: str, timeout_s: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_s = timeout_s

    def embed(self, texts: list[str]) -> list[list[float]]:
        response = httpx.post(f"{self.base_url}/api/embed", json={"model": self.model, "input": texts},
                              timeout=self.timeout_s)
        response.raise_for_status()
        return response.json()["embeddings"]


class HashingEmbedder(Embedder):
    """Vecteur de fréquences de mots hachés (pas de sens sémantique, mais déterministe)."""

    def __init__(self, dim: int = 512):
        self.dim = dim

    def embed(self, texts: list[str]) -> list[list[float]]:
        out = []
        for text in texts:
            vec = [0.0] * self.dim
            for word in re.findall(r"[a-zà-ÿ0-9_]{3,}", text.lower()):
                vec[int(hashlib.md5(word.encode()).hexdigest(), 16) % self.dim] += 1.0
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            out.append([v / norm for v in vec])
        return out


class VectorStore(ABC):
    @abstractmethod
    def upsert(self, docs: list[Document], embeddings: list[list[float]]) -> None:
        ...

    @abstractmethod
    def query(self, embedding: list[float], k: int) -> list[Document]:
        ...

    @abstractmethod
    def ids(self, source: str) -> set[str]:
        """Identifiants des passages indexés provenant de `source`."""

    @abstractmethod
    def delete(self, ids: set[str]) -> None:
        ...


class InMemoryStore(VectorStore):
    def __init__(self):
        self._docs: dict[str, Document] = {}
        self._vecs: dict[str, np.ndarray] = {}

    def upsert(self, docs: list[Document], embeddings: list[list[float]]) -> None:
        for doc, emb in zip(docs, embeddings):
            vec = np.asarray(emb, dtype=float)
            self._docs[doc.doc_id] = doc
            self._vecs[doc.doc_id] = vec / (np.linalg.norm(vec) or 1.0)

    def query(self, embedding: list[float], k: int) -> list[Document]:
        if not self._docs:
            return []
        q = np.asarray(embedding, dtype=float)
        q = q / (np.linalg.norm(q) or 1.0)
        ranked = sorted(self._vecs, key=lambda i: -float(self._vecs[i] @ q))
        return [self._docs[i] for i in ranked[:k]]

    def ids(self, source: str) -> set[str]:
        return {i for i, d in self._docs.items() if d.source == source}

    def delete(self, ids: set[str]) -> None:
        for i in ids:
            self._docs.pop(i, None)
            self._vecs.pop(i, None)


class ChromaStore(VectorStore):
    """Serveur ChromaDB (conteneur « chroma » du PC IA). Les embeddings sont calculés ici."""

    def __init__(self, host: str, port: int, collection: str):
        import chromadb  # import tardif : dépendance absente des tests

        client = chromadb.HttpClient(host=host, port=port)
        self._col = client.get_or_create_collection(collection, metadata={"hnsw:space": "cosine"})

    def upsert(self, docs: list[Document], embeddings: list[list[float]]) -> None:
        self._col.upsert(
            ids=[d.doc_id for d in docs],
            embeddings=embeddings,
            documents=[d.text for d in docs],
            metadatas=[{"source": d.source, "title": d.title, "url": d.url} for d in docs],
        )

    def query(self, embedding: list[float], k: int) -> list[Document]:
        res = self._col.query(query_embeddings=[embedding], n_results=k)
        return [
            Document(doc_id=i, text=t, source=m.get("source", ""), title=m.get("title", ""), url=m.get("url", ""))
            for i, t, m in zip(res["ids"][0], res["documents"][0], res["metadatas"][0])
        ]

    def ids(self, source: str) -> set[str]:
        return set(self._col.get(where={"source": source}, include=[])["ids"])

    def delete(self, ids: set[str]) -> None:
        if ids:
            self._col.delete(ids=sorted(ids))


class Retriever:
    def __init__(self, embedder: Embedder, store: VectorStore):
        self.embedder = embedder
        self.store = store

    def index(self, docs: list[Document], batch: int = 32) -> int:
        for start in range(0, len(docs), batch):
            chunk = docs[start:start + batch]
            self.store.upsert(chunk, self.embedder.embed([f"{d.title}\n{d.text}" for d in chunk]))
        return len(docs)

    def sync(self, docs: list[Document], source: str) -> tuple[int, int]:
        """Réindexe TOUTE la source et retire les passages qui n'y sont plus (section supprimée ou
        renommée) : sans ça, ChromaDB les garderait et le LLM citerait une doc disparue. Les autres
        sources (veille RSS...) ne sont pas touchées. Renvoie (indexés, retirés)."""
        stale = self.store.ids(source) - {d.doc_id for d in docs}
        self.store.delete(stale)
        return self.index(docs), len(stale)

    def search(self, query: str, k: int) -> list[Document]:
        if not query:
            return []
        return self.store.query(self.embedder.embed([query])[0], k)
