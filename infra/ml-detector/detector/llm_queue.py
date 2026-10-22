"""File d'attente vers le LLM : une place par campagne, la plus grave d'abord, sans données périmées.

Le LLM traite une analyse à la fois (~40-55 s, verrou GPU du gateway) alors que l'escalade peut en
produire jusqu'à 2 par minute : pendant un pic, la file grossit. Règles :
  - une campagne n'a qu'UNE place : une nouvelle escalade de la même campagne remplace son résumé
    par le plus récent (fusion) au lieu de s'ajouter ;
  - la plus grave sort en premier (un échec de remédiation ne patiente pas derrière un scan) ;
  - une analyse qui attend depuis plus de `max_age_s` est écartée : ses données ne décrivent plus
    la situation ; si la campagne dure, elle sera réescaladée avec des données fraîches ;
  - au-delà de `max_size`, la moins grave est écartée.
Toute analyse écartée est signalée (`on_drop`) pour que l'escalade libère son délai de garde.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class QueuedAnalysis:
    key: object                    # identité de campagne (escalation.campaign_key) ou du symptôme
    severity: int
    queued_at: datetime            # date de la PREMIÈRE mise en file (la fusion ne la rajeunit pas)
    item: dict                     # {"trigger", "cluster", "context"}
    merged: int = 0                # escalades fusionnées dans cette place
    seq: int = field(default=0, compare=False)


class LlmQueue:
    def __init__(self, max_size: int = 10, max_age_s: int = 300, on_drop=None):
        self.max_size, self.max_age_s, self.on_drop = max_size, max_age_s, on_drop
        self._items: dict[object, QueuedAnalysis] = {}
        self._cond = threading.Condition()
        self._seq = 0

    def put(self, key, severity: int, item: dict, now: datetime) -> None:
        with self._cond:
            current = self._items.get(key)
            if current:
                current.item, current.severity, current.merged = item, max(severity, current.severity), current.merged + 1
            else:
                self._seq += 1
                self._items[key] = QueuedAnalysis(key, severity, now, item, seq=self._seq)
                if len(self._items) > self.max_size:
                    weakest = min(self._items.values(), key=lambda q: (q.severity, -q.seq))
                    self._drop(weakest, "file pleine")
            self._cond.notify()

    def get(self, now_fn, timeout: float = 0.5) -> QueuedAnalysis | None:
        """Prend la plus grave (à égalité : la plus ancienne), après avoir écarté les périmées."""
        with self._cond:
            if not self._items:
                self._cond.wait(timeout)
            now = now_fn()
            for q in [q for q in self._items.values() if (now - q.queued_at).total_seconds() > self.max_age_s]:
                self._drop(q, "périmée")
            if not self._items:
                return None
            best = max(self._items.values(), key=lambda q: (q.severity, -q.seq))
            del self._items[best.key]
            return best

    def _drop(self, q: QueuedAnalysis, why: str) -> None:
        del self._items[q.key]
        if self.on_drop:
            self.on_drop(q, why)

    def __len__(self) -> int:
        return len(self._items)
