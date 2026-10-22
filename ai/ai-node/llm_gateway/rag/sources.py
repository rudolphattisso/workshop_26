"""Sources de connaissance : documentation locale (à implémenter) et flux RSS (emplacement réservé)."""
from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from .base import Document, KnowledgeSource

_HEADING = re.compile(r"^(#{1,3})\s+(.+?)\s*$")


def _sections(markdown: str) -> list[tuple[str, str]]:
    """Découpe sur les titres ; le titre parent est conservé (« Doc > Section ») pour le contexte."""
    out, stack, lines = [], [], []

    def flush():
        body = "\n".join(lines).strip()
        if body:
            out.append((" > ".join(stack) or "Introduction", body))

    for line in markdown.splitlines():
        match = _HEADING.match(line)
        if match:
            flush()
            lines = []
            level = len(match.group(1))
            stack = stack[: level - 1] + [match.group(2)]
        else:
            lines.append(line)
    flush()
    return out


def _slug(title: str) -> str:
    ascii_title = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_title.lower()).strip("-")
    if len(slug) <= 80:
        return slug
    # Tronqué : deux sections au début de titre identique (« Méthode 1 », « Méthode 2 ») auraient le
    # même identifiant, et l'une écraserait l'autre dans l'index. Empreinte du titre complet.
    return f"{slug[:72].rstrip('-')}-{hashlib.sha1(title.encode()).hexdigest()[:7]}"


class LocalDocsSource(KnowledgeSource):
    """Fichiers Markdown/texte du dossier knowledge/ (docs infra, OWASP, syntaxe des règles WAF).

    Un Document par section (titre Markdown de niveau 1 à 3) : des passages courts et
    cohérents se retrouvent mieux et tiennent dans le prompt.
    """

    name = "internal-docs"

    def __init__(self, root: Path):
        self.root = Path(root)

    def load(self, since: datetime | None = None) -> Iterable[Document]:
        for path in sorted(self.root.rglob("*")):
            if path.suffix.lower() not in (".md", ".txt") or not path.is_file():
                continue
            modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            if since is not None and modified <= since:
                continue
            rel = path.relative_to(self.root).as_posix()
            for title, text in _sections(path.read_text(encoding="utf-8")):
                yield Document(doc_id=f"{rel}#{_slug(title)}", text=text, source=self.name,
                               title=title, published=modified)


class RssFeedSource(KnowledgeSource):
    """EMPLACEMENT RÉSERVÉ — veille sécurité par flux RSS (CERT-FR, CVE, éditeurs...).

    Points d'attention pour l'implémentation :
      - le contenu RSS est externe et NON FIABLE (injection de prompt indirecte possible) :
        le marquer comme tel dans les métadonnées et le présenter au LLM comme une citation ;
      - liste blanche des flux autorisés, taille maximale par article, dédoublonnage par guid ;
      - le PC IA a besoin d'un accès Internet sortant pour cette source uniquement.
    """

    name = "rss"

    def __init__(self, feeds: list[str]):
        self.feeds = feeds

    def load(self, since: datetime | None = None) -> Iterable[Document]:
        raise NotImplementedError("Source RSS prévue pour une version ultérieure")
