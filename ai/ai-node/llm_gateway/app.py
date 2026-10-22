"""API HTTP du PC IA. Un seul appelant : le ml-detector du PC infra.

    POST /analyze     Authorization: Bearer <LLM_GATEWAY_TOKEN>   corps : AnalyzeRequest
    POST /heartbeat   (même jeton) signal de vie du détecteur, toutes les 30 s
    GET  /health      état de la gateway et du détecteur (« muet » sans signal depuis 2 min)

Lancement : uvicorn --factory llm_gateway.app:create_app --host 0.0.0.0 --port 8080
(l'application n'est construite qu'au lancement : les tests importent ce module sans jeton ni Ollama)
"""
from __future__ import annotations

import hmac
import html
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from .analyzer import Analyzer
from .config import GatewayConfig
from .contract import AnalysisReport, AnalyzeRequest, Heartbeat
from .llm import OllamaClient
from .rag import ChromaStore, HashingEmbedder, InMemoryStore, LocalDocsSource, OllamaEmbedder, Retriever
from .rule_compiler import allocator_for
from .rules_writer import RulesWriter

log = logging.getLogger("llm_gateway")


def build_retriever(config: GatewayConfig, index_if_memory: bool = True) -> Retriever:
    embedder = (HashingEmbedder() if config.embedder == "hashing"
                else OllamaEmbedder(config.ollama_url, config.embed_model))
    if config.vector_store == "memory":
        retriever = Retriever(embedder, InMemoryStore())
        if index_if_memory:
            n = retriever.index(list(LocalDocsSource(config.knowledge_dir).load()))
            log.info("index RAG en mémoire : %d passages", n)
        return retriever
    return Retriever(embedder, ChromaStore(config.chroma_host, config.chroma_port, config.collection))


def build_analyzer(config: GatewayConfig) -> Analyzer:
    return Analyzer(
        config,
        OllamaClient(config.ollama_url, config.ollama_model, config.temperature, config.num_ctx,
                     config.keep_alive),
        model_name=config.ollama_model,
        retriever=build_retriever(config),
        writer=RulesWriter(config.rules_dir),
        rule_ids=allocator_for(config),
    )


class DetectorWatch:
    """Dernier signal de vie du détecteur. Vu depuis le PC IA, indépendant du PC infra : si
    l'attaque fait tomber le PC infra ou le réseau, c'est ici que ça se voit."""
    SILENT_AFTER_S = 120

    def __init__(self, clock=time.time):
        self.clock = clock
        self.last: Heartbeat | None = None
        self.received_at: float | None = None

    def beat(self, heartbeat: Heartbeat) -> None:
        self.last, self.received_at = heartbeat, self.clock()

    def status(self) -> dict:
        if self.received_at is None:
            return {"etat": "inconnu", "message": "aucun signal du détecteur depuis le démarrage de la gateway"}
        age = self.clock() - self.received_at
        since = datetime.fromtimestamp(self.received_at, timezone.utc).strftime("%H:%M:%S")
        if age > self.SILENT_AFTER_S:
            state, message = "muet", (f"détecteur muet depuis {since} UTC ({age:.0f} s) : PC infra arrêté, "
                                      "réseau coupé ou détecteur tombé")
        elif self.last.statut == "aveugle":
            state, message = "aveugle", (f"le détecteur ne lit plus les journaux depuis "
                                         f"{self.last.derniere_lecture or 'son démarrage'} (Loki injoignable ?)")
        else:
            state, message = "ok", "détecteur actif"
        return {"etat": state, "message": message, "dernier_signal_s": round(age)}


def create_app(config: GatewayConfig | None = None, analyzer: Analyzer | None = None,
               watch: DetectorWatch | None = None) -> FastAPI:
    config = config or GatewayConfig()
    if len(config.token) < 32:
        raise RuntimeError("LLM_GATEWAY_TOKEN absent ou trop court (32 caractères minimum)")
    analyzer = analyzer or build_analyzer(config)
    watch = watch or DetectorWatch()
    app = FastAPI(title="llm-gateway", docs_url=None, redoc_url=None, openapi_url=None)

    async def authorized(request: Request, authorization: str = Header(default="")) -> None:
        if int(request.headers.get("content-length") or 0) > config.max_body_bytes:
            raise HTTPException(status_code=413, detail="corps trop volumineux")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(token.encode(), config.token.encode()):
            raise HTTPException(status_code=401, detail="jeton invalide")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "model": analyzer.model_name, "detecteur": watch.status()["etat"]}

    @app.post("/heartbeat", dependencies=[Depends(authorized)])
    def heartbeat(body: Heartbeat) -> dict:
        previous = watch.status()["etat"]
        watch.beat(body)
        if watch.status()["etat"] != previous:
            log.info("détecteur : %s -> %s", previous, watch.status()["etat"])
        return {"ok": True}

    @app.post("/analyze", response_model=AnalysisReport, dependencies=[Depends(authorized)])
    def analyze(body: AnalyzeRequest) -> AnalysisReport:      # synchrone : exécuté dans un thread
        return analyzer.analyze(body)

    add_report_pages(app, config, watch)
    return app


# -- consultation des rapports (lien depuis le tableau des incidents de Grafana) ------------------
_REPORT_NAME = re.compile(r"^\d{8}T\d{6}Z_[A-Za-z0-9_-]{1,64}\.md$")
_PAGE = ("<!doctype html><html lang='fr'><head><meta charset='utf-8'><title>{title}</title><style>"
         "body{{font-family:system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;line-height:1.5}}"
         "pre{{white-space:pre-wrap;word-break:break-word;background:#f6f6f6;padding:1rem;border-radius:6px}}"
         "a{{color:#1a5fb4}}</style></head><body>{body}</body></html>")


def add_report_pages(app: FastAPI, config: GatewayConfig, watch: DetectorWatch | None = None) -> None:
    """Pages en lecture seule : /reports (liste) et /reports/<fichier> (rapport). Authentification
    « basic » (utilisateur soc, REPORTS_PASSWORD) : le navigateur la demande lui-même. Sans mot de
    passe configuré, les pages n'existent pas. Le contenu vient en partie de l'attaquant (URI
    assainies) : tout est échappé en HTML, jamais interprété."""
    security = HTTPBasic(auto_error=False)

    def viewer(credentials: HTTPBasicCredentials | None = Depends(security)) -> None:
        if not config.reports_password:
            raise HTTPException(status_code=404)
        ok = credentials is not None and hmac.compare_digest(credentials.username.encode(), b"soc") \
            and hmac.compare_digest(credentials.password.encode(), config.reports_password.encode())
        if not ok:
            raise HTTPException(status_code=401, headers={"WWW-Authenticate": 'Basic realm="rapports SOC"'})

    def banner() -> str:
        status = watch.status() if watch else {"etat": "ok"}
        if status["etat"] == "ok":
            return ""
        return ("<p style='background:#fde8e8;border-left:4px solid #b42318;padding:.75rem 1rem'><strong>"
                f"{html.escape(status['message'])}</strong><br>Les rapports ci-dessous peuvent ne plus refléter "
                "la situation actuelle.</p>")

    @app.get("/reports", response_class=HTMLResponse, dependencies=[Depends(viewer)])
    def list_reports() -> str:
        files = sorted((p for p in Path(config.rules_dir).glob("*.md") if _REPORT_NAME.match(p.name)), reverse=True)
        rows = []
        for path in files[:200]:
            title = path.read_text(encoding="utf-8").splitlines()[0].lstrip("# ") if path.stat().st_size else path.name
            rows.append(f"<li><a href='/reports/{html.escape(path.name)}'>{html.escape(path.name[:15])}</a> — "
                        f"{html.escape(title)}</li>")
        return _PAGE.format(title="Rapports SOC", body=f"<h1>Rapports SOC</h1>{banner()}<ul>{''.join(rows) or '<li>aucun</li>'}</ul>")

    @app.get("/reports/{name}", response_class=HTMLResponse, dependencies=[Depends(viewer)])
    def show_report(name: str) -> str:
        path = Path(config.rules_dir) / name
        if not _REPORT_NAME.match(name) or not path.is_file():
            raise HTTPException(status_code=404)
        text = path.read_text(encoding="utf-8")
        return _PAGE.format(title=html.escape(name), body=f"<p><a href='/reports'>Tous les rapports</a></p>{banner()}"
                                                          f"<pre>{html.escape(text)}</pre>")
