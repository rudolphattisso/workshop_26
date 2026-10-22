"""Outils en ligne de commande du PC IA.

    python -m llm_gateway.cli index                       # indexe knowledge/ dans la base vectorielle
    python -m llm_gateway.cli analyze cluster.json [--context ctx.json] [--no-write]
                                                          # analyse un résumé de cluster (sans HTTP)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analyzer import Analyzer
from .app import build_retriever
from .config import GatewayConfig
from .contract import AnalyzeRequest
from .llm import OllamaClient
from .rag import LocalDocsSource
from .rule_compiler import allocator_for
from .rules_writer import RulesWriter


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("index", help="indexe le dossier de connaissance")
    an = sub.add_parser("analyze", help="analyse un résumé de cluster JSON")
    an.add_argument("cluster", type=Path)
    an.add_argument("--context", type=Path)
    an.add_argument("--no-write", action="store_true", help="n'écrit pas le fichier de recommandations")
    args = parser.parse_args(argv)
    config = GatewayConfig()

    if args.command == "index":
        docs = list(LocalDocsSource(config.knowledge_dir).load())
        n, removed = build_retriever(config, index_if_memory=False).sync(docs, LocalDocsSource.name)
        print(f"{n} passages indexés depuis {config.knowledge_dir} ({config.vector_store}), "
              f"{removed} passage(s) disparu(s) retiré(s)")
        return 0

    request = AnalyzeRequest(
        cluster=json.loads(args.cluster.read_text(encoding="utf-8")),
        context=json.loads(args.context.read_text(encoding="utf-8")) if args.context else {},
    )
    analyzer = Analyzer(config, OllamaClient(config.ollama_url, config.ollama_model, config.temperature, config.num_ctx,
                     config.keep_alive),
                        model_name=config.ollama_model, retriever=build_retriever(config),
                        writer=None if args.no_write else RulesWriter(config.rules_dir),
                        rule_ids=allocator_for(config))
    print(analyzer.analyze(request).model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
