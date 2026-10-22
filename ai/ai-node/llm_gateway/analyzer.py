"""Orchestration d'une analyse : RAG -> LLM -> garde-fous -> fichier de recommandations."""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import ValidationError

from . import consistency, guardrails
from .config import GatewayConfig
from .contract import (AnalysisReport, AnalyzeRequest, ClusterSummary, Confidence, LlmAnalysis, LlmOutput, Timings,
                       Verdict, llm_output_schema)
from .llm import LLMClient, LLMError
from .prompts import build_system_prompt, build_user_prompt, retrieval_query
from .rule_compiler import RuleIdAllocator, compile_output, normalized
from .rag import Retriever
from .rules_writer import RulesWriter

log = logging.getLogger("llm_gateway")


class Analyzer:
    def __init__(self, config: GatewayConfig, llm: LLMClient, model_name: str,
                 retriever: Retriever | None = None, writer: RulesWriter | None = None,
                 rule_ids: RuleIdAllocator | None = None):
        self.config = config
        self.llm = llm
        self.model_name = model_name
        self.retriever = retriever
        self.writer = writer
        self.rule_ids = rule_ids or RuleIdAllocator(config.rule_id_min, config.rule_id_max)
        self._llm_lock = threading.Lock()      # un seul GPU : une génération à la fois
        self._rules_lock = threading.Lock()
        self._recent_rules: dict[str, tuple[datetime, str]] = {}   # règle normalisée -> (date, rapport)

    def analyze(self, request: AnalyzeRequest) -> AnalysisReport:
        cluster = request.cluster
        start = time.perf_counter()
        knowledge = []
        if self.retriever is not None:
            try:
                knowledge = self.retriever.search(retrieval_query(cluster), self.config.rag_top_k)
            except Exception as exc:                       # le RAG est un plus, pas un prérequis
                log.warning("RAG indisponible : %s", exc)
        rag_s = time.perf_counter() - start

        degraded = False
        queue_s = llm_s = 0.0
        try:
            waiting = time.perf_counter()
            with self._llm_lock:
                queue_s = time.perf_counter() - waiting
                called = time.perf_counter()
                try:
                    raw = self.llm.generate_json(
                        build_system_prompt(self.config),
                        build_user_prompt(cluster, request.context, knowledge, self.config),
                        llm_output_schema(),
                        timeout_s=self.config.llm_timeout_s,
                    )
                finally:
                    llm_s = time.perf_counter() - called
            analysis, compile_rejected = compile_output(LlmOutput.model_validate(raw), self.rule_ids)
        except (LLMError, ValidationError) as exc:
            log.warning("analyse dégradée pour %s : %s", cluster.signature, exc)
            analysis, degraded, compile_rejected = fallback_analysis(cluster, _short(exc)), True, []

        analysis, rejected = guardrails.validate(analysis, cluster, self.config)
        rejected = compile_rejected + rejected
        timings = Timings(total_s=round(time.perf_counter() - start, 2), rag_s=round(rag_s, 2),
                          queue_s=round(queue_s, 2), llm_s=round(llm_s, 2), **(self.llm.last_stats or {}))
        log.info("analyse %s : %.1f s (LLM %.1f s, attente GPU %.1f s)", cluster.signature,
                 timings.total_s, timings.llm_s, timings.queue_s)
        report = AnalysisReport(
            signature=cluster.signature,
            cluster_id=cluster.cluster_id,
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            model=self.model_name,
            degraded=degraded,
            analysis=analysis,
            rejected_rules=rejected,
            knowledge_used=[d.doc_id for d in knowledge],
            rules_file=None,
            warnings=consistency.warnings_for(analysis, cluster) + (
                ["Le prompt a atteint la taille de contexte du modèle : une partie a pu être ignorée "
                 "(augmenter LLM_NUM_CTX)."] if timings.truncated else []),
            timings=timings,
        )
        report = self._mark_already_proposed(report)
        if self.writer is not None:
            report.rules_file = str(self.writer.write(report, cluster, request.context))
        self._remember_rules(report)
        return report

    def _mark_already_proposed(self, report: AnalysisReport) -> AnalysisReport:
        """Une règle identique (hors id et message) à une règle d'un rapport des dernières 24 h est
        citée (« déjà proposée dans le rapport X ») au lieu d'être recopiée : une réanalyse ou deux
        campagnes voisines ne doivent pas faire copier deux fois la même règle."""
        now = datetime.now(timezone.utc)
        with self._rules_lock:
            self._recent_rules = {k: v for k, v in self._recent_rules.items()
                                  if now - v[0] < timedelta(hours=self.config.recent_rules_hours)}
            kept, cited = [], []
            for rule in report.analysis.rules:
                previous = self._recent_rules.get(normalized(rule))
                if previous:
                    cited.append({"engine": rule.engine.value, "rapport": previous[1], "date": previous[0].isoformat(timespec="seconds")})
                else:
                    kept.append(rule)
        if not cited:
            return report
        return report.model_copy(update={"analysis": report.analysis.model_copy(update={"rules": kept}),
                                         "already_proposed": cited})

    def _remember_rules(self, report: AnalysisReport) -> None:
        name = Path(report.rules_file).name if report.rules_file else report.signature
        with self._rules_lock:
            for rule in report.analysis.rules:
                self._recent_rules[normalized(rule)] = (datetime.now(timezone.utc), name)


def fallback_analysis(cluster: ClusterSummary, reason: str) -> LlmAnalysis:
    """Sans LLM : on restitue les faits du détecteur, sans verdict ni règle inventés."""
    return LlmAnalysis(
        verdict=Verdict.UNDETERMINED,
        confidence=Confidence.LOW,
        attack_type=", ".join(cluster.attack_hints)[:120],
        summary=(f"Analyse automatique indisponible ({reason}). Le détecteur signale {cluster.n_requests} "
                 f"requêtes anormales depuis {cluster.n_distinct_ips} IP ; indices : "
                 f"{', '.join(cluster.attack_hints)}."),
        evidence=[f"chemins : {', '.join(str(p.get('path')) for p in cluster.top_paths[:3])}",
                  f"statuts : {cluster.statuses}",
                  f"part déjà bloquée par le WAF : {cluster.blocked_ratio:.0%}"],
        impact="",
        rules=[],
        operator_actions=["Examiner le cluster manuellement (Grafana / Loki) avant toute mesure."],
        uncertainties=[reason],
    )


def _short(exc: Exception) -> str:
    text = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
    return text[:200]
