"""Fichier de recommandations : un Markdown par analyse, relu puis copié-collé par un opérateur.

Rien n'est appliqué automatiquement. Les règles refusées par les garde-fous n'apparaissent que
par leur motif, jamais par leur contenu (pour qu'on ne puisse pas les copier par erreur).
"""
from __future__ import annotations

from pathlib import Path

from .contract import AnalysisReport, ClusterSummary, Engine

_FENCE = {Engine.MODSECURITY: "apache", Engine.BUNKERWEB: "ini"}
_WHERE = {
    Engine.MODSECURITY: "fichier de règles ModSecurity personnalisées de BunkerWeb (ex. modsec/ai-rules.conf)",
    Engine.BUNKERWEB: "variables d'environnement / configuration du service dans BunkerWeb",
}


class RulesWriter:
    def __init__(self, directory: Path):
        self.directory = Path(directory)

    def write(self, report: AnalysisReport, cluster: ClusterSummary, context: dict | None = None) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        stamp = report.generated_at.replace("-", "").replace(":", "")[:15]
        path = self.directory / f"{stamp}Z_{report.signature}.md"
        path.write_text(render(report, cluster, context), encoding="utf-8")
        return path


def render(report: AnalysisReport, cluster: ClusterSummary, context: dict | None = None) -> str:
    a = report.analysis
    context = context if isinstance(context, dict) else {}
    escalation = context.get("escalade") if isinstance(context.get("escalade"), dict) else {}
    blind = []
    if escalation.get("trigger") == "perte_de_visibilite":
        blind = [f"> **PERTE DE VISIBILITÉ** : le détecteur ne reçoit plus de journaux exploitables. Analyse faite "
                 f"sur les données d'avant la coupure (jusqu'à {_clean(escalation.get('donnees_jusqu_a'))}).", "",
                 *[f"> - {_clean(r)}" for r in escalation.get("reasons") or []], ""]
    lines = [
        f"# Analyse SOC — {a.attack_type or 'anomalie'} ({cluster.window_start} → {cluster.window_end})",
        "",
        "> Recommandations produites par l'IA. **Rien n'est appliqué automatiquement** : relire chaque",
        "> règle, vérifier ses effets de bord, puis la copier à l'endroit indiqué.",
        "",
        *blind,
        *[line for w in report.warnings for line in (f"> **AVERTISSEMENT** : {w}", "")],
        f"- **Verdict** : {a.verdict.value} (confiance {a.confidence.value})",
        f"- **Cluster** : `{report.signature}` / {cluster.cluster_id} — {cluster.n_requests} requêtes, "
        f"{cluster.n_distinct_ips} IP, {cluster.blocked_ratio:.0%} déjà bloquées par le WAF",
        f"- **Indices du détecteur** : {', '.join(cluster.attack_hints)}",
        f"- **Modèle** : {report.model}" + (" — **analyse dégradée (LLM indisponible)**" if report.degraded else ""),
        "",
        "## Diagnostic",
        "",
        a.summary,
        "",
        f"**Impact** : {a.impact or 'non évalué'}",
        "",
        "**Éléments factuels** :",
        *[f"- {e}" for e in a.evidence],
        "",
        *_infra_actions(context),
        "## Règles proposées",
        "",
    ]
    if not a.rules:
        lines += ["Aucune règle proposée.", ""]
    for n, rule in enumerate(a.rules, 1):
        provenance = f"# IA {report.generated_at} — cluster {report.signature} — à relire avant application"
        lines += [
            f"### Règle {n} — {rule.engine.value}",
            "",
            f"**Où** : {_WHERE[rule.engine]}",
            "",
            f"**Ce qu'elle fait** : {rule.explanation}",
            "",
            f"**Effets de bord** : {rule.side_effects}",
            "",
            f"```{_FENCE[rule.engine]}",
            provenance,
            rule.content.strip(),
            "```",
            "",
        ]
    if report.already_proposed:
        lines += ["## Règles déjà proposées", "",
                  "Identiques à une règle d'un rapport récent : toujours valables, non recopiées ici.", "",
                  *[f"- {r['engine']} : rapport `{r['rapport']}` ({r['date']})" for r in report.already_proposed], ""]
    if report.rejected_rules:
        lines += ["## Propositions écartées par les garde-fous", ""]
        lines += [f"- {r.engine} : {r.reason}" for r in report.rejected_rules]
        lines.append("")
    if a.ideas_to_review:
        lines += ["## Pistes à expertiser", "",
                  "Idées que la grammaire de règles ne permet pas d'écrire directement : à formuler et "
                  "valider par un expert avant toute mise en œuvre.", "",
                  *[f"- {x}" for x in a.ideas_to_review], ""]
    if a.operator_actions:
        lines += ["## Actions conseillées à l'opérateur", "", *[f"- {x}" for x in a.operator_actions], ""]
    if a.uncertainties:
        lines += ["## Incertitudes", "", *[f"- {x}" for x in a.uncertainties], ""]
    if report.knowledge_used:
        lines += ["## Sources consultées (RAG)", "", *[f"- `{d}`" for d in report.knowledge_used], ""]
    if report.timings:
        lines += ["## Temps d'analyse", "", _timings_line(report.timings), ""]
    return "\n".join(lines)


def _clean(value, limit: int = 200) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _infra_actions(context: dict) -> list[str]:
    """Actions automatiques de l'infra (journal du moteur de remédiation), telles que relevées."""
    actions = [a for a in context.get("actions_infra") or [] if isinstance(a, dict)]
    if not actions:
        return []
    lines = ["## Actions automatiques de l'infra (15 dernières minutes)", "",
             "| Heure | Événement | Alerte | Action | Cible | Détail |", "|---|---|---|---|---|---|"]
    for a in actions:
        cells = [_clean(a.get(k), 120).replace("|", "/") for k in ("heure", "evenement", "alerte", "action", "cible", "detail")]
        lines.append("| " + " | ".join(cells) + " |")
    return lines + [""]


def _timings_line(t) -> str:
    parts = [f"total {t.total_s:.1f} s", f"LLM {t.llm_s:.1f} s"]
    if t.queue_s >= 0.1:
        parts.append(f"attente du GPU {t.queue_s:.1f} s")
    if t.load_s:
        parts.append(f"chargement du modèle {t.load_s:.1f} s")
    if t.prompt_tokens is not None and t.prompt_s is not None:
        parts.append(f"lecture du prompt {t.prompt_s:.1f} s ({t.prompt_tokens} tokens)")
    if t.output_tokens is not None and t.generation_s is not None:
        speed = f", {t.tokens_per_s:.0f} tokens/s" if t.tokens_per_s else ""
        parts.append(f"génération {t.generation_s:.1f} s ({t.output_tokens} tokens{speed})")
    if t.other_s:
        parts.append(f"contrainte de format JSON et divers {t.other_s:.1f} s")
    parts.append(f"RAG {t.rag_s:.2f} s")
    return " · ".join(parts)
