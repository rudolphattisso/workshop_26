"""Base de connaissances : index tenu à jour, et exemples des fiches compatibles avec les garde-fous
(une fiche qui enseigne une règle refusée ne sert à rien)."""
from conftest import KNOWLEDGE, FakeLLM, llm_output, load_cluster, modsec_spec
from llm_gateway.analyzer import Analyzer
from llm_gateway.contract import AnalyzeRequest
from llm_gateway.rag import Document, HashingEmbedder, InMemoryStore, LocalDocsSource, Retriever


def doc(doc_id, source="internal-docs"):
    return Document(doc_id=doc_id, text=f"texte {doc_id}", source=source, title=doc_id)


def test_sync_removes_passages_that_no_longer_exist_and_keeps_other_sources():
    retriever = Retriever(HashingEmbedder(), InMemoryStore())
    retriever.index([doc("a#un"), doc("a#deux"), doc("rss#article", source="rss")])
    indexed, removed = retriever.sync([doc("a#un")], "internal-docs")             # section « deux » supprimée
    assert (indexed, removed) == (1, 1)
    assert retriever.store.ids("internal-docs") == {"a#un"} and retriever.store.ids("rss") == {"rss#article"}


def test_injection_knowledge_is_found_for_an_injection_cluster(config):
    retriever = Retriever(HashingEmbedder(), InMemoryStore())
    retriever.index(list(LocalDocsSource(KNOWLEDGE).load()))
    from llm_gateway.contract import ClusterSummary
    from llm_gateway.prompts import retrieval_query
    hits = retriever.search(retrieval_query(ClusterSummary.model_validate(load_cluster("sql_injection"))), 4)
    assert any(d.doc_id.startswith("injections.md") for d in hits)


def test_rule_examples_of_the_injection_sheet_pass_the_guardrails(config):
    """Les deux règles de knowledge/injections.md (format attendu, motif sur paramètre décodé)."""
    specs = [
        modsec_spec(("REQUEST_FILENAME", "equals", "/api/payments"), ("ARGS_GET", "regex", "^[0-9]{1,4}$", "limit", True)),
        modsec_spec(("REQUEST_FILENAME", "equals", "/api/payments"),
                    ("ARGS_GET", "regex", "(?i)(union[ +]+select|;[ +]*drop[ +]+table)", "id")),
    ]
    report = Analyzer(config, FakeLLM(llm_output(modsecurity=specs)), "fake").analyze(
        AnalyzeRequest(cluster=load_cluster("sql_injection")))
    assert len(report.analysis.rules) == 2, [r.reason for r in report.rejected_rules]
    text = (KNOWLEDGE / "injections.md").read_text(encoding="utf-8")
    for rule in report.analysis.rules:                   # la fiche montre exactement la syntaxe compilée
        body = [line.strip() for line in rule.content.splitlines() if line.strip() and not line.startswith("#")]
        assert all(part.split('"id:')[0].strip() in text for part in body)
