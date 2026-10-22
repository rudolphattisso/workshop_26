"""Grammaire de règles : le LLM décrit, le gateway écrit la syntaxe."""
import re

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from conftest import KNOWLEDGE, FakeLLM, bw_spec, llm_output, load_cluster, modsec_spec
from llm_gateway import guardrails
from llm_gateway.analyzer import Analyzer
from llm_gateway.contract import (AnalyzeRequest, BunkerWebChangeSpec, Condition, ModSecOperator, ModSecRuleSpec,
                                  ModSecVariable)
from llm_gateway.rag import HashingEmbedder, InMemoryStore, LocalDocsSource, Retriever
from llm_gateway.rule_compiler import CompileError, RuleIdAllocator, compile_bunkerweb, compile_modsecurity
from llm_gateway.rules_writer import RulesWriter


def spec(*conditions, **kw):
    return ModSecRuleSpec.model_validate(modsec_spec(*conditions, **kw))


def lines(content):
    return [line.strip() for line in content.splitlines() if line.strip()]


def test_single_condition_gets_id_phase_and_quoted_message():
    out = compile_modsecurity(spec(("ARGS_GET", "greater_than", "1000", "limit"), message="Export d'un \"gros\" lot"), 99042)
    assert out == ('SecRule ARGS_GET:limit "@gt 1000" '
                   '"id:99042,phase:1,deny,status:403,log,msg:\'Export d’un gros lot\'"')
    assert guardrails._secrule_syntax_problem(lines(out)) is None


def test_trailing_backslash_in_message_cannot_escape_the_closing_quote():
    # Trouvé par hypothesis : msg:'\' laissait la chaîne ouverte.
    out = compile_modsecurity(spec(("ARGS_GET", "equals", "1", "limit"), message="C:\\chemin\\"), 99010)
    assert "msg:'C:/chemin/'" in out and guardrails._secrule_syntax_problem(lines(out)) is None


@pytest.mark.parametrize("value", ["fin\\", 'a\\"b'])
def test_value_whose_backslash_would_eat_the_closing_quote_is_refused(value):
    with pytest.raises(CompileError):
        compile_modsecurity(spec(("ARGS_GET", "contains", value, "q")), 99010)


def test_conditions_are_chained_with_actions_only_on_the_first():
    out = compile_modsecurity(spec(("REQUEST_FILENAME", "equals", "/"), ("ARGS_GET_NAMES", "equals", "_"),
                                   ("REQUEST_HEADERS", "absent", "", "Referer")), 99001)
    assert lines(out) == [
        'SecRule REQUEST_FILENAME "@streq /" "id:99001,phase:1,deny,status:403,log,msg:\'Campagne détectée\',chain"',
        'SecRule ARGS_GET_NAMES "@streq _" "chain"',
        'SecRule &REQUEST_HEADERS:Referer "@eq 0"',
    ]
    assert guardrails._secrule_syntax_problem(lines(out)) is None


def test_body_variables_move_the_rule_to_phase_2_and_log_only_means_pass():
    out = compile_modsecurity(spec(("ARGS", "contains", "<script", "q"), ("REQUEST_METHOD", "equals", "POST"),
                                   action="log_only"), 99002)
    assert "phase:2,pass,log" in out and "deny" not in out


def test_negation_and_ip_lists():
    out = compile_modsecurity(spec(("REMOTE_ADDR", "ip_in", "10.66.0.59 10.66.0.125"),
                                   ("REQUEST_HEADERS", "contains", "Mozilla", "User-Agent", True)), 99003)
    assert '"@ipMatch 10.66.0.59,10.66.0.125"' in out and '"!@contains Mozilla"' in out


@pytest.mark.parametrize("condition, reason", [
    (("REMOTE_ADDR", "ip_in", "10.66.0.59, pas-une-ip"), "ni une IP"),
    (("ARGS_GET", "equals", "x", "a b"), "nom invalide"),
    (("ARGS_GET", "greater_than", "mille", "limit"), "nombre entier"),
    (("REQUEST_URI", "regex", "(?i)<script)"), "expression régulière invalide"),
    (("REQUEST_URI", "equals", ""), "valeur vide"),
    (("REQUEST_URI", "equals", "a\nb"), "multiligne"),
    (("REQUEST_FILENAME", "equals", "0\x850"), "caractère de contrôle"),       # trouvé par hypothesis
    (("REQUEST_HEADERS", "absent", "", "Referer", True), "négation"),
])
def test_incoherent_descriptions_are_refused(condition, reason):
    with pytest.raises(CompileError, match=reason):
        compile_modsecurity(spec(condition), 99004)


def test_bunkerweb_settings_with_suffix():
    change = BunkerWebChangeSpec.model_validate(bw_spec(("USE_LIMIT_REQ", "yes"), ("LIMIT_REQ_URL", "/api/payments", 2),
                                                        ("LIMIT_REQ_RATE", "2r/s", 2)))
    assert compile_bunkerweb(change) == "USE_LIMIT_REQ=yes\nLIMIT_REQ_URL_2=/api/payments\nLIMIT_REQ_RATE_2=2r/s"


def test_rule_ids_are_unique_persistent_and_wrap_around(tmp_path):
    state = tmp_path / ".next_ai_rule_id"
    first = RuleIdAllocator(99000, 99002, state)
    assert [first.allocate() for _ in range(2)] == [99000, 99001]
    again = RuleIdAllocator(99000, 99002, state)                       # après redémarrage
    assert [again.allocate() for _ in range(2)] == [99002, 99000]      # puis retour au début de la plage


TEXT = st.text(st.characters(blacklist_categories=("Cs",), blacklist_characters="\n\r\x00"), min_size=1, max_size=40)
CONDITIONS = st.builds(Condition, variable=st.sampled_from(list(ModSecVariable)), name=st.one_of(st.none(), TEXT),
                       operator=st.sampled_from(list(ModSecOperator)), value=TEXT, negate=st.booleans())


@settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(CONDITIONS, min_size=1, max_size=4), st.sampled_from(["deny", "log_only"]), TEXT)
def test_whatever_the_description_the_compiled_syntax_is_valid(conditions, action, message):
    """La garantie de la grammaire : si la description compile, la syntaxe est valide (guillemets,
    apostrophes, chaînage, regex). La portée (règle trop large, inopérante) est contrôlée à part."""
    rule_spec = ModSecRuleSpec(conditions=conditions, action=action, message=message, explanation="e", side_effects="s")
    try:
        out = compile_modsecurity(rule_spec, 99010)
    except CompileError:
        return
    assert guardrails._secrule_syntax_problem(lines(out)) is None, out


def test_end_to_end_structured_rule_lands_in_the_report(config):
    referer_absent = modsec_spec(("REQUEST_FILENAME", "equals", "/"), ("REQUEST_HEADERS", "absent", "", "Referer"),
                                 message="Botnet sans Referer sur l'accueil")
    whole_endpoint = modsec_spec(("REQUEST_FILENAME", "equals", "/api/payments"))      # refusée : tout l'endpoint
    antibot = bw_spec(("USE_ANTIBOT", "javascript"))
    retriever = Retriever(HashingEmbedder(), InMemoryStore())
    retriever.index(list(LocalDocsSource(KNOWLEDGE).load()))
    analyzer = Analyzer(config, FakeLLM(llm_output(modsecurity=[referer_absent, whole_endpoint], bunkerweb=[antibot],
                                                   ideas=["Mettre en cache la page d'accueil côté proxy"])),
                        "fake", retriever=retriever, writer=RulesWriter(config.rules_dir))
    report = analyzer.analyze(AnalyzeRequest(cluster=load_cluster("distributed_flood")))
    assert [r.engine.value for r in report.analysis.rules] == ["modsecurity", "bunkerweb"]
    assert any("TOUT le trafic" in r.reason for r in report.rejected_rules)
    text = open(report.rules_file, encoding="utf-8").read()
    assert re.search(r'SecRule &REQUEST_HEADERS:Referer "@eq 0"', text)
    assert "## Pistes à expertiser" in text and "Mettre en cache" in text


@pytest.mark.parametrize("value", ["[10.66.0.59, 10.66.0.125]", "'10.66.0.59','10.66.0.125'", "10.66.0.59 10.66.0.125"])
def test_ip_lists_are_cleaned_as_the_model_writes_them(value):
    """Vu en réel (qwen2.5) : « @ipMatch [10.66.0.59,...] » aurait empêché ModSecurity de démarrer."""
    out = compile_modsecurity(spec(("REMOTE_ADDR", "ip_in", value)), 99050)
    assert '"@ipMatch 10.66.0.59,10.66.0.125"' in out and guardrails._secrule_syntax_problem(lines(out)) is None


def test_collections_without_name_target_all_parameters():
    out = compile_modsecurity(spec(("ARGS_GET", "contains", "<script")), 99051)
    assert out.startswith('SecRule ARGS_GET "@contains <script"')


@pytest.mark.parametrize("raw, expected", [("5/minute", "5r/m"), ("10 req/s", "10r/s"), ("2r/s", "2r/s"),
                                           ("30 requêtes / min", "30r/m")])
def test_rates_are_normalized(raw, expected):
    change = BunkerWebChangeSpec.model_validate(bw_spec(("LIMIT_REQ_RATE", raw, 2)))
    assert compile_bunkerweb(change) == f"LIMIT_REQ_RATE_2={expected}"


def test_antibot_yes_means_javascript_challenge():
    change = BunkerWebChangeSpec.model_validate(bw_spec(("USE_ANTIBOT", "yes")))
    assert compile_bunkerweb(change) == "USE_ANTIBOT=javascript"


def test_guardrails_reject_a_malformed_ip_list_written_by_hand():
    content = 'SecRule REMOTE_ADDR "@ipMatch [10.66.0.59,10.66.0.125]" "id:99052,phase:1,deny,log,msg:\'x\'"'
    assert "liste d'IP invalide" in guardrails._secrule_syntax_problem(lines(content))


def test_parameter_value_written_as_name_equals_value_is_refused():
    """Vu en réel : ARGS_GET "@contains limit=10000" ne se déclencherait jamais."""
    with pytest.raises(CompileError, match="name"):
        compile_modsecurity(spec(("ARGS_GET", "contains", "limit=10000")), 99060)


def test_duplicate_rules_are_dropped(config):
    same = modsec_spec(("REQUEST_URI", "equals", "/"), ("REMOTE_ADDR", "ip_in", "10.66.0.59"), message="A")
    twin = modsec_spec(("REQUEST_URI", "equals", "/"), ("REMOTE_ADDR", "ip_in", "10.66.0.59"), message="B")
    report = Analyzer(config, FakeLLM(llm_output(modsecurity=[same, twin])), "fake").analyze(
        AnalyzeRequest(cluster=load_cluster("distributed_flood")))
    assert len(report.analysis.rules) == 1 and any("doublon" in r.reason for r in report.rejected_rules)
