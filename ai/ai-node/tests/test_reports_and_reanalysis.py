"""Réanalyses (mémoire des règles, mise à jour) et pages de consultation des rapports."""
import pytest
from fastapi.testclient import TestClient

from conftest import FakeLLM, bw_spec, llm_output, load_cluster
from llm_gateway.analyzer import Analyzer
from llm_gateway.app import create_app
from llm_gateway.config import GatewayConfig
from llm_gateway.contract import AnalyzeRequest
from llm_gateway.rules_writer import RulesWriter


def test_rule_already_proposed_recently_is_cited_not_copied_again(config):
    antibot = bw_spec(("USE_ANTIBOT", "javascript"))
    analyzer = Analyzer(config, FakeLLM(llm_output(bunkerweb=[antibot])), "fake", writer=RulesWriter(config.rules_dir))
    first = analyzer.analyze(AnalyzeRequest(cluster=load_cluster("distributed_flood")))
    second = analyzer.analyze(AnalyzeRequest(cluster=load_cluster("distributed_flood")))
    assert len(first.analysis.rules) == 1 and not first.already_proposed
    assert second.analysis.rules == [] and second.already_proposed[0]["rapport"] == first.rules_file.replace("\\", "/").rsplit("/", 1)[-1]
    text = open(second.rules_file, encoding="utf-8").read()
    assert "## Règles déjà proposées" in text and "USE_ANTIBOT=javascript" not in text


def test_reanalysis_prompt_states_it_is_an_update(config):
    llm = FakeLLM(llm_output())
    previous = {"date": "2026-10-20T14:11:00+00:00", "verdict": "attaque", "resume": "Botnet sur /",
                "regles_deja_proposees": ["USE_ANTIBOT=javascript"]}
    Analyzer(config, llm, "fake").analyze(AnalyzeRequest(cluster=load_cluster("distributed_flood"),
                                                         context={"analyse_precedente": previous}))
    assert "MISE À JOUR d'une campagne déjà analysée le 2026-10-20T14:11:00" in llm.last_user
    assert "analyse_precedente" in llm.last_system


@pytest.fixture
def viewer(tmp_path):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "20261020T141100Z_abc123.md").write_text("# Analyse SOC — botnet\n\n/?q=<script>alert(1)</script>",
                                                        encoding="utf-8")
    config = GatewayConfig(token="t" * 40, rules_dir=reports, reports_password="mot-de-passe-soc")
    return TestClient(create_app(config, Analyzer(config, FakeLLM(llm_output()), "fake")))


def test_report_pages_require_basic_auth_and_escape_attacker_text(viewer):
    assert viewer.get("/reports").status_code == 401
    assert viewer.get("/reports", auth=("soc", "faux")).status_code == 401
    page = viewer.get("/reports/20261020T141100Z_abc123.md", auth=("soc", "mot-de-passe-soc"))
    assert page.status_code == 200 and "&lt;script&gt;" in page.text and "<script>alert" not in page.text
    listing = viewer.get("/reports", auth=("soc", "mot-de-passe-soc"))
    assert "20261020T141100Z_abc123.md" in listing.text


@pytest.mark.parametrize("name", ["..%2F..%2Fetc%2Fpasswd", "../config.py", "x.md", "20261020T141100Z_abc123.txt"])
def test_report_pages_refuse_anything_but_report_files(viewer, name):
    assert viewer.get(f"/reports/{name}", auth=("soc", "mot-de-passe-soc")).status_code == 404


def test_report_pages_do_not_exist_without_a_password(config):
    client = TestClient(create_app(config, Analyzer(config, FakeLLM(llm_output()), "fake")))
    assert client.get("/reports", auth=("soc", "")).status_code == 404
