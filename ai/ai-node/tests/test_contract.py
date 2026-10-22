"""Contrat avec le PC infra : les requêtes /analyze produites par le vrai détecteur
(contracts/analyze, générées par infra/ml-detector/scripts/contract_examples.py).

La gateway ignore les champs inconnus (extra="ignore") : un champ renommé côté détecteur
disparaîtrait en silence. Ces tests le rendent visible.
"""
import json
from pathlib import Path

import pytest

from conftest import FakeLLM, llm_output
from llm_gateway.analyzer import Analyzer
from llm_gateway.contract import AnalyzeRequest, ClusterSummary, TopIp
from llm_gateway.rules_writer import RulesWriter

CONTRACTS = Path(__file__).resolve().parents[3] / "contracts" / "analyze"
EXAMPLES = sorted(CONTRACTS.glob("*.json")) if CONTRACTS.is_dir() else []

pytestmark = pytest.mark.skipif(not EXAMPLES, reason="contracts/ absent (image Docker : tests hors dépôt)")


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.stem)
def test_no_field_sent_by_the_detector_is_silently_dropped(path):
    body = load(path)
    AnalyzeRequest.model_validate(body)                      # bornes et types acceptés
    cluster = body["cluster"]
    assert set(cluster) <= set(ClusterSummary.model_fields), set(cluster) - set(ClusterSummary.model_fields)
    for ip in cluster["top_ips"]:
        assert set(ip) <= set(TopIp.model_fields), set(ip) - set(TopIp.model_fields)


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.stem)
def test_every_example_goes_through_the_analysis(path, config):
    analyzer = Analyzer(config, FakeLLM(llm_output()), "fake", writer=RulesWriter(config.rules_dir))
    report = analyzer.analyze(AnalyzeRequest.model_validate(load(path)))
    assert Path(report.rules_file).is_file()


def _prompt_and_report(name, config):
    llm = FakeLLM(llm_output())
    analyzer = Analyzer(config, llm, "fake", writer=RulesWriter(config.rules_dir))
    report = analyzer.analyze(AnalyzeRequest.model_validate(load(CONTRACTS / f"{name}.json")))
    return llm.last_user.split("<donnees_incident>")[0], Path(report.rules_file).read_text(encoding="utf-8")


def test_context_keys_read_by_code_are_the_ones_the_detector_sends(config):
    # Visibilité : déclencheur, date de coupure, actions de l'infra (lus par prompts et rules_writer).
    facts, text = _prompt_and_report("visibilite", config)
    assert "PERTE DE VISIBILITÉ" in facts and "actions automatiques de l'infra" in facts
    assert "**PERTE DE VISIBILITÉ**" in text and "| remédiation réussie | WafDown | restart | bunkerweb |" in text
    # Réanalyse : analyse_precedente (date, verdict).
    facts, _ = _prompt_and_report("campagne_reanalyse", config)
    assert "MISE À JOUR d'une campagne déjà analysée" in facts
    # Symptôme : l'indice service_degradation change la description du volume.
    facts, _ = _prompt_and_report("symptome", config)
    assert "toute la fenêtre, normales comprises" in facts
