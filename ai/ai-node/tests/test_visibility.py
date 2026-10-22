"""Actions de l'infra et perte de visibilité : vues par le LLM, recopiées dans le rapport ; signal
de vie du détecteur affiché sur le PC IA."""
from fastapi.testclient import TestClient

from conftest import FakeLLM, llm_output, load_cluster
from llm_gateway.analyzer import Analyzer
from llm_gateway.app import DetectorWatch, create_app
from llm_gateway.config import GatewayConfig
from llm_gateway.contract import AnalyzeRequest, Heartbeat
from llm_gateway.rules_writer import RulesWriter

ACTIONS = [
    {"heure": "2026-10-20T13:58:00+00:00", "evenement": "remédiation lancée", "alerte": "WafDown",
     "action": "restart", "cible": "bunkerweb", "detail": ""},
    {"heure": "2026-10-20T13:59:30+00:00", "evenement": "remédiation EN ÉCHEC", "alerte": "WafDown",
     "action": "restart", "cible": "bunkerweb", "detail": "vérification | métier\nen échec"},
]
BLIND = {"escalade": {"trigger": "perte_de_visibilite", "severity": 60, "donnees_jusqu_a": "2026-10-20T14:00:00+00:00",
                      "reasons": ["sources de données injoignables depuis 3 cycles (30 s)"]},
         "actions_infra": ACTIONS}


def test_llm_is_told_what_the_infra_did_and_that_it_is_blind(config):
    llm = FakeLLM(llm_output())
    Analyzer(config, llm, "fake").analyze(AnalyzeRequest(cluster=load_cluster("distributed_flood"), context=BLIND))
    facts = llm.last_user.split("<donnees_incident>")[0]
    assert "PERTE DE VISIBILITÉ" in facts and "2026-10-20T14:00:00" in facts
    assert "remédiation EN ÉCHEC restart bunkerweb ×1" in facts
    assert "actions_infra" in llm.last_system and "perte_de_visibilite" in llm.last_system


def test_report_copies_the_infra_actions_and_flags_blindness(config):
    analyzer = Analyzer(config, FakeLLM(llm_output()), "fake", writer=RulesWriter(config.rules_dir))
    report = analyzer.analyze(AnalyzeRequest(cluster=load_cluster("distributed_flood"), context=BLIND))
    text = open(report.rules_file, encoding="utf-8").read()
    assert "**PERTE DE VISIBILITÉ**" in text and "injoignables depuis 3 cycles" in text
    assert "## Actions automatiques de l'infra" in text
    assert "| 2026-10-20T13:59:30+00:00 | remédiation EN ÉCHEC | WafDown | restart | bunkerweb | vérification / métier en échec |" in text


def test_report_without_actions_has_no_empty_section(config):
    analyzer = Analyzer(config, FakeLLM(llm_output()), "fake", writer=RulesWriter(config.rules_dir))
    report = analyzer.analyze(AnalyzeRequest(cluster=load_cluster("distributed_flood")))
    text = open(report.rules_file, encoding="utf-8").read()
    assert "Actions automatiques" not in text and "PERTE DE VISIBILITÉ" not in text


def test_detector_watch_states():
    now = [1_000_000.0]
    watch = DetectorWatch(clock=lambda: now[0])
    assert watch.status()["etat"] == "inconnu"
    watch.beat(Heartbeat(statut="ok"))
    assert watch.status()["etat"] == "ok"
    watch.beat(Heartbeat(statut="aveugle", derniere_lecture="2026-10-20T14:00:00+00:00"))
    assert watch.status()["etat"] == "aveugle" and "2026-10-20T14:00:00" in watch.status()["message"]
    now[0] += 121
    assert watch.status()["etat"] == "muet"                 # plus rien depuis 2 min : PC infra ou réseau


def test_heartbeat_endpoint_requires_the_token_and_feeds_the_report_pages(tmp_path):
    now = [1_000_000.0]
    watch = DetectorWatch(clock=lambda: now[0])
    config = GatewayConfig(token="t" * 40, rules_dir=tmp_path, reports_password="mot-de-passe-soc")
    client = TestClient(create_app(config, Analyzer(config, FakeLLM(llm_output()), "fake"), watch))
    assert client.post("/heartbeat", json={"statut": "ok"}).status_code == 401
    assert client.post("/heartbeat", json={"statut": "ok"}, headers={"Authorization": "Bearer " + "t" * 40}).json() == {"ok": True}
    assert client.get("/health").json()["detecteur"] == "ok"
    assert "muet" not in client.get("/reports", auth=("soc", "mot-de-passe-soc")).text
    now[0] += 300
    assert client.get("/health").json()["detecteur"] == "muet"
    assert "détecteur muet depuis" in client.get("/reports", auth=("soc", "mot-de-passe-soc")).text
