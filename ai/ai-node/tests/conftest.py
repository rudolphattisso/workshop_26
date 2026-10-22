import copy
import json
from pathlib import Path

import pytest

from llm_gateway.config import GatewayConfig
from llm_gateway.llm import LLMClient, LLMError

FIXTURES = Path(__file__).parent / "fixtures"
KNOWLEDGE = Path(__file__).parents[1] / "knowledge"


def load_cluster(name: str) -> dict:
    """Résumés réels produits par la démo du ml-detector (contrat ClusterSummary)."""
    return json.loads((FIXTURES / f"cluster_{name}.json").read_text(encoding="utf-8"))


class FakeLLM(LLMClient):
    """Renvoie une réponse préparée (ou lève une erreur) et garde le dernier prompt reçu."""

    def __init__(self, response: dict | Exception):
        self.response = response
        self.last_system = self.last_user = None

    def generate_json(self, system, user, schema, timeout_s=60.0):
        self.last_system, self.last_user = system, user
        if isinstance(self.response, Exception):
            raise self.response
        return copy.deepcopy(self.response)


def llm_answer(verdict="attaque", rules=(), actions=("Surveiller les 503 côté sondes.",)) -> dict:
    return {
        "verdict": verdict, "confidence": "elevee", "attack_type": "DDoS distribué (botnet)",
        "summary": "Trois cents IP nouvelles répètent GET / sans parcours utilisateur.",
        "evidence": ["n_distinct_ips = 301", "endpoint_sessionless_ips z = 57"],
        "impact": "60 % de 503 : service dégradé pour les clients.",
        "rules": list(rules), "operator_actions": list(actions), "uncertainties": [],
    }


def llm_output(verdict="attaque", modsecurity=(), bunkerweb=(), ideas=(), actions=("Surveiller les 503 côté sondes.",)) -> dict:
    """Réponse BRUTE du LLM au format de la grammaire de règles (LlmOutput)."""
    return {
        "verdict": verdict, "confidence": "elevee", "attack_type": "DDoS distribué (botnet)",
        "summary": "Trois cents IP nouvelles répètent GET / sans parcours utilisateur.",
        "evidence": ["n_distinct_ips = 301"], "impact": "60 % de 503.",
        "modsecurity_rules": list(modsecurity), "bunkerweb_changes": list(bunkerweb),
        "ideas_to_review": list(ideas), "operator_actions": list(actions), "uncertainties": [],
    }


def modsec_spec(*conditions, action="deny", message="Campagne détectée"):
    return {"conditions": [dict(zip(("variable", "operator", "value", "name", "negate"), c)) for c in conditions],
            "action": action, "message": message, "explanation": "explication", "side_effects": "aucun connu"}


def bw_spec(*settings):
    return {"settings": [dict(zip(("setting", "value", "suffix"), s)) for s in settings],
            "explanation": "explication", "side_effects": "aucun connu"}


def rule(engine, content, explanation="explication", side_effects="aucun connu"):
    return {"engine": engine, "content": content, "explanation": explanation, "side_effects": side_effects}


@pytest.fixture
def config(tmp_path):
    return GatewayConfig(token="t" * 40, rules_dir=tmp_path / "reports", knowledge_dir=KNOWLEDGE,
                         vector_store="memory", embedder="hashing")


__all__ = ["FakeLLM", "LLMError", "bw_spec", "llm_answer", "llm_output", "load_cluster", "modsec_spec", "rule"]
