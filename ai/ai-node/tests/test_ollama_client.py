"""Le vrai client Ollama (sans Ollama) : toute panne doit devenir une LLMError, que l'analyseur
transforme en rapport dégradé sans règle. Une exception d'un autre type ferait échouer /analyze."""
import json

import httpx
import pytest

from llm_gateway.llm import LLMError, OllamaClient

URL = "http://ollama:11434"


def respond(monkeypatch, response=None, exc=None, seen=None):
    def fake_post(url, json=None, timeout=None):
        if seen is not None:
            seen.update(url=url, payload=json, timeout=timeout)
        if exc:
            raise exc
        return response
    monkeypatch.setattr(httpx, "post", fake_post)


def ok(content: str) -> httpx.Response:
    return httpx.Response(200, json={"message": {"content": content}}, request=httpx.Request("POST", URL))


def test_success_returns_parsed_json_and_sends_schema(monkeypatch):
    seen = {}
    respond(monkeypatch, ok(json.dumps({"verdict": "attaque"})), seen=seen)
    out = OllamaClient(URL, "qwen2.5:7b-instruct").generate_json("sys", "user", {"type": "object"}, timeout_s=12)
    assert out == {"verdict": "attaque"}
    assert seen["url"] == f"{URL}/api/chat" and seen["timeout"] == 12
    assert seen["payload"]["format"] == {"type": "object"} and seen["payload"]["stream"] is False
    assert seen["payload"]["keep_alive"] == "24h"            # modèle gardé en mémoire entre deux incidents


@pytest.mark.parametrize("response, exc", [
    (None, httpx.ReadTimeout("trop lent")),                                               # délai dépassé
    (None, httpx.ConnectError("refusé")),                                                 # Ollama arrêté
    (httpx.Response(500, text="oom", request=httpx.Request("POST", URL)), None),         # erreur GPU / modèle
    (ok("ceci n'est pas du JSON"), None),                                                 # sortie libre
    (httpx.Response(200, json={"oups": 1}, request=httpx.Request("POST", URL)), None),   # format inattendu
])
def test_every_failure_becomes_an_llm_error(monkeypatch, response, exc):
    respond(monkeypatch, response, exc)
    with pytest.raises(LLMError):
        OllamaClient(URL, "m").generate_json("s", "u", {})
