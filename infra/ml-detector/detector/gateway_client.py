"""Client du llm-gateway (PC IA) : POST /analyze et /heartbeat avec jeton. Bibliothèque standard uniquement."""
from __future__ import annotations

import json
import urllib.error
import urllib.request


class GatewayError(RuntimeError):
    """Gateway injoignable, jeton refusé, réponse invalide."""


class GatewayClient:
    def __init__(self, url: str, token: str, timeout_s: float = 180.0):
        self.base = url.rstrip("/")
        self.url = self.base + "/analyze"
        self.token = token
        self.timeout_s = timeout_s      # une analyse dure ~40 s sur le GPU, plus l'attente d'une autre

    def analyze(self, cluster: dict, context: dict) -> dict:
        return self._post(self.url, {"cluster": cluster, "context": context}, self.timeout_s)

    def heartbeat(self, status: dict) -> dict:
        """Signal de vie : le PC IA affiche « détecteur muet » s'il n'en reçoit plus."""
        return self._post(self.base + "/heartbeat", status, 5.0)

    def _post(self, url: str, payload: dict, timeout_s: float) -> dict:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode()
        try:
            request = urllib.request.Request(url, data=body, method="POST", headers={
                "Content-Type": "application/json", "Authorization": f"Bearer {self.token}"})
            with urllib.request.urlopen(request, timeout=timeout_s) as response:
                return json.loads(response.read().decode())
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise GatewayError(f"llm-gateway ({url}) : {exc}") from exc
