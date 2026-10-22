"""Métriques Prometheus du détecteur, exposées sur /metrics (bibliothèque standard uniquement).

Métrique DÉDIÉE soc_waf_anomaly_score, jamais aiops_anomaly_score : celle-ci déclenche la
remédiation automatique de l'infra (AnomalyDetected -> redémarrage). L'IA ne remédie jamais.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HELP = {
    "soc_waf_anomaly_score": ("gauge", "Gravité la plus haute de la fenêtre (0-100), avec ou sans appel au LLM"),
    "soc_detector_window_requests": ("gauge", "Requêtes dans la fenêtre glissante analysée"),
    "soc_detector_clusters": ("gauge", "Groupes anormaux dans la fenêtre"),
    "soc_detector_cycle_seconds": ("gauge", "Durée du dernier cycle d'analyse"),
    "soc_detector_errors_total": ("counter", "Cycles d'analyse en échec (Loki injoignable...)"),
    "soc_detector_truncated_total": ("counter", "Lectures de journaux tronquées (volume hors norme)"),
    "soc_heartbeat_errors_total": ("counter", "Signaux de vie non reçus par le llm-gateway"),
    "soc_llm_escalations_total": ("counter", "Analyses envoyées au LLM, par déclencheur"),
    "soc_llm_reports_total": ("counter", "Rapports reçus du LLM, par verdict"),
    "soc_llm_errors_total": ("counter", "Appels au llm-gateway en échec"),
    "soc_llm_queue_size": ("gauge", "Analyses en attente d'envoi au LLM"),
    "soc_llm_dropped_total": ("counter", "Analyses écartées de la file (périmées, file pleine)"),
}


class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self._values: dict[tuple[str, tuple], float] = {}

    def set(self, name: str, value: float, **labels) -> None:
        with self._lock:
            self._values[(name, tuple(sorted(labels.items())))] = value

    def inc(self, name: str, amount: float = 1.0, **labels) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def get(self, name: str, **labels) -> float:
        return self._values.get((name, tuple(sorted(labels.items()))), 0.0)

    def render(self) -> str:
        lines = []
        with self._lock:
            names = sorted({name for name, _ in self._values})
            for name in names:
                kind, text = _HELP.get(name, ("gauge", name))
                lines += [f"# HELP {name} {text}", f"# TYPE {name} {kind}"]
                for (n, labels), value in sorted(self._values.items()):
                    if n == name:
                        tag = ",".join(f'{k}="{v}"' for k, v in labels)
                        lines.append(f"{name}{{{tag}}} {value:g}" if tag else f"{name} {value:g}")
        return "\n".join(lines) + "\n"


def serve(metrics: Metrics, port: int, checks=None) -> ThreadingHTTPServer:
    """/metrics (Prometheus), /health et /ready (contracts/service-conventions.md), dans un thread ;
    renvoie le serveur (pour l'arrêter). Port 8000 : cible Prometheus ml-detector:8000.
    `checks` : fonction -> {"loki": "ok"|"down", ...} ; /ready répond 503 si une dépendance est down."""
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            status = 200
            if self.path == "/metrics":
                body, kind = metrics.render().encode(), "text/plain; version=0.0.4"
            elif self.path == "/health":
                body, kind = json.dumps({"status": "ok", "service": "ml-detector"}).encode(), "application/json"
            elif self.path == "/ready":
                state = checks() if checks else {}
                ready = all(v == "ok" for v in state.values())
                status = 200 if ready else 503
                body = json.dumps({"status": "ok" if ready else "down", "service": "ml-detector",
                                   "checks": state}).encode()
                kind = "application/json"
            else:
                self.send_error(404)
                return
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):          # pas de journal par requête Prometheus
            pass

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True, name="metrics").start()
    return server
