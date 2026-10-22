"""Service continu du détecteur (PC infra).

Toutes les `cycle_s` secondes (10 par défaut), il analyse la FENÊTRE GLISSANTE des 60 dernières
secondes (celle sur laquelle le modèle a été entraîné) : détection en 10 à 20 s au lieu d'une
minute, pour ~0,1 s de calcul en trafic normal et ~3 s en plein DDoS (60 000 req/min).

    logs (Loki, rejeu)  ->  détection  ->  escalade (gravité, délai de garde, plafond/minute)
    alarmes (Wazuh...)  ->               ->  file d'attente  ->  llm-gateway (fil séparé, ~40 s)
                                         ->  /metrics (soc_waf_anomaly_score) et journal JSON

Le LLM n'est appelé que sur escalade (cf. escalation.py) ; il ne bloque jamais la détection.

Perte de visibilité (l'attaque peut faire tomber les sources de données) : Loki injoignable
plusieurs cycles, plus aucune requête après du trafic, ou lecture tronquée -> une analyse est
demandée quand même, avec ce qui a été vu AVANT la coupure (le LLM est sur l'autre PC). Un
signal de vie part vers la gateway toutes les 30 s : le PC IA affiche « détecteur muet » si
plus rien n'arrive (PC infra tombé, réseau coupé).
Lancement en production : python -m detector.service (variables d'environnement, cf. main()).
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import Counter, deque
from dataclasses import asdict
from datetime import datetime, timedelta

from . import infra_actions
from .alarms import Alarm
from .detection import DetectionPipeline
from .escalation import SYMPTOM_KEY, VISIBILITY_KEY, Escalator, campaign_key
from .gateway_client import GatewayClient, GatewayError
from .ip_history import IpHistory
from .llm_queue import LlmQueue, QueuedAnalysis
from .metrics import Metrics
from .models import HttpRequestLog
from .sources.base import LogSource
from .sources.replay import Clock

log = logging.getLogger("ml_detector")


class DetectorService:
    def __init__(self, pipeline: DetectionPipeline, logs: LogSource, alarms, escalator: Escalator,
                 gateway: GatewayClient | None, metrics: Metrics | None = None, cycle_s: int = 10,
                 queue: LlmQueue | None = None, reports_url: str | None = None, ingest_delay_s: int = 0,
                 actions=None, visibility_errors: int = 3, heartbeat_s: float = 30.0,
                 probe_ua: str = "resilience-blackbox/", probe_interval_s: float = 5.0, probe_missed: int = 3):
        """`alarms` : objet avec fetch(start, end) -> list[Alarm] (ou None). `gateway` None : mode
        à blanc, les analyses qui seraient envoyées sont seulement journalisées. `reports_url` :
        adresse de consultation des rapports (lien dans le journal, repris par Grafana).
        `actions` : actions du moteur de remédiation, fetch(start, end) -> list[InfraAction] (ou None).
        `visibility_errors` : cycles en échec d'affilée avant de signaler la perte de visibilité.
        `probe_*` : sondes de supervision de l'infra qui traversent le WAF (Prometheus blackbox, toutes
        les 5 s) : `probe_missed` intervalles sans aucune d'elles dans les journaux = perte de visibilité."""
        self.pipeline, self.logs, self.alarms = pipeline, logs, alarms
        self.escalator, self.gateway = escalator, gateway
        self.metrics = metrics or Metrics()
        self.cycle_s = cycle_s
        self.reports_url = reports_url.rstrip("/") if reports_url else None
        # Loki reçoit les journaux avec quelques secondes de retard : analyser jusqu'à « maintenant »
        # ferait manquer les lignes arrivées après le passage du curseur. 0 en rejeu, 5 s avec Loki.
        self.ingest_delay = timedelta(seconds=ingest_delay_s)
        self.window = timedelta(seconds=pipeline.config.window_seconds)
        self.history = IpHistory()
        # Deux fenêtres en mémoire : les features par IP d'une requête regardent les 60 s qui la
        # précèdent, y compris avant le début de la fenêtre analysée.
        self._buffer: deque[HttpRequestLog] = deque()
        self._cursor: datetime | None = None
        self._queue = queue or LlmQueue()
        self.actions = actions
        self._actions: dict[tuple, infra_actions.InfraAction] = {}   # 15 dernières minutes, sans doublon
        self._last_alarms: list[Alarm] = []
        self._recent_counts: deque[tuple[datetime, int]] = deque()   # requêtes par fenêtre (5 min)
        self.visibility_errors = visibility_errors
        self.heartbeat_s = heartbeat_s
        self.errors_in_row = 0
        self.last_ok: datetime | None = None                         # fin de la dernière fenêtre lue
        self.probe_ua, self.probe_missed = probe_ua, probe_missed
        self.probe_interval = timedelta(seconds=probe_interval_s)
        self._last_probe: datetime | None = None                     # dernière sonde vue dans les journaux
        self._blind: frozenset = frozenset()                         # causes en cours (journal sur changement)
        self._queue.on_drop = self._dropped
        self._last_report: dict = {}               # campagne -> résumé du dernier rapport (réanalyse)
        self.sent: list[dict] = []                 # analyses mises en file (pour la démo et les tests)
        self.reports: list[dict] = []              # rapports reçus

    # -- un cycle ---------------------------------------------------------------------------
    def tick(self, now: datetime) -> dict:
        started = time.perf_counter()
        now = now - self.ingest_delay
        # Reprise après une panne de Loki : on rattrape au plus deux fenêtres (le tampon n'en garde pas plus).
        new = self.logs.fetch(max(self._cursor or now - self.window, now - 2 * self.window), now)
        self._cursor = now
        self._buffer.extend(new)
        self.history.update(new)
        while self._buffer and self._buffer[0].ts < now - 2 * self.window:
            self._buffer.popleft()

        buffer = list(self._buffer)
        start = now - self.window
        idx = [i for i, r in enumerate(buffer) if r.ts >= start]
        window_records = [buffer[i] for i in idx]
        clusters = []
        if window_records:
            X = self.pipeline.features(buffer)
            clusters = self.pipeline.analyze(window_records, X[idx], history=self.history).clusters
        alarms: list[Alarm] = self.alarms.fetch(start, now) if self.alarms else []
        if self.actions is not None:
            for a in self.actions.fetch(start, now):
                self._actions[(a.ts, a.event, a.alertname, a.target)] = a
        self._actions = {k: a for k, a in self._actions.items() if a.ts >= now - timedelta(minutes=15)}
        alarms += infra_actions.as_alarms([a for a in self._actions.values() if start <= a.ts < now])
        self._last_alarms = alarms

        decisions = self.escalator.decide(clusters, alarms, now)
        symptom = self.escalator.decide_symptom(alarms, decisions, now)
        for d in decisions:
            if d.escalate:
                self._enqueue("campagne", campaign_key(d.cluster), d.severity, asdict(d.cluster), d.to_context(),
                              alarms, now)
        if symptom and symptom.escalate:
            overview = self.pipeline.overview(window_records, history=self.history,
                                              window=(start.isoformat(), now.isoformat()))
            self._enqueue("symptome", SYMPTOM_KEY, symptom.severity, asdict(overview), symptom.to_context(),
                          alarms, now)
        lost = self._visibility_reasons(window_records, new, now)
        if lost and not (symptom and symptom.escalate):
            self._visibility_lost(lost, now)
        self.errors_in_row, self.last_ok = 0, now

        score = max([self.escalator.anomaly_score(decisions)] + ([symptom.severity] if symptom else []))
        self.metrics.set("soc_waf_anomaly_score", score)
        self.metrics.set("soc_detector_window_requests", len(window_records))
        self.metrics.set("soc_detector_clusters", len(clusters))
        self.metrics.set("soc_detector_cycle_seconds", round(time.perf_counter() - started, 3))
        self.metrics.set("soc_llm_queue_size", len(self._queue))
        return {"now": now, "requests": len(window_records), "clusters": len(clusters), "score": score,
                "decisions": decisions, "symptom": symptom}

    # -- perte de visibilité -----------------------------------------------------------------
    # Repli si les sondes n'apparaissent pas dans les journaux (cible changée...) : volume avant silence.
    _SILENCE_MIN_REQUESTS = 30

    def _visibility_reasons(self, window: list[HttpRequestLog], new: list[HttpRequestLog], now: datetime) -> list[str]:
        reasons, causes = [], set()
        n_requests = len(window)
        # Requêtes REÇUES pendant ce cycle (pas toute la fenêtre de 60 s, qui contient encore celles
        # d'avant la coupure : vu en test de panne, « 57 autres requêtes arrivent » avec le WAF arrêté).
        others = sum(1 for r in new if not (self.probe_ua and r.user_agent.startswith(self.probe_ua)))
        probes = [r.ts for r in new if self.probe_ua and r.user_agent.startswith(self.probe_ua)]
        if probes:
            self._last_probe = max(probes + ([self._last_probe] if self._last_probe else []))
        if self._last_probe and now - self._last_probe > self.probe_missed * self.probe_interval:
            causes.add("sondes")
            reasons.append(f"aucune sonde de supervision dans les journaux du WAF depuis "
                           f"{(now - self._last_probe).total_seconds():.0f} s (attendues toutes les "
                           f"{self.probe_interval.total_seconds():g} s) : "
                           + ("WAF arrêté ou collecte des journaux coupée" if others == 0 else
                              f"pourtant {others} autres requêtes sont arrivées pendant ce cycle : le WAF ne sert plus les sondes "
                              "(saturé, sondes bannies) ou la sonde est arrêtée"))
        before = [n for t, n in self._recent_counts if now - t <= timedelta(minutes=5)]
        self._recent_counts.append((now, n_requests))
        while self._recent_counts and now - self._recent_counts[0][0] > timedelta(minutes=5):
            self._recent_counts.popleft()
        if n_requests == 0 and before and max(before) >= self._SILENCE_MIN_REQUESTS and not self._last_probe:
            causes.add("silence")
            reasons.append(f"plus AUCUNE requête dans les journaux du WAF depuis {self.window.seconds} s, après "
                           f"{max(before)} requêtes par fenêtre dans les 5 dernières minutes : WAF arrêté, "
                           "journalisation coupée, ou trafic arrêté en amont")
        if getattr(self.logs, "truncated", False):
            self.metrics.inc("soc_detector_truncated_total")
            causes.add("troncature")
            reasons.append("lecture des journaux tronquée (volume hors norme en un cycle) : seule la première "
                           "partie a été analysée")
        # Journal sur changement d'état, pas à chaque cycle (la condition dure tant que la coupure dure).
        if causes - self._blind:
            log.warning(json.dumps({"event": "perte_de_visibilite", "causes": sorted(causes), "raisons": reasons},
                                   ensure_ascii=False))
        if self._blind and not causes:
            log.info(json.dumps({"event": "visibilite_retablie", "causes": sorted(self._blind)}, ensure_ascii=False))
        self._blind = frozenset(causes)
        return reasons

    def _visibility_lost(self, reasons: list[str], now: datetime) -> None:
        decision = self.escalator.decide_visibility(reasons, now)
        if not decision.escalate:
            return
        records = list(self._buffer)                 # ce qui a été vu AVANT la coupure
        end = self.last_ok or now
        overview = asdict(self.pipeline.overview(records, history=self.history,
                                                 window=((end - 2 * self.window).isoformat(), end.isoformat())))
        overview["signature"] = overview["signature"].replace("symptome", "visibilite", 1)
        overview["attack_hints"] = [h for h in overview["attack_hints"] if h != "service_degradation"] + ["visibility_loss"]
        context = decision.to_context()
        context["donnees_jusqu_a"] = end.isoformat()
        self._enqueue("visibilite", VISIBILITY_KEY, decision.severity, overview, context, self._last_alarms, now)

    def _enqueue(self, trigger: str, key, severity: int, cluster: dict, escalation: dict, alarms: list[Alarm],
                 now: datetime) -> None:
        context = {"escalade": escalation, "alarmes": _alarm_summary(alarms)}
        if self._actions:
            # Ce que l'infra a déjà fait (redémarrages...) : le LLM dit si ça a aidé, le rapport le recopie.
            context["actions_infra"] = infra_actions.to_context(list(self._actions.values()))
        previous = self._last_report.get(key)
        if previous:
            # Réanalyse (aggravation) : le LLM part de ce qu'il a déjà dit et décrit ce qui a changé
            # au lieu de reproduire le même rapport et les mêmes règles.
            context["analyse_precedente"] = previous
        item = {"trigger": trigger, "cluster": cluster, "context": context, "mise_a_jour": bool(previous)}
        self.sent.append(item)
        self.metrics.inc("soc_llm_escalations_total", trigger=trigger)
        log.info(json.dumps({"event": "escalade", "trigger": trigger, "signature": cluster["signature"],
                             "gravite": severity, "raisons": escalation["reasons"], "mise_a_jour": bool(previous)},
                            ensure_ascii=False))
        self._queue.put(key, severity, item, now)

    def _dropped(self, queued: QueuedAnalysis, why: str) -> None:
        self.escalator.release(queued.key)          # la campagne pourra être réescaladée, données fraîches
        self.metrics.inc("soc_llm_dropped_total", reason=why)
        log.warning(json.dumps({"event": "analyse_ecartee", "raison": why, "signature": queued.item["cluster"]["signature"],
                                "gravite": queued.severity}, ensure_ascii=False))

    # -- appels au LLM : fil séparé, jamais bloquants pour la détection ---------------------
    def drain(self, now: datetime) -> None:
        """Envoie ce qui attend dans la file (utilisé par le fil d'envoi et par les tests)."""
        while (queued := self._queue.get(lambda: now, timeout=0)) is not None:
            self._send(queued)

    def _send(self, queued: QueuedAnalysis) -> None:
        item = queued.item
        if self.gateway is None:
            log.info(json.dumps({"event": "analyse_a_blanc", "signature": item["cluster"]["signature"]}))
            return
        try:
            report = self.gateway.analyze(item["cluster"], item["context"])
        except GatewayError as exc:
            self.metrics.inc("soc_llm_errors_total")
            self.escalator.release(queued.key)
            log.error(json.dumps({"event": "gateway_erreur", "erreur": str(exc)[:300]}, ensure_ascii=False))
            return
        self.reports.append(report)
        analysis = report.get("analysis", {})
        verdict = analysis.get("verdict", "inconnu")
        self.metrics.inc("soc_llm_reports_total", verdict=verdict)
        fichier = report.get("rules_file") or ""
        self._last_report[queued.key] = {
            "date": report.get("generated_at"), "verdict": verdict, "resume": str(analysis.get("summary", ""))[:400],
            "regles_deja_proposees": [r.get("content", "")[:300] for r in analysis.get("rules", [])],
        }
        # Une ligne par rapport : le tableau des incidents de Grafana (Loki) se construit sur ces lignes.
        # `popup` est le rapport mis en forme (markdown), affiché tel quel dans l'infobulle de
        # l'annotation sur la courbe de gravité : toute la mise en forme est faite ici, pas dans Grafana.
        lien = f"{self.reports_url}/{fichier.replace(chr(92), '/').rsplit('/', 1)[-1]}" if self.reports_url and fichier else None
        popup = _report_popup(analysis, report, item["trigger"], item["mise_a_jour"], lien)
        log.info(json.dumps({
            "event": "rapport", "signature": report.get("signature"), "declencheur": item["trigger"],
            "famille": queued.key[0] if isinstance(queued.key, tuple) else item["trigger"],
            "mise_a_jour": item["mise_a_jour"], "gravite": queued.severity, "verdict": verdict,
            "confiance": analysis.get("confidence"), "type": analysis.get("attack_type"),
            "regles": len(analysis.get("rules", [])), "degrade": bool(report.get("degraded")),
            "duree_s": (report.get("timings") or {}).get("total_s"),
            "popup": popup,
            "lien": lien,
        }, ensure_ascii=False))

    def run(self, clock: Clock, until: datetime | None = None, on_tick=None) -> None:
        stop = threading.Event()

        def sender():
            while not stop.is_set() or len(self._queue):
                queued = self._queue.get(clock.now, timeout=0.5)
                if queued is not None:
                    self._send(queued)

        worker = threading.Thread(target=sender, name="llm-sender", daemon=True)
        worker.start()
        if self.gateway is not None and self.heartbeat_s > 0:
            threading.Thread(target=self._heartbeat, args=(clock, stop), name="heartbeat", daemon=True).start()
        try:
            while until is None or clock.now() < until:
                cycle_start = clock.now()
                try:
                    result = self.tick(cycle_start)
                except Exception as exc:               # Loki indisponible... : on journalise, on réessaie au cycle suivant
                    self.metrics.inc("soc_detector_errors_total")
                    self.errors_in_row += 1
                    error = f"{type(exc).__name__}: {exc}"[:300]
                    log.error(json.dumps({"event": "cycle_erreur", "erreur": error}, ensure_ascii=False))
                    if self.errors_in_row == self.visibility_errors:
                        self._visibility_lost([f"sources de données injoignables depuis {self.errors_in_row} cycles "
                                               f"({self.errors_in_row * self.cycle_s} s) : {error}"],
                                              cycle_start - self.ingest_delay)
                    result = None
                if on_tick and result is not None:
                    on_tick(result)
                elapsed = (clock.now() - cycle_start).total_seconds()
                clock.sleep(max(0.0, self.cycle_s - elapsed))
        finally:
            stop.set()
            worker.join()


    def _heartbeat(self, clock: Clock, stop: threading.Event) -> None:
        """Signal de vie vers le PC IA, en temps réel, indépendant des analyses."""
        while not stop.is_set():
            try:
                self.gateway.heartbeat({
                    "ts": clock.now().isoformat(timespec="seconds"),
                    "statut": "aveugle" if self.errors_in_row >= self.visibility_errors else "ok",
                    "erreurs_consecutives": self.errors_in_row,
                    "derniere_lecture": self.last_ok.isoformat(timespec="seconds") if self.last_ok else None,
                    "file_llm": len(self._queue),
                })
            except GatewayError:
                self.metrics.inc("soc_heartbeat_errors_total")
            stop.wait(self.heartbeat_s)


_TRIGGER_LABEL = {"campagne": "campagne détectée", "symptome": "symptôme sans campagne",
                  "visibilite": "perte de visibilité"}


def _report_popup(analysis: dict, report: dict, trigger: str, maj: bool, lien: str | None) -> str:
    """Rapport mis en forme (markdown) pour l'infobulle de l'annotation sur la courbe de gravité.
    La gravité n'y figure pas : elle est déjà lue sur la courbe. Tout tient dans l'infobulle."""
    lines: list[str] = []
    contexte = _TRIGGER_LABEL.get(trigger, trigger) + (" · mise à jour" if maj else "")
    lines.append(f"_{contexte} · confiance {analysis.get('confidence', '?')}_")
    if report.get("degraded"):
        lines.append("⚠️ **Analyse dégradée** (LLM indisponible) : vérifier manuellement.")
    lines.append("")
    lines.append(str(analysis.get("summary", "")).strip() or "_pas de diagnostic_")
    if analysis.get("impact"):
        lines += ["", f"**Impact** — {analysis['impact']}"]
    warnings = report.get("warnings") or []
    if warnings:
        lines += ["", "**⚠ Cohérence** — " + " ; ".join(str(w) for w in warnings)]
    if analysis.get("uncertainties"):
        lines += ["", "**Incertitudes** — " + " ; ".join(str(u) for u in analysis["uncertainties"])]
    if analysis.get("operator_actions"):
        lines += ["", "**À faire**"] + [f"- {a}" for a in analysis["operator_actions"]]
    rules = analysis.get("rules") or []
    lines += ["", "**Règles proposées** (à relire avant de coller)"]
    if rules:
        for n, r in enumerate(rules, 1):
            lines.append(f"{n}. {r.get('explanation', '').strip()}")
            if r.get("side_effects"):
                lines.append(f"   _effets de bord : {r['side_effects']}_")
            lines.append(f"```\n{r.get('content', '').strip()}\n```")
    else:
        lines.append("_aucune — le WAF suffit, ou éléments insuffisants._")
    if analysis.get("ideas_to_review"):
        lines += ["", "**Pistes à expertiser** — " + " ; ".join(str(i) for i in analysis["ideas_to_review"])]
    if lien:
        lines += ["", f"[Rapport complet]({lien})"]
    return "\n".join(lines)


def _alarm_summary(alarms: list[Alarm]) -> list[dict]:
    counts = Counter((a.kind, a.rule, a.description) for a in alarms)
    return [{"famille": k, "regle": r, "description": d, "nombre": n} for (k, r, d), n in counts.most_common(8)]


def main() -> int:
    """Production (PC infra) : logs depuis Loki, alarmes Wazuh, envoi au llm-gateway."""
    import os
    import sys
    from pathlib import Path

    from . import logs
    from .escalation import EscalationConfig
    from .metrics import serve
    from .sources.loki import LokiSource, LokiWazuhAlarmSource
    from .training import load

    logs.setup()
    # Secrets lus dans /run/secrets (contrat de l'infra), jamais en variable d'environnement en clair.
    token_file = Path(os.getenv("LLM_GATEWAY_TOKEN_FILE", "/run/secrets/llm_gateway_token"))
    token = token_file.read_text(encoding="utf-8").strip() if token_file.exists() else ""
    gateway_url = os.getenv("LLM_GATEWAY_URL", "").strip()
    if gateway_url and not gateway_url.startswith(("http://", "https://")):
        log.error(json.dumps({"event": "configuration_invalide", "variable": "LLM_GATEWAY_URL",
                              "valeur": gateway_url[:80], "effet": "détection seule, sans appel au LLM"},
                             ensure_ascii=False))
        gateway_url = ""
    if gateway_url and len(token) < 32:
        print("LLM_GATEWAY_TOKEN absent ou trop court", file=sys.stderr)
        return 1
    from .sources.loki import LokiRemediationSource

    service = DetectorService(
        pipeline=load(Path(os.getenv("MODEL_PATH", "models/baseline.joblib"))),
        logs=LokiSource(os.getenv("LOKI_URL", "http://loki:3100"), os.getenv("LOKI_WAF_QUERY", '{service="bunkerweb"}')),
        alarms=LokiWazuhAlarmSource(os.getenv("LOKI_URL", "http://loki:3100"),
                                    os.getenv("LOKI_WAZUH_QUERY", '{service="wazuh"}'),
                                    margin_s=float(os.getenv("LOKI_WAZUH_MARGIN_S", "30"))),
        escalator=Escalator(EscalationConfig()),
        gateway=GatewayClient(gateway_url, token) if gateway_url else None,
        cycle_s=int(os.getenv("DETECTOR_CYCLE_S", "10")),
        reports_url=os.getenv("REPORTS_URL"),            # ex. http://<PC IA>:8080/reports (lien Grafana)
        ingest_delay_s=int(os.getenv("DETECTOR_INGEST_DELAY_S", "5")),
        actions=LokiRemediationSource(os.getenv("LOKI_URL", "http://loki:3100"),
                                      os.getenv("LOKI_REMEDIATION_QUERY", '{service="auto-recovery"}')),
        # Seuils de perte de visibilité : à recalibrer avec python -m detector.calibrate sur le PC infra.
        visibility_errors=int(os.getenv("DETECTOR_VISIBILITY_ERRORS", "3")),
        probe_ua=os.getenv("DETECTOR_PROBE_UA", "resilience-blackbox/"),
        probe_interval_s=float(os.getenv("DETECTOR_PROBE_INTERVAL_S", "5")),
        probe_missed=int(os.getenv("DETECTOR_PROBE_MISSED", "3")),
    )
    # /ready : Loki est la seule dépendance bloquante (sans journaux, rien à analyser). Le PC IA n'en
    # est pas une : sans lui, la détection et les métriques continuent.
    serve(service.metrics, int(os.getenv("METRICS_PORT", "8000")),
          checks=lambda: {"loki": "ok" if service.errors_in_row == 0 else "down"})
    service.run(Clock())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
