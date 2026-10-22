"""Démo du service continu : rejoue un scénario « en direct » à travers le vrai service
(fenêtre glissante, cycles, escalade, file d'attente vers le LLM, /metrics).

    python -m scripts.run_service --scenario ddos --speed 5                 # à blanc (sans LLM)
    python -m scripts.run_service --scenario ddos --speed 5 \\
        --gateway http://localhost:8080 --token "$LLM_GATEWAY_TOKEN"        # avec le PC IA
    python -m scripts.run_service --scenario wazuh --export ../../wazuh-alerts.jsonl --speed 60

Vitesse 5 : les 20 minutes du scénario DDoS en 4 minutes ; les cycles de 10 s (temps du scénario)
durent alors 2 s réelles. Les appels au LLM, eux, gardent leur durée réelle (~40 s).
"""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import timedelta
from pathlib import Path

from detector.alarms import WazuhAlarmSource
from detector.escalation import Escalator
from detector.gateway_client import GatewayClient
from detector.metrics import serve
from detector.service import DetectorService
from detector.sources.replay import ReplayAlarmSource, ReplayClock, ReplaySource
from detector.sources.wazuh import WazuhJsonlSource
from detector.training import load
from scripts.scenarios import T0, ddos_traffic, demo_traffic
from scripts.sim_alarms import simulated_alarms


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", choices=("ddos", "web", "wazuh"), default="ddos")
    parser.add_argument("--export", type=Path, default=Path("../../wazuh-alerts.jsonl"))
    parser.add_argument("--model", type=Path, default=Path("models/baseline.joblib"))
    parser.add_argument("--speed", type=float, default=5.0, help="accélération du temps du scénario")
    parser.add_argument("--cycle", type=int, default=10, help="secondes (temps du scénario) entre deux analyses")
    parser.add_argument("--gateway", help="URL du llm-gateway ; absent : à blanc")
    parser.add_argument("--token", default="")
    parser.add_argument("--reports-url", help="adresse des pages de rapports (ex. http://127.0.0.1:8080/reports)")
    parser.add_argument("--metrics-port", type=int, default=0, help="expose /metrics sur ce port (0 : non)")
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(message)s")

    if args.scenario == "wazuh":
        records, alarms = WazuhJsonlSource(args.export).read_all(), WazuhAlarmSource(args.export).read_all()
        start, end = records[0].ts, records[-1].ts + timedelta(minutes=1)
    else:
        labeled = ddos_traffic() if args.scenario == "ddos" else demo_traffic()
        records = [lr.record for lr in labeled]
        alarms = simulated_alarms(records)
        start, end = T0, records[-1].ts + timedelta(seconds=1)

    service = DetectorService(load(args.model), ReplaySource(records), ReplayAlarmSource(alarms), Escalator(),
                              GatewayClient(args.gateway, args.token) if args.gateway else None,
                              cycle_s=args.cycle, reports_url=args.reports_url)
    if args.metrics_port:
        serve(service.metrics, args.metrics_port)
    print(f"Scénario {args.scenario} : {len(records)} requêtes, {len(alarms)} alarmes, cycle {args.cycle} s, "
          f"vitesse x{args.speed:g}, LLM {'via ' + args.gateway if args.gateway else 'à blanc'}\n")

    def show(tick: dict) -> None:
        sent = [d for d in tick["decisions"] if d.escalate]
        symptom = tick["symptom"] if tick["symptom"] and tick["symptom"].escalate else None
        if not (sent or symptom) and tick["score"] < 30:
            return
        line = f"{tick['now']:%H:%M:%S}  {tick['requests']:5d} req/60 s  {tick['clusters']} groupe(s)  gravité max {tick['score']:3d}"
        for d in sent:
            line += f"\n          -> LLM : {','.join(d.cluster.attack_hints)} (gravité {d.severity})"
            line += f"\n             {' ; '.join(d.reasons)}"
        if symptom:
            line += f"\n          -> LLM : symptôme sans campagne (gravité {symptom.severity})"
        print(line, flush=True)

    # Les dates du scénario sont rejouées à l'horloge accélérée ; les appels au LLM partent dans un
    # fil séparé et ne retardent pas les cycles.
    service.run(ReplayClock(start, args.speed), until=end, on_tick=show)
    print(f"\n{len(service.sent)} analyse(s) envoyée(s) au LLM, {len(service.reports)} rapport(s) reçu(s).")
    for report in service.reports:
        a = report.get("analysis", {})
        print(f"  {report.get('signature')}: {a.get('verdict')} — {len(a.get('rules', []))} règle(s), "
              f"{len(report.get('warnings', []))} avertissement(s) -> {report.get('rules_file')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
