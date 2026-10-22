"""Exemples du contrat entre les deux PC : requêtes POST /analyze produites par le VRAI détecteur
sur les scénarios simulés, écrites dans contracts/analyze/ à la racine du dépôt.

Les deux suites de tests les lisent :
  - ml-detector : le détecteur produit-il encore cette forme (champ renommé, supprimé, ajouté) ?
  - ai-node     : la gateway lit-elle chaque champ (elle ignore en silence les champs inconnus) ?

À relancer après toute modification volontaire du format, puis relire le diff :
    python -m scripts.contract_examples
"""
from __future__ import annotations

import argparse
import json
from datetime import timedelta
from pathlib import Path

from detector.alarms import AVAILABILITY, Alarm
from detector.config import DetectorConfig
from detector.escalation import Escalator
from detector.infra_actions import InfraAction
from detector.service import DetectorService
from detector.sources.loki import LokiError
from detector.sources.replay import ReplaySource
from detector.training import filter_training_records, train
from scripts.scenarios import T0, baseline_traffic, ddos_traffic, demo_traffic
from scripts.sim_alarms import simulated_alarms

CONTRACTS = Path(__file__).resolve().parents[3] / "contracts" / "analyze"


class _Alarms:
    def __init__(self, alarms):
        self.alarms = alarms

    def fetch(self, start, end):
        return [a for a in self.alarms if start <= a.ts < end]


class _Actions:
    def __init__(self, actions):
        self.actions = actions

    def fetch(self, start, end):
        return [a for a in self.actions if start <= a.ts < end]


class _Gateway:
    """Rapport minimal : permet de produire une réanalyse (context.analyse_precedente)."""
    def analyze(self, cluster, context):
        return {"signature": cluster["signature"], "generated_at": "2026-10-20T14:00:00+00:00",
                "rules_file": f"/app/reports/20261020T140000Z_{cluster['signature']}.md", "warnings": [],
                "analysis": {"verdict": "attaque", "summary": "exemple", "confidence": "moyenne",
                             "attack_type": "exemple", "rules": [{"content": "USE_ANTIBOT=javascript"}]},
                "timings": {"total_s": 1.0}}


def _run(pipeline, records, start, end, alarms=(), actions=(), fail_after=None) -> list[dict]:
    replay = ReplaySource(records)

    class Logs:
        def fetch(self, a, b):
            if fail_after and b > fail_after:
                raise LokiError("Loki (http://loki:3100) : <urlopen error timed out>")
            return replay.fetch(a, b)

    svc = DetectorService(pipeline, Logs(), _Alarms(list(alarms)), Escalator(), _Gateway(),
                          actions=_Actions(list(actions)), heartbeat_s=0)
    now = start
    while now < end:
        try:
            svc.tick(now)
            svc.errors_in_row = 0
        except LokiError as exc:
            svc.errors_in_row += 1
            if svc.errors_in_row == svc.visibility_errors:
                svc._visibility_lost([f"sources de données injoignables depuis 3 cycles (30 s) : {exc}"], now)
        svc.drain(now)
        now += timedelta(seconds=10)
    return svc.sent


def build_examples(pipeline) -> dict[str, dict]:
    """Une requête par déclencheur et par situation."""
    examples: dict[str, dict] = {}

    def keep(name, item):
        examples[name] = {"cluster": item["cluster"], "context": item["context"]}

    ddos = [lr.record for lr in ddos_traffic()]
    restart = [
        InfraAction(T0 + timedelta(minutes=10, seconds=25), "alert_received", "WafDown", "restart", "bunkerweb", "firing"),
        InfraAction(T0 + timedelta(minutes=10, seconds=26), "remediation_started", "WafDown", "restart", "bunkerweb", ""),
        InfraAction(T0 + timedelta(minutes=10, seconds=40), "remediation_succeeded", "WafDown", "restart",
                    "bunkerweb", "service rétabli en 14 s"),
    ]
    sent = _run(pipeline, ddos, T0 + timedelta(minutes=9, seconds=50), T0 + timedelta(minutes=13),
                simulated_alarms(ddos), restart)
    keep("campagne_ddos", next(i for i in sent if i["trigger"] == "campagne"))
    # Exports coûteux : gravité 55 puis 80 -> réanalyse avec analyse_precedente.
    sent = _run(pipeline, ddos, T0 + timedelta(minutes=16, seconds=50), T0 + timedelta(minutes=18, seconds=30),
                simulated_alarms(ddos))
    keep("campagne_reanalyse", next(i for i in sent if i["mise_a_jour"]))

    web = [lr.record for lr in demo_traffic(waf_blocking=False)]
    sent = _run(pipeline, web, T0, web[-1].ts, simulated_alarms(web))
    injection = next((i for i in sent if i["trigger"] == "campagne"
                      and i["cluster"].get("injections_answered")), None)
    if injection:
        keep("campagne_injection", injection)

    quiet = [lr.record for lr in baseline_traffic(minutes=3)]
    failed = [Alarm(T0 + timedelta(minutes=2), AVAILABILITY, "wazuh", "100210", "Remédiation en échec : bascule PRA")]
    sent = _run(pipeline, quiet, T0 + timedelta(minutes=1, seconds=30), T0 + timedelta(minutes=3), failed)
    keep("symptome", next(i for i in sent if i["trigger"] == "symptome"))

    sent = _run(pipeline, ddos, T0 + timedelta(minutes=9, seconds=50), T0 + timedelta(minutes=11, seconds=30),
                simulated_alarms(ddos), restart, fail_after=T0 + timedelta(minutes=10, seconds=50))
    keep("visibilite", next(i for i in sent if i["trigger"] == "visibilite"))
    return examples


def baseline_pipeline():
    records, _ = filter_training_records([lr.record for lr in baseline_traffic(minutes=20)])
    return train(records, DetectorConfig())


def dumps(body: dict) -> str:
    return json.dumps(body, ensure_ascii=False, indent=1, sort_keys=True, default=str) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=CONTRACTS)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for name, body in build_examples(baseline_pipeline()).items():
        (args.out / f"{name}.json").write_text(dumps(body), encoding="utf-8")
        print(f"{args.out / name}.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
