"""Rejoue un export d'alertes Wazuh (JSON Lines) dans le détecteur, par fenêtres comme en continu.

    python -m scripts.replay_wazuh ../../wazuh-alerts.jsonl [--model models/baseline.joblib] [--show-json]

Rappel : Wazuh n'exporte que les requêtes ayant déclenché une règle (4xx/5xx), sans le trafic
normal autour. Le taux de détection mesuré ici porte donc sur des requêtes déjà suspectes.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np

from datetime import timedelta

from detector.alarms import AVAILABILITY, WazuhAlarmSource, in_window
from detector.escalation import Escalator
from detector.features import BLOCKED_STATUSES
from detector.ip_history import IpHistory
from detector.sources.wazuh import WazuhJsonlSource
from detector.training import load


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("export", type=Path, help="fichier wazuh-alerts.jsonl")
    parser.add_argument("--model", type=Path, default=Path("models/baseline.joblib"))
    parser.add_argument("--show-json", action="store_true", help="affiche le JSON du plus gros cluster (contrat LLM)")
    args = parser.parse_args()

    if not args.model.exists():
        print(f"Modèle absent ({args.model}) : lancer d'abord le service 'train'.", file=sys.stderr)
        return 1
    pipeline = load(args.model)
    window = pipeline.config.window_seconds

    records = WazuhJsonlSource(args.export).read_all()
    if not records:
        print("Aucune requête HTTP (decoder web-accesslog) dans l'export.", file=sys.stderr)
        return 1
    X = pipeline.features(records)
    t0 = records[0].ts
    ts = np.array([(r.ts - t0).total_seconds() for r in records])

    flagged = np.zeros(len(records), dtype=bool)
    history = IpHistory()
    escalator, alarms = Escalator(), WazuhAlarmSource(args.export).read_all()
    groups = calls = symptoms = 0
    biggest = None
    print(f"Export : {len(records)} requêtes du {records[0].ts:%d/%m %H:%M} au {records[-1].ts:%d/%m %H:%M} UTC, "
          f"seuil {pipeline.detector.threshold:.3f}\n")

    # Fenêtres qui contiennent des requêtes OU des alarmes : une alarme critique peut tomber dans une
    # minute sans aucune requête (remédiation en échec du 20/10 à 07:30, manquée sans cela).
    alarm_windows = {int((a.ts - t0).total_seconds() // window) for a in alarms if a.ts >= t0}
    for w in sorted(set(np.unique((ts // window).astype(int)).tolist()) | alarm_windows):
        idx = np.flatnonzero((ts >= w * window) & (ts < (w + 1) * window))
        window_records = [records[i] for i in idx]
        result = pipeline.analyze(window_records, X[idx], history=history)
        history.update(window_records)
        flagged[idx] = result.is_anomaly
        w_from, w_to = t0 + timedelta(seconds=int(w) * window), t0 + timedelta(seconds=(int(w) + 1) * window)
        clock = w_from.strftime("%d/%m %H:%M")
        window_alarms = in_window(alarms, w_from, w_to)
        decisions = {d.cluster.cluster_id: d for d in escalator.decide(result.clusters, window_alarms, w_to)}
        availability = sum(a.kind == AVAILABILITY for a in window_alarms)
        note = f"  [{availability} alarme(s) de disponibilité]" if availability else ""
        symptom = escalator.decide_symptom(window_alarms, list(decisions.values()), w_to)
        if symptom:
            symptoms += 1
            calls += symptom.escalate
            what = (f"-> LLM sur la fenêtre entière (gravité {symptom.severity})" if symptom.escalate
                    else f"gravité {symptom.severity}, non envoyé : {symptom.skipped_because or 'sous le seuil'}")
            note += f"\n{'':19s}SYMPTÔME SANS CAMPAGNE {what} : {' ; '.join(symptom.reasons)}"
        if not result.clusters:
            print(f"{clock}  {len(idx):5d} req  max {result.max_score:.2f}  —{note}")
            continue
        print(f"{clock}  {len(idx):5d} req  max {result.max_score:.2f}  {len(result.clusters)} groupe(s) anormal(aux){note}")
        for c in result.clusters:
            d = decisions[c.cluster_id]
            groups += 1
            calls += d.escalate
            verdict = (f"-> LLM (gravité {d.severity})" if d.escalate else
                       f"   gravité {d.severity:3d}" + (f", non envoyé : {d.skipped_because}" if d.skipped_because else ""))
            print(f"         {c.cluster_id:9s} {c.n_requests:5d} req  {c.n_distinct_ips:2d} IP  "
                  f"{','.join(c.attack_hints):34s} {verdict}")
            if d.escalate:
                print(f"{'':19s}raisons : {' ; '.join(d.reasons)}")
            if biggest is None or (c.n_requests > biggest.n_requests and c.cluster_id != "isolated"):
                biggest = c

    print(f"\nEscalade vers le LLM : {calls} appel(s) pour {groups} groupes anormaux et {symptoms} fenêtre(s) "
          f"à symptôme sans campagne ({len(alarms)} alarmes Wazuh)")
    print(f"Requêtes signalées : {flagged.mean():.1%} ({flagged.sum()}/{len(records)})")
    blocked = np.array([r.status in BLOCKED_STATUSES for r in records])
    for label, mask in (("bloquées par le WAF", blocked), ("non bloquées par le WAF", ~blocked)):
        if mask.any():
            print(f"  {label:24s} {flagged[mask].mean():6.1%}  ({mask.sum()} req)")
    for label, key in (("statut", lambda r: r.status), ("IP", lambda r: r.client_ip)):
        print(f"Par {label} :")
        groups = Counter(key(r) for r in records)
        for value, n in groups.most_common():
            hits = sum(flagged[i] for i, r in enumerate(records) if key(r) == value)
            print(f"  {str(value):15s} {hits / n:6.1%}  ({n} req)")

    if args.show_json and biggest is not None:
        print("\nExemple de résumé envoyé au LLM (plus gros cluster) :")
        print(json.dumps(biggest.to_dict(), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
