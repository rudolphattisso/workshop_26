"""Démo hors ligne : trafic simulé + attaques, analysé par fenêtres de 60 s comme en continu.

    python -m scripts.demo_detect [--scenario ddos|web] [--detection-only] [--show-json]

Scénario « ddos » (défaut, 20 min, WAF actif) : flood d'une IP (arrêté par le WAF), afflux promo
légitime (piège à faux positifs), puis trois DDoS qui passent sous les seuils du WAF (botnet,
contournement de cache, exports coûteux). Voir scripts/scenarios.py.
Scénario « web » (15 min) : injections, scan, force brute, flood.

Affiche les clusters détectés par fenêtre, comparés à la vérité terrain du simulateur
(qui n'est jamais montrée au modèle), puis, par type d'attaque, la part bloquée par le WAF,
le rappel du module sur ce que le WAF laisse passer (sa valeur ajoutée) et la couverture
combinée, ainsi que le taux de faux positifs sur le trafic normal. Le modèle ne voit jamais la
décision du WAF : --detection-only mesure le cas où le WAF ne bloque rien par signature.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import Path

import numpy as np

from detector.alarms import in_window
from detector.escalation import Escalator
from detector.features import BLOCKED_STATUSES
from detector.ip_history import IpHistory
from detector.training import load
from detector.sources.sim_normal import RUSH_NET
from scripts.scenarios import T0, ddos_traffic, demo_traffic
from scripts.sim_alarms import simulated_alarms


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", type=Path, default=Path("models/baseline.joblib"))
    parser.add_argument("--scenario", choices=("ddos", "web"), default="ddos")
    parser.add_argument("--minutes", type=int, help="durée (défaut : 20 pour ddos, 15 pour web)")
    parser.add_argument("--detection-only", action="store_true", help="scénario web : WAF en DetectionOnly")
    parser.add_argument("--show-json", action="store_true", help="affiche le JSON du plus gros cluster (contrat LLM)")
    args = parser.parse_args()

    if not args.model.exists():
        print(f"Modèle absent ({args.model}) : lancer d'abord le service 'train'.", file=sys.stderr)
        return 1
    pipeline = load(args.model)
    window = pipeline.config.window_seconds

    if args.scenario == "ddos":
        args.minutes = args.minutes or 20
        labeled = ddos_traffic(args.minutes)
    else:
        args.minutes = args.minutes or 15
        labeled = demo_traffic(args.minutes, waf_blocking=not args.detection_only)
    records = [lr.record for lr in labeled]
    truth = np.array([lr.label for lr in labeled])
    # Features calculées sur toute la chronologie : les features par IP voient l'historique,
    # exactement comme le service en continu qui garde l'état d'une fenêtre à l'autre.
    X = pipeline.features(records)
    ts = np.array([(r.ts - T0).total_seconds() for r in records])

    flagged = np.zeros(len(records), dtype=bool)
    history = IpHistory()
    escalator, alarms = Escalator(), simulated_alarms(records)
    escalation_stats: dict[str, list[int]] = defaultdict(lambda: [0, 0])   # vérité dominante -> [groupes, appels LLM]
    biggest = None
    print(f"Trafic : {len(records)} requêtes sur {args.minutes} min, "
          f"WAF {'DetectionOnly' if args.detection_only else 'On'}, seuil {pipeline.detector.threshold:.3f}\n")

    for w_start in range(0, args.minutes * 60, window):
        idx = np.flatnonzero((ts >= w_start) & (ts < w_start + window))
        if not len(idx):
            continue
        window_records = [records[i] for i in idx]
        result = pipeline.analyze(window_records, X[idx], history=history)
        history.update(window_records)
        flagged[idx] = result.is_anomaly
        clock = (T0 + timedelta(seconds=w_start)).strftime("%H:%M")
        w_from, w_to = T0 + timedelta(seconds=w_start), T0 + timedelta(seconds=w_start + window)
        decisions = {d.cluster.cluster_id: d for d in
                     escalator.decide(result.clusters, in_window(alarms, w_from, w_to), w_to)}
        if not result.clusters:
            print(f"{clock}  {len(idx):5d} req  max {result.max_score:.2f}  —")
            continue
        print(f"{clock}  {len(idx):5d} req  max {result.max_score:.2f}  {len(result.clusters)} groupe(s) anormal(aux)")
        for c in result.clusters:
            members = idx[result.labels == (-1 if c.cluster_id == "isolated" else int(c.cluster_id[1:]))]
            composition = dict(Counter(truth[members]).most_common(3))
            d = decisions[c.cluster_id]
            verdict = (f"-> LLM (gravité {d.severity})" if d.escalate else
                       f"   gravité {d.severity:3d}" + (f", non envoyé : {d.skipped_because}" if d.skipped_because else ""))
            print(f"         {c.cluster_id:9s} {c.n_requests:5d} req  {c.n_distinct_ips:3d} IP  "
                  f"{','.join(c.attack_hints):34s} {verdict}   vérité={composition}")
            if d.escalate:
                print(f"{'':19s}raisons : {' ; '.join(d.reasons)}")
            stats = escalation_stats[Counter(truth[members]).most_common(1)[0][0]]
            stats[0] += 1
            stats[1] += d.escalate
            if biggest is None or (c.n_requests > biggest.n_requests and c.cluster_id != "isolated"):
                biggest = c

    calls = sum(v[1] for v in escalation_stats.values())
    print(f"\nEscalade vers le LLM : {calls} appel(s) pour {sum(v[0] for v in escalation_stats.values())} groupes "
          f"anormaux ({len(alarms)} alarmes WAF/supervision simulées)")
    for label, (groups, sent) in sorted(escalation_stats.items(), key=lambda kv: -kv[1][1]):
        print(f"  {label:18s} {groups:3d} groupe(s), {sent} appel(s) au LLM")

    # Valeur ajoutée du module = ce qu'il trouve parmi ce que le WAF a laissé passer.
    blocked = np.array([r.status in BLOCKED_STATUSES for r in records])
    print("\nPar type d'attaque :   WAF seul | module sur ce que le WAF laisse passer | WAF + module")
    for kind in sorted(set(truth) - {"normal"}):
        mask = truth == kind
        missed = mask & ~blocked
        on_missed = f"{flagged[missed].mean():6.1%} ({missed.sum():4d} req)" if missed.any() else "     —  (   0 req)"
        print(f"  {kind:11s} {blocked[mask].mean():6.1%}  |  {on_missed}  |  {(flagged | blocked)[mask].mean():6.1%}")
    attack = truth != "normal"
    missed = attack & ~blocked
    if missed.any():
        print(f"  {'TOUTES':11s} {blocked[attack].mean():6.1%}  |  {flagged[missed].mean():6.1%} ({missed.sum():4d} req)"
              f"  |  {(flagged | blocked)[attack].mean():6.1%}")
    normal = truth == "normal"
    rush = normal & np.array([r.client_ip.startswith(RUSH_NET) for r in records])
    if rush.any():
        print(f"Faux positifs sur l'afflux légitime (promo) : {flagged[rush].mean():.2%} ({flagged[rush].sum()}/{rush.sum()})")
    saturated = normal & np.array([r.status == 503 for r in records])
    if saturated.any():
        print(f"Faux positifs sur les clients légitimes touchés par la saturation (503) : "
              f"{flagged[saturated].mean():.2%} ({flagged[saturated].sum()}/{saturated.sum()})")
    print(f"Faux positifs sur le trafic normal : {flagged[normal].mean():.2%} ({flagged[normal].sum()}/{normal.sum()})")

    if args.show_json and biggest is not None:
        print("\nExemple de résumé envoyé au LLM (plus gros cluster) :")
        print(json.dumps(biggest.to_dict(), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
