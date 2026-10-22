"""Entraîne le modèle de référence sur du trafic normal, le valide par canaris, l'enregistre.

    python -m scripts.train_baseline --out models/baseline.joblib [--minutes 30]

Source actuelle : trafic simulé. Quand LokiSource sera prête, la même procédure s'appliquera
sur une plage de vrais journaux choisie par l'opérateur (après filtrage).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from detector.config import DetectorConfig
from detector.training import ModelRejected, filter_training_records, save, train, validate_canaries
from scripts.scenarios import baseline_traffic, canary_traffic


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path("models/baseline.joblib"))
    parser.add_argument("--minutes", type=int, default=30, help="durée de trafic normal simulé")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    config = DetectorConfig()
    raw = [lr.record for lr in baseline_traffic(args.minutes, args.seed)]
    records, report = filter_training_records(raw)
    print(f"[train] {len(raw)} requêtes simulées, {report.kept} conservées, exclues : {report.excluded or 'aucune'}")

    pipeline = train(records, config)
    print(f"[train] IsolationForest entraîné, seuil d'anomalie = {pipeline.detector.threshold:.3f}")

    try:
        recall = validate_canaries(pipeline, [(lr.record, lr.label) for lr in canary_traffic()])
    except ModelRejected as exc:
        print(f"[train] MODÈLE REJETÉ : {exc}", file=sys.stderr)
        return 1
    print(f"[train] canaris détectés : {recall}")

    meta = save(pipeline, args.out, {
        "source": "simulated", "minutes": args.minutes, "seed": args.seed,
        "n_samples": report.kept, "excluded": report.excluded, "canary_recall": recall,
    })
    print(f"[train] modèle enregistré : {args.out} (sha256 {meta['sha256'][:12]}…)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
