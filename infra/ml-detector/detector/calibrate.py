"""Mesure, sur le PC infra, des délais réels des sources de données, pour remplacer les seuils
estimés du détecteur par des valeurs mesurées. Lecture seule : interroge Loki, ne touche à rien.

    docker compose run --rm ml-detector python -m detector.calibrate             # ~2 min
    docker compose run --rm ml-detector python -m detector.calibrate --watch-loki 180
        (pendant ce temps, dans un autre terminal : docker compose restart loki)

Mesures :
  - retard d'ingestion de Loki (WAF) : heure d'arrivée dans Loki - heure de la ligne
        -> DETECTOR_INGEST_DELAY_S
  - intervalle réel des sondes de supervision dans les journaux du WAF, et plus grand trou
        -> DETECTOR_PROBE_INTERVAL_S, DETECTOR_PROBE_MISSED
  - retard des alertes Wazuh sur les faits qu'elles signalent      -> LOKI_WAZUH_MARGIN_S
  - temps de réponse de Loki (délai d'attente du client : 10 s)
  - durée d'indisponibilité de Loki pendant un redémarrage (option --watch-loki)
        -> DETECTOR_VISIBILITY_ERRORS
"""
from __future__ import annotations

import argparse
import json
import math
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from .parsing import parse_line
from .sources.loki import LokiClient, LokiError


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(q / 100 * len(ordered)) - 1))]


def _stats(values: list[float]) -> dict:
    def r(v):
        return None if v is None else round(v, 2)
    return {"n": len(values), "p50": r(percentile(values, 50)), "p95": r(percentile(values, 95)),
            "p99": r(percentile(values, 99)), "max": r(max(values) if values else None)}


# -- mesures sur l'historique (fonctions pures, testées) --------------------------------------
def probe_stats(lines: list[str], probe_ua: str) -> dict:
    """Écarts entre sondes : par chemin (intervalle d'une sonde) et toutes confondues (trou)."""
    by_path: dict[str, list[datetime]] = defaultdict(list)
    for record in filter(None, map(parse_line, lines)):
        if record.user_agent.startswith(probe_ua):
            by_path[record.uri.split("?")[0]].append(record.ts)
    per_path = {}
    for path, stamps in by_path.items():
        stamps.sort()
        per_path[path] = _stats([(b - a).total_seconds() for a, b in zip(stamps, stamps[1:])])
    every = sorted(t for stamps in by_path.values() for t in stamps)
    return {"par_chemin": per_path, "toutes": _stats([(b - a).total_seconds() for a, b in zip(every, every[1:])])}


def volume_stats(lines: list[str], window_s: int = 60) -> dict:
    stamps = sorted(r.ts for r in filter(None, map(parse_line, lines)))
    if not stamps:
        return _stats([])
    counts: dict[int, int] = defaultdict(int)
    origin = stamps[0]
    for t in stamps:
        counts[int((t - origin).total_seconds() // window_s)] += 1
    return _stats([counts.get(i, 0) for i in range(max(counts) + 1)])


def wazuh_lateness(lines: list[str]) -> dict:
    """Alerte Wazuh dont full_log est une ligne d'accès : heure de l'alerte - heure de la requête."""
    delays = []
    for line in lines:
        first, last = line.find("{"), line.rfind("}")
        try:
            alert = json.loads(line[first:last + 1])
            alerted = datetime.strptime(alert["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
        except (ValueError, KeyError):
            continue
        record = parse_line(str(alert.get("full_log", "")))
        if record is not None:
            delays.append((alerted - record.ts).total_seconds())
    return _stats(delays)


def recommend(ingest: dict, probes: dict, wazuh: dict, outage_s: float | None, cycle_s: int = 10) -> dict:
    out = {}
    if ingest.get("p99") is not None:
        out["DETECTOR_INGEST_DELAY_S"] = max(2, math.ceil(ingest["p99"]) + 1)
    intervals = [s["p50"] for s in probes.get("par_chemin", {}).values() if s.get("p50")]
    if intervals:
        interval = round(min(intervals))                  # la sonde la plus fréquente
        gap = probes["toutes"].get("p99") or interval
        out["DETECTOR_PROBE_INTERVAL_S"] = max(1, interval)
        # Trou toléré : 3 intervalles au moins, et au-delà du plus grand trou normal observé (p99).
        out["DETECTOR_PROBE_MISSED"] = max(3, math.ceil(gap / max(1, interval)) + 1)
    if wazuh.get("p99") is not None:
        out["LOKI_WAZUH_MARGIN_S"] = max(10, math.ceil(wazuh["p99"]) + 5)
    if outage_s is not None:
        out["DETECTOR_VISIBILITY_ERRORS"] = max(2, math.ceil(outage_s / cycle_s) + 1)
    return out


# -- mesures en direct ------------------------------------------------------------------------
def measure_ingestion(client: LokiClient, query: str, duration_s: float, poll_s: float = 1.0) -> tuple[dict, list[float]]:
    """Retard d'ingestion : on interroge Loki chaque seconde ; une ligne vue pour la première fois
    à l'instant t a été ingérée au plus tard à t. Précision : poll_s + 1 s (heure de la ligne d'accès
    à la seconde)."""
    seen: set = set()
    delays, latencies = [], []
    first = True
    stop = time.time() + duration_s
    while time.time() < stop:
        now = datetime.now(timezone.utc)
        started = time.perf_counter()
        entries = client.entries(query, now - timedelta(seconds=60), now)
        latencies.append(time.perf_counter() - started)
        for ts_ns, line in entries:
            key = (ts_ns, hash(line))
            if key in seen:
                continue
            seen.add(key)
            if not first:                                   # le premier passage relit l'historique
                record = parse_line(line)
                if record is not None:
                    delays.append((now - record.ts).total_seconds())
        first = False
        time.sleep(poll_s)
    return _stats(delays), latencies


def watch_loki(base_url: str, duration_s: float) -> float | None:
    """Plus longue indisponibilité de Loki (/ready) observée pendant duration_s."""
    down_since, longest = None, None
    stop = time.time() + duration_s
    while time.time() < stop:
        try:
            with urllib.request.urlopen(f"{base_url}/ready", timeout=2) as response:
                ready = response.status == 200
        except (urllib.error.URLError, TimeoutError, OSError):
            ready = False
        now = time.time()
        if not ready and down_since is None:
            down_since = now
        elif ready and down_since is not None:
            longest = max(longest or 0.0, now - down_since)
            down_since = None
        time.sleep(1)
    if down_since is not None:
        longest = max(longest or 0.0, time.time() - down_since)
    return longest


def main() -> int:
    import os
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--loki", default=os.getenv("LOKI_URL", "http://loki:3100"))
    parser.add_argument("--waf-query", default=os.getenv("LOKI_WAF_QUERY", '{service="bunkerweb"}'))
    parser.add_argument("--wazuh-query", default=os.getenv("LOKI_WAZUH_QUERY", '{service="wazuh"}'))
    parser.add_argument("--probe-ua", default=os.getenv("DETECTOR_PROBE_UA", "resilience-blackbox/"))
    parser.add_argument("--history-min", type=int, default=60, help="historique analysé (minutes)")
    parser.add_argument("--duration", type=float, default=120, help="mesure en direct de l'ingestion (s)")
    parser.add_argument("--watch-loki", type=float, default=0,
                        help="surveille /ready pendant N s (redémarrer Loki pendant ce temps)")
    args = parser.parse_args()

    client = LokiClient(args.loki, max_pages=200)
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=args.history_min)
    try:
        waf = client.lines(args.waf_query, start, end)
        wazuh = client.lines(args.wazuh_query, start, end)
        print(f"Historique : {len(waf)} lignes WAF, {len(wazuh)} lignes Wazuh sur {args.history_min} min. "
              f"Mesure de l'ingestion en direct pendant {args.duration:.0f} s...", flush=True)
        ingest, latencies = measure_ingestion(client, args.waf_query, args.duration)
    except LokiError as exc:
        print(f"Loki injoignable : {exc}")
        return 1
    outage = None
    if args.watch_loki:
        print(f"Surveillance de Loki pendant {args.watch_loki:.0f} s : redémarrez-le maintenant "
              "(docker compose restart loki).", flush=True)
        outage = watch_loki(args.loki, args.watch_loki)

    result = {
        "retard_ingestion_s": ingest,
        "sondes_s": probe_stats(waf, args.probe_ua),
        "requetes_par_minute": volume_stats(waf),
        "retard_alertes_wazuh_s": wazuh_lateness(wazuh),
        "temps_reponse_loki_s": _stats(latencies),
        "indisponibilite_loki_s": outage,
    }
    result["recommandations"] = recommend(result["retard_ingestion_s"], result["sondes_s"],
                                          result["retard_alertes_wazuh_s"], outage)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result["sondes_s"]["par_chemin"]:
        print(f"ATTENTION : aucune sonde « {args.probe_ua} » dans les journaux du WAF : vérifier DETECTOR_PROBE_UA.")
    print("Reporter les recommandations dans l'environnement du service ml-detector (docker-compose.yml).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
