"""Alarmes que Wazuh aurait levées sur le trafic simulé (mêmes familles et règles que l'export
réel du 19-20/10/2026) : disponibilité vue par les sondes, bannissements, blocages d'injection."""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from detector.alarms import AVAILABILITY, WAF_BAN, WAF_BLOCK, Alarm
from detector.features import attack_signals
from detector.models import HttpRequestLog
from detector.sources.sim_normal import BLACKBOX_IP, PROBE_IP, UPTIME_IP

_PROBES = {PROBE_IP, BLACKBOX_IP, UPTIME_IP}
_PAYLOAD = ("sqli_hits", "xss_hits", "traversal_hits", "cmdi_hits")


def simulated_alarms(records: list[HttpRequestLog], ban_threshold: int = 20) -> list[Alarm]:
    out: list[Alarm] = []
    refused: dict[str, deque] = defaultdict(deque)
    banned_until: dict[str, object] = {}
    last_block: dict[str, object] = {}
    for rec in sorted(records, key=lambda r: r.ts):
        if rec.client_ip in _PROBES and rec.status == 503:
            out.append(Alarm(rec.ts, AVAILABILITY, "simulation", "31123", "503 vu par une sonde de supervision"))
        if rec.status in (403, 429):
            q = refused[rec.client_ip]
            q.append(rec.ts)
            while q and q[0] < rec.ts - timedelta(seconds=60):
                q.popleft()
            if len(q) >= ban_threshold and (rec.client_ip not in banned_until or rec.ts >= banned_until[rec.client_ip]):
                banned_until[rec.client_ip] = rec.ts + timedelta(seconds=300)
                out.append(Alarm(rec.ts, WAF_BAN, "simulation", "100110", "IP bannie (bad behavior)", rec.client_ip))
        if rec.status == 403 and any(attack_signals(rec.uri)[k] for k in _PAYLOAD):
            if rec.client_ip not in last_block or rec.ts - last_block[rec.client_ip] >= timedelta(seconds=60):
                last_block[rec.client_ip] = rec.ts
                out.append(Alarm(rec.ts, WAF_BLOCK, "simulation", "100100", "injection bloquée par le WAF", rec.client_ip))
    return out
