"""Alarmes externes (WAF, Wazuh, supervision) : elles ne déclenchent pas le LLM seules, elles
pèsent dans la décision d'escalade (escalation.py).

Une alarme « XSS bloqué » porte sur ce que le WAF a DÉJÀ arrêté : elle corrobore un groupe
anormal (mêmes IP). Une alarme de disponibilité (503 vus par les sondes, remédiation automatique
de l'infra) signale un IMPACT : elle rend urgent de comprendre ce qui se passe.

Lecture seule : le module ne s'abonne jamais au webhook de remédiation de l'infra.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Familles d'alarmes, de la plus grave à la moins grave.
AVAILABILITY = "availability"     # service dégradé ou indisponible (503 vus par les sondes, WAF redémarré)
WAF_BAN = "waf_ban"               # IP bannie par le WAF (bad behavior, flood)
WAF_BLOCK = "waf_block"           # requête d'attaque bloquée par le WAF (XSS, SQLi, CRS)
RECON = "recon"                   # erreurs 4xx en série depuis une IP (scan)
AUTH = "auth"                     # échecs d'authentification, force brute (application de paiement)


@dataclass(frozen=True, slots=True)
class Alarm:
    ts: datetime
    kind: str
    source: str                   # "wazuh", "simulation"...
    rule: str                     # identifiant de la règle d'origine
    description: str
    ip: str | None = None


# Règles Wazuh de l'infra (local_rules.xml de la branche infrastructure, 100100-100211) -> famille.
_WAZUH_RULES = {
    "31123": AVAILABILITY, "31163": AVAILABILITY,       # 503 (dont sondes de supervision)
    "100210": AVAILABILITY, "100211": AVAILABILITY,     # remédiation automatique (WafDown : échec / succès)
    "100110": WAF_BAN,
    "100100": WAF_BLOCK, "100101": WAF_BLOCK, "100102": WAF_BLOCK, "100103": WAF_BLOCK,   # 100103 : campagne
    "100112": WAF_BAN,                                  # volume anormal (DDoS applicatif probable)
    "100200": AUTH, "100201": AUTH,                     # échec d'authentification, force brute
    "31105": WAF_BLOCK, "31154": WAF_BLOCK, "31333": WAF_BLOCK,
    "31151": RECON,
}


class WazuhAlarmSource:
    """Export JSON Lines des alertes Wazuh (rejeu). En production : même lecture depuis Loki
    ({service="wazuh"}) ou l'API Wazuh, à brancher avec la source de logs."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def read_all(self) -> list[Alarm]:
        out = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                alarm = self._to_alarm(line)
                if alarm is not None:
                    out.append(alarm)
        return sorted(out, key=lambda a: a.ts)

    @staticmethod
    def _to_alarm(line: str) -> Alarm | None:
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            return None
        alert = alert.get("_source", alert)
        rule = alert.get("rule") or {}
        kind = _WAZUH_RULES.get(str(rule.get("id")))
        if kind is None:
            return None
        try:
            ts = datetime.strptime(alert["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
        except (KeyError, ValueError):
            return None
        return Alarm(ts=ts, kind=kind, source="wazuh", rule=str(rule.get("id")),
                     description=str(rule.get("description", ""))[:160], ip=(alert.get("data") or {}).get("srcip"))


def in_window(alarms: list[Alarm], start: datetime, end: datetime) -> list[Alarm]:
    return [a for a in alarms if start <= a.ts < end]
