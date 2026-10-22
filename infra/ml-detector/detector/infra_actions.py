"""Actions automatiques de l'infra (moteur de remédiation), lues dans son journal JSON.

Lecture seule : le module ne s'abonne pas au webhook et ne déclenche rien. Ces actions sont
données au LLM (chronologie : « bunkerweb redémarré à 14:32, échec ») pour qu'il dise si elles
ont aidé ou non, et recopiées telles quelles dans le rapport.

Formats acceptés : convention commune (contracts/service-conventions.md : "timestamp", "event")
et ancien format de la branche infrastructure (services/common/obs.py : "ts", "msg") :
  {"timestamp": "2026-10-19T16:43:48.000+00:00", "service": "remediation", "event": "remediation_failed",
   "alertname": "WafDown", "action": "restart", "target": "bunkerweb", ...}
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from .alarms import AVAILABILITY, Alarm

# Événements retenus (remediation_action_done, intermédiaire, n'apporte rien de plus).
_EVENTS = {
    "alert_received": "alerte reçue",
    "remediation_started": "remédiation lancée",
    "remediation_succeeded": "remédiation réussie",
    "remediation_failed": "remédiation EN ÉCHEC",
    "remediation_skipped": "remédiation ignorée",
    "remediation_refused": "remédiation refusée",
}
FAILED = "remediation_failed"


@dataclass(frozen=True, slots=True)
class InfraAction:
    ts: datetime
    event: str
    alertname: str
    action: str | None
    target: str | None
    detail: str


def parse_line(line: str) -> InfraAction | None:
    try:
        fields = json.loads(line)
        if "timestamp" in fields:
            ts = datetime.fromisoformat(fields["timestamp"])
        else:
            ts = datetime.strptime(fields["ts"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    event = fields.get("event") or fields.get("msg")
    if event not in _EVENTS:
        return None
    if event == "alert_received":
        detail = f"{fields.get('status', '')} : {fields.get('summary') or ''}".strip(" :")
    elif event == "remediation_succeeded":
        detail = f"service rétabli en {fields.get('recovery_seconds')} s"
    elif event == FAILED:
        detail = str(fields.get("error") or "vérification métier en échec après l'action")
    else:
        detail = str(fields.get("reason") or "")
    return InfraAction(ts=ts, event=event, alertname=str(fields.get("alertname", "")),
                       action=fields.get("action"), target=fields.get("target"), detail=detail[:200])


def to_context(actions: list[InfraAction], limit: int = 20) -> list[dict]:
    """Chronologie pour le LLM et le rapport : les `limit` plus récentes, dans l'ordre."""
    return [{"heure": a.ts.isoformat(timespec="seconds"), "evenement": _EVENTS[a.event], "alerte": a.alertname,
             "action": a.action, "cible": a.target, "detail": a.detail}
            for a in sorted(actions, key=lambda a: a.ts)[-limit:]]


def as_alarms(actions: list[InfraAction]) -> list[Alarm]:
    """Un échec de remédiation est une alarme critique, même sans Wazuh (qui le signale par la
    règle 100210 s'il fonctionne encore)."""
    return [Alarm(ts=a.ts, kind=AVAILABILITY, source="remediation", rule=FAILED,
                  description=f"remédiation {a.action} de {a.target} en échec ({a.alertname})")
            for a in actions if a.event == FAILED]
