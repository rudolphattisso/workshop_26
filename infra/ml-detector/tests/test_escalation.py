"""Escalade vers le LLM : n'appeler que ce qui le mérite, dire pourquoi."""
from datetime import datetime, timedelta, timezone

import pytest

from detector.alarms import AVAILABILITY, WAF_BAN, Alarm, WazuhAlarmSource
from detector.escalation import EscalationConfig, Escalator, severity
from detector.models import ClusterSummary

T = datetime(2026, 10, 20, 14, 0, tzinfo=timezone.utc)


def cluster(hints, n=500, ips=1, statuses=None, blocked=0.0, signature="s1", top_ip="10.0.0.1", answered=0):
    return ClusterSummary(cluster_id="c0", signature=signature, window_start="", window_end="", n_requests=n,
                          n_distinct_ips=ips, score_mean=0.9, score_max=1.0, blocked_ratio=blocked,
                          attack_hints=list(hints), top_ips=[{"ip": top_ip, "count": n}], top_paths=[], methods={},
                          statuses=statuses or {"200": n}, top_user_agents=[], injections_answered=answered)


def alarm(kind, rule="31123", ip=None, at=T):
    return Alarm(at, kind, "test", rule, "test", ip)


@pytest.mark.parametrize("c, alarms, escalate", [
    # Botnet qui sature le service : oui.
    (cluster(["distributed_flood"], n=9000, ips=300, statuses={"503": 5400, "200": 3600}), [alarm(AVAILABILITY)], True),
    # Injection bloquée à 100 % par le WAF, sans impact : une attaque seule et contenue ne nuit pas.
    (cluster(["xss"], n=65, statuses={"403": 65}, blocked=1.0), [], False),
    # La même injection qui reçoit des réponses de l'application : oui (ce que le WAF n'a pas vu).
    (cluster(["xss"], n=65, statuses={"200": 65}, blocked=0.0, answered=65), [], True),
    # Groupe naissant : 1 réponse 200 d'un client ordinaire, aucune injection servie (vu en démo).
    (cluster(["sql_injection"], n=5, statuses={"403": 4, "200": 1}, blocked=0.8, answered=0), [], False),
    # 503 pendant un redémarrage du WAF : l'injection n'a PAS atteint l'application (vu le 20/10 à 08:56).
    (cluster(["xss"], n=3, statuses={"503": 2, "403": 1}, blocked=0.33), [alarm(AVAILABILITY)], False),
    # Flood d'une IP contenu par le WAF : non.
    (cluster(["request_flood", "automated_tool"], n=1665, statuses={"403": 1640, "429": 25}, blocked=1.0), [], False),
    # Trois clients légitimes pris dans une saturation : l'impact concerne le service, pas eux.
    (cluster(["unknown_anomaly"], n=3, statuses={"503": 3}), [alarm(AVAILABILITY)], False),
    # Requêtes anormalement lourdes avec service dégradé : oui.
    (cluster(["heavy_requests"], n=105, ips=17, statuses={"200": 64, "503": 41}), [alarm(AVAILABILITY)], True),
])
def test_escalation_policy(c, alarms, escalate):
    d = Escalator().decide([c], alarms, now=T)[0]
    assert d.escalate is escalate, (d.severity, d.reasons)
    assert d.reasons                                                    # toujours expliqué


def test_waf_corroboration_on_same_ip_raises_severity():
    c = cluster(["credential_bruteforce"], n=200, statuses={"401": 200})
    alone, _ = severity(c, [])
    corroborated, reasons = severity(c, [alarm(WAF_BAN, "100110", ip="10.0.0.1")])
    assert corroborated == alone + 10 and any("100110" in r for r in reasons)


def test_cooldown_and_worsening():
    esc = Escalator(EscalationConfig(threshold=50, cooldown_s=1800, worsening=20, max_per_minute=2))
    mild = cluster(["heavy_requests"], n=60, statuses={"200": 60})
    worse = cluster(["heavy_requests"], n=105, statuses={"200": 64, "503": 41})
    first = esc.decide([mild], [alarm(AVAILABILITY)], T)[0]
    again = esc.decide([mild], [alarm(AVAILABILITY)], T + timedelta(minutes=1))[0]
    worsened = esc.decide([worse], [alarm(AVAILABILITY)], T + timedelta(minutes=2))[0]
    later = esc.decide([mild], [alarm(AVAILABILITY)], T + timedelta(minutes=40))[0]
    assert first.escalate and not again.escalate and "délai de garde" in again.skipped_because
    assert worsened.escalate                                            # aggravation nette : réanalyse
    assert later.escalate                                               # délai de garde écoulé


def test_llm_calls_are_capped_per_window_and_ordered_by_severity():
    esc = Escalator(EscalationConfig(threshold=50, cooldown_s=1800, worsening=20, max_per_minute=1))
    big = cluster(["distributed_flood"], n=9000, ips=300, statuses={"503": 9000}, signature="big")
    small = cluster(["xss"], n=65, statuses={"200": 65}, signature="small", answered=65)
    decisions = esc.decide([small, big], [], T)
    assert [d.cluster.signature for d in decisions if d.escalate] == ["big"]
    assert "plafond" in next(d for d in decisions if d.cluster.signature == "small").skipped_because


def test_persistence_over_consecutive_windows():
    esc = Escalator(EscalationConfig(threshold=101, cooldown_s=0, worsening=0, max_per_minute=9))
    c = cluster(["request_flood"], n=100)
    scores = [esc.decide([c], [], T + timedelta(minutes=w))[0].severity for w in range(3)]
    assert scores[2] == scores[0] + 10


def test_symptom_without_campaign_and_remediation_failure():
    esc = Escalator()
    quiet = [cluster(["unknown_anomaly"], n=2)]
    decisions = esc.decide(quiet, [], T)
    assert esc.decide_symptom([alarm(AVAILABILITY)] * 2, decisions, T) is None             # trop peu
    first = esc.decide_symptom([alarm(AVAILABILITY)] * 25, decisions, T)
    assert first.escalate and first.to_context()["trigger"] == "symptome_sans_campagne"
    # Une seule alarme d'échec de remédiation suffit, et passe outre le délai de garde.
    failed = esc.decide_symptom([alarm(AVAILABILITY, "100210")], decisions, T + timedelta(minutes=5))
    assert failed.escalate and any("ÉCHEC" in r for r in failed.reasons)


def test_symptom_is_not_raised_when_a_campaign_explains_it():
    esc = Escalator()
    botnet = cluster(["distributed_flood"], n=9000, ips=300, statuses={"503": 5000, "200": 4000})
    decisions = esc.decide([botnet], [alarm(AVAILABILITY)] * 25, T)
    assert esc.decide_symptom([alarm(AVAILABILITY)] * 25, decisions, T) is None


def test_wazuh_rules_map_to_alarm_families(tmp_path):
    lines = [
        '{"timestamp":"2026-10-20T07:30:49.214+0000","rule":{"id":"100210","description":"échec"},"data":{}}',
        '{"timestamp":"2026-10-19T16:43:48.000+0000","rule":{"id":"100110","description":"ban"},"data":{"srcip":"172.30.10.1"}}',
        '{"timestamp":"2026-10-19T16:43:48.000+0000","rule":{"id":"19009","description":"SCA"}}',
        "pas du json",
    ]
    path = tmp_path / "alerts.jsonl"
    path.write_text("\n".join(lines), encoding="utf-8")
    alarms = WazuhAlarmSource(path).read_all()
    assert [(a.kind, a.rule, a.ip) for a in alarms] == [(WAF_BAN, "100110", "172.30.10.1"), (AVAILABILITY, "100210", None)]


def test_sliding_cycles_every_10_seconds_do_not_multiply_llm_calls():
    """Fenêtre glissante recalculée toutes les 10 s : la même campagne est revue à chaque cycle,
    mais n'est envoyée qu'une fois ; sa persistance se compte en minutes, pas en cycles."""
    esc = Escalator(EscalationConfig(threshold=50, cooldown_s=1800, worsening=20, max_per_minute=2, persistence_s=120))
    botnet = cluster(["distributed_flood"], n=9000, ips=300, statuses={"503": 5000, "200": 4000})
    sent, persisted = 0, None
    for k in range(18):                                     # 3 minutes de cycles de 10 s
        d = esc.decide([botnet], [], T + timedelta(seconds=10 * k))[0]
        sent += d.escalate
        if any("persiste" in r for r in d.reasons) and persisted is None:
            persisted = 10 * k
    assert sent == 1 and persisted == 120


def test_campaign_identity_survives_minor_variations_between_cycles():
    """Vu en démo : un chemin secondaire et un indice ajouté faisaient renvoyer la même campagne."""
    from detector.escalation import campaign_key
    heavy = cluster(["heavy_requests"], n=200, signature="a")
    heavy.top_paths = [{"path": "/api/payments", "count": 190}, {"path": "/", "count": 10}]
    variant = cluster(["distributed_flood", "heavy_requests"], n=150, signature="b")
    variant.top_paths = [{"path": "/api/payments", "count": 150}]
    botnet = cluster(["distributed_flood"], n=9000, signature="c")
    botnet.top_paths = [{"path": "/", "count": 9000}]
    cachebust = cluster(["distributed_flood"], n=4000, signature="d")
    cachebust.top_paths = [{"path": "/", "count": 2000}, {"path": "/api/payments/ready", "count": 2000}]
    assert campaign_key(heavy) == campaign_key(variant)
    assert campaign_key(botnet) != campaign_key(cachebust)            # deux attaques distinctes


def test_only_one_reanalysis_per_cooldown():
    """Vu en démo : 55 -> 80 -> 100 donnait trois analyses de la même campagne en deux minutes."""
    esc = Escalator(EscalationConfig(threshold=50, cooldown_s=1800, worsening=20, max_per_minute=9))
    def heavy(statuses):
        c = cluster(["heavy_requests"], n=100, statuses=statuses)
        c.top_paths = [{"path": "/api/payments", "count": 100}]
        return c
    calls = [esc.decide([heavy(s)], [alarm(AVAILABILITY)], T + timedelta(minutes=m))[0].escalate
             for m, s in enumerate([{"200": 100}, {"200": 70, "503": 30}, {"503": 100}])]
    assert calls == [True, True, False]
