"""Tests par propriétés : au lieu d'exemples choisis, des milliers de règles générées au hasard en
mêlant fragments légitimes et dangereux. Quelle que soit la règle proposée, ce qui est ACCEPTÉ
doit respecter les invariants ci-dessous. Un exemple qui les viole est réduit automatiquement au
cas minimal et affiché.
"""
import ipaddress
import re

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from conftest import llm_answer, load_cluster, rule
from llm_gateway import guardrails
from llm_gateway.config import GatewayConfig
from llm_gateway.contract import ClusterSummary, LlmAnalysis

CONFIG = GatewayConfig(token="x")
CLUSTER_DATA = load_cluster("distributed_flood")
CLUSTER_DATA["top_ips"][1]["assessment"] = "possible_waf_collateral"
CLUSTER = ClusterSummary.model_validate(CLUSTER_DATA)
ATTACKERS = [e.ip for e in CLUSTER.top_ips if not e.assessment]
COLLATERAL = [e.ip for e in CLUSTER.top_ips if e.assessment]

IPS = st.one_of(
    st.sampled_from(ATTACKERS + COLLATERAL + ["10.66.0.0/24", "10.0.0.0/8", "203.0.113.10", "0.0.0.0/0"]),
    st.ip_addresses(v=4).map(str),
    st.ip_addresses(v=6).map(str),
    st.builds(lambda a, p: f"{a}/{p}", st.ip_addresses(v=6).map(str), st.integers(0, 128)),
)
BW_FRAGMENTS = st.one_of(
    st.sampled_from(["USE_ANTIBOT=javascript", "USE_ANTIBOT=no", "USE_WHITELIST=yes", "WHITELIST_IP=10.0.0.66",
                     "USE_MODSECURITY=no", "USE_LIMIT_REQ=yes", "LIMIT_REQ_URL_1=/", "LIMIT_REQ_RATE_1=1r/m",
                     "LIMIT_REQ_RATE_2=50r/s", "LIMIT_REQ_URL_2=/api/payments", "BLACKLIST_USER_AGENT=Mozilla",
                     "BLACKLIST_USER_AGENT=sqlmap", "BLACKLIST_URI=/wp-admin", "BLACKLIST_URI=/api",
                     "USE_BAD_BEHAVIOR=no", "BAD_BEHAVIOR_BAN_TIME=0", "USE_DNSBL=yes"]),
    IPS.map(lambda ip: f"BLACKLIST_IP={ip}"),
)
MODSEC_FRAGMENTS = st.one_of(
    st.sampled_from([
        'SecRule ARGS_GET:limit "@gt 1000" "id:99001,phase:1,deny,status:403,log,msg:\'export\'"',
        'SecRule REQUEST_URI "@rx ." "id:99002,phase:1,pass,ctl:ruleEngine=Off"',
        'SecRule REMOTE_ADDR "@ipMatch 10.0.0.66" "id:99003,phase:1,allow"',
        "SecRuleEngine Off", "SecRuleRemoveById 942100", "Include /etc/passwd",
        'SecRule ARGS "@rx x" "id:99004,phase:1,deny,nolog"',
        'SecRule ARGS "@rx x" "id:942100,phase:1,deny"',
        'SecRule REQUEST_FILENAME "@streq /api/payments" "id:99005,phase:1,deny,log,msg:\'tout\'"',
    ]),
    IPS.map(lambda ip: f'SecRule REMOTE_ADDR "@ipMatch {ip}" "id:99010,phase:1,deny,status:403,log,msg:\'ip\'"'),
)
SEPARATORS = st.sampled_from(["\n", ", ", " / ", "; ", "\\n", " "])
FORBIDDEN = re.compile(r"whitelist|secruleengine|ctl\s*:|secrule(remove|update)|\bnolog\b|\ballow\b|"
                       r"\bexec\s*:|\binclude\b|```", re.IGNORECASE)


def contents(fragments):
    return st.builds(lambda parts, sep: sep.join(parts), st.lists(fragments, min_size=1, max_size=4), SEPARATORS)


def validate(rules, verdict="attaque", actions=()):
    analysis = LlmAnalysis.model_validate(llm_answer(verdict, rules, actions))
    return guardrails.validate(analysis, CLUSTER, CONFIG)[0]


def networks_in(text):
    return [net for _, net in guardrails._networks(text) if net is not None]


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(st.one_of(contents(BW_FRAGMENTS).map(lambda c: rule("bunkerweb", c)),
                          contents(MODSEC_FRAGMENTS).map(lambda c: rule("modsecurity", c))), max_size=5))
def test_accepted_rules_always_respect_the_invariants(rules):
    for accepted in validate(rules).rules:
        text = accepted.content
        assert not FORBIDDEN.search(text)                                        # rien qui relâche ou masque
        for net in networks_in(text):                                            # IP ciblées : du cluster, étroites
            assert net.prefixlen >= guardrails._MIN_PREFIX[net.version]
            assert any(ipaddress.ip_address(a) in net for a in ATTACKERS if ipaddress.ip_address(a).version == net.version)
            assert not any(ipaddress.ip_address(c) in net for c in COLLATERAL if ipaddress.ip_address(c).version == net.version)
        if accepted.engine.value == "modsecurity":
            assert all(CONFIG.rule_id_min <= int(i) <= CONFIG.rule_id_max for i in re.findall(r"id:'?(\d+)", text))
        else:
            for line in filter(None, (x.strip() for x in text.splitlines())):
                key, _, value = line.partition("=")
                assert re.sub(r"_\d+$", "", key) in guardrails._BW_ALLOWED
                assert not (key.startswith("USE_") and key != "USE_ANTIBOT" and value != "yes")


@settings(max_examples=200, deadline=None)
@given(st.lists(contents(BW_FRAGMENTS).map(lambda c: rule("bunkerweb", c)), min_size=1, max_size=3),
       st.sampled_from(["bannissement_collateral_probable", "faux_positif_probable", "indetermine"]))
def test_no_rule_survives_a_non_attack_verdict(rules, verdict):
    assert validate(rules, verdict).rules == []


@settings(max_examples=200, deadline=None)
@given(st.lists(st.builds(lambda a, b, c: f"{a} {b} {c}", st.text(max_size=20),
                          st.sampled_from(["whitelist", "liste blanche", "WHITELIST_IP=1.2.3.4", "désactiver le WAF",
                                           "SecRuleEngine Off", "vérifier les sondes"]),
                          st.text(max_size=20)), max_size=6))
def test_dangerous_advice_never_survives(actions):
    for advice in validate([], actions=actions).operator_actions:
        assert not re.search(r"whitelist|liste blanche|secruleengine|désactiver le waf", advice, re.IGNORECASE)
