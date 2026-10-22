import pytest

from conftest import llm_answer, load_cluster, rule
from llm_gateway import guardrails
from llm_gateway.contract import ClusterSummary, LlmAnalysis

BOTNET = ClusterSummary.model_validate(load_cluster("distributed_flood"))
ATTACKER = BOTNET.top_ips[0].ip


def check(rules, verdict="attaque", cluster=BOTNET, config=None, actions=()):
    from llm_gateway.config import GatewayConfig
    analysis = LlmAnalysis.model_validate(llm_answer(verdict, rules, actions))
    return guardrails.validate(analysis, cluster, config or GatewayConfig(token="x"))


@pytest.mark.parametrize("r", [
    rule("bunkerweb", "USE_ANTIBOT=javascript"),
    rule("bunkerweb", "USE_LIMIT_REQ=yes\nLIMIT_REQ_URL_2=/api/payments\nLIMIT_REQ_RATE_2=2r/s"),
    rule("bunkerweb", f"USE_BLACKLIST=yes\nBLACKLIST_IP={ATTACKER}"),
    rule("modsecurity", 'SecRule REQUEST_FILENAME "@streq /api/payments" '
                        '"id:99001,phase:1,deny,status:403,log,msg:\'export\',chain"\n'
                        '    SecRule ARGS_GET:limit "@gt 1000"'),
    rule("modsecurity", f'SecRule REMOTE_ADDR "@ipMatch {ATTACKER}" "id:99002,phase:1,deny,status:403,log,msg:\'bot\'"'),
])
def test_tightening_rules_pass(r):
    analysis, rejected = check([r])
    assert len(analysis.rules) == 1 and not rejected


@pytest.mark.parametrize("r, reason", [
    (rule("bunkerweb", "USE_WHITELIST=yes\nWHITELIST_IP=10.0.0.66"), "liste blanche"),
    (rule("bunkerweb", "USE_MODSECURITY=no"), "hors de la liste"),
    (rule("bunkerweb", "USE_BAD_BEHAVIOR=no"), "doit valoir yes"),
    (rule("bunkerweb", "USE_ANTIBOT=no"), "défi"),
    (rule("bunkerweb", "LIMIT_REQ_RATE_1=beaucoup"), "invalide"),
    (rule("modsecurity", "SecRuleEngine Off"), "moteur"),
    (rule("modsecurity", 'SecRule REQUEST_URI "@rx ." "id:99003,phase:1,pass,ctl:ruleEngine=Off"'), "ctl"),
    (rule("modsecurity", "SecRuleRemoveById 942100"), "retire"),
    (rule("modsecurity", 'SecRule REMOTE_ADDR "@ipMatch 10.0.0.66" "id:99004,phase:1,allow"'), "allow"),
    (rule("modsecurity", 'SecRule ARGS "@rx x" "id:942999,phase:2,deny"'), "plage"),
    (rule("modsecurity", 'SecRule ARGS "@rx x" "phase:2,deny"'), "id"),
    (rule("modsecurity", 'SecRule ARGS "@rx x" "id:99005,phase:2,deny,nolog"'), "journaux"),
    (rule("bunkerweb", "BLACKLIST_IP=8.8.8.8"), "aucune IP"),                 # IP hors du cluster
    (rule("bunkerweb", "BLACKLIST_IP=10.0.0.0/8"), "trop large"),
    (rule("bunkerweb", "USE_ANTIBOT=javascript\n```\nrm -rf /"), "Markdown"),
    # Portée : toutes les conditions inversées = presque tout le trafic (vu sur qwen2.5, 2026-10-22).
    (rule("modsecurity", 'SecRule ARGS_GET "!@contains DROP" "id:99006,phase:1,deny,status:403,log,msg:\'x\',chain"\n'
                         '    SecRule ARGS_GET "!@rx union"'), "presque TOUT"),
    # Portée : %XX comparé à un paramètre déjà décodé = ne correspond jamais (vu sur qwen2.5, 2026-10-22).
    (rule("modsecurity", 'SecRule ARGS_GET:id "@contains %3B%20DROP" "id:99007,phase:1,deny,status:403,log,msg:\'x\'"'),
     "ne correspondrait jamais"),
])
def test_dangerous_or_untargeted_rules_are_rejected(r, reason):
    analysis, rejected = check([r])
    assert not analysis.rules
    assert reason in rejected[0].reason


@pytest.mark.parametrize("content", [
    # Une condition inversée à côté d'une condition positive reste ciblée (validation de format).
    'SecRule REQUEST_FILENAME "@streq /api/payments" "id:99008,phase:1,deny,status:403,log,msg:\'x\',chain"\n'
    '    SecRule ARGS_GET:limit "!@rx ^[0-9]{1,4}$"',
    # %XX sur l'URI brute est légitime : REQUEST_URI n'est pas décodé.
    'SecRule REQUEST_URI "@contains %00" "id:99009,phase:1,deny,status:403,log,msg:\'x\'"',
])
def test_targeted_rules_with_negation_or_raw_encoding_pass(content):
    analysis, rejected = check([rule("modsecurity", content)])
    assert len(analysis.rules) == 1, [r.reason for r in rejected]


def test_rules_only_for_attack_verdict():
    analysis, rejected = check([rule("bunkerweb", "USE_ANTIBOT=javascript")], verdict="faux_positif_probable")
    assert not analysis.rules and "attaque" in rejected[0].reason


def test_collateral_ip_is_protected():
    data = load_cluster("distributed_flood")
    data["top_ips"][1]["assessment"] = "possible_waf_collateral"
    cluster = ClusterSummary.model_validate(data)
    analysis, rejected = check([rule("bunkerweb", f"BLACKLIST_IP={data['top_ips'][1]['ip']}")], cluster=cluster)
    assert not analysis.rules and "collatéral" in rejected[0].reason
    # Un /24 qui engloberait l'IP collatérale est refusé aussi.
    analysis, rejected = check([rule("bunkerweb", "BLACKLIST_IP=10.66.0.0/24")], cluster=cluster)
    assert not analysis.rules


def test_dangerous_advice_is_removed():
    analysis, rejected = check([], actions=["Mettre 10.0.0.66 en liste blanche", "Désactiver le WAF 10 minutes",
                                            "Vérifier les 503 des sondes"])
    assert analysis.operator_actions == ["Vérifier les 503 des sondes"]
    assert len(rejected) == 2


def test_secrule_filed_under_bunkerweb_is_reclassified_then_validated():
    ok = rule("bunkerweb", 'SecRule ARGS_GET:limit "@gt 1000" "id:99010,phase:1,deny,status:403,log,msg:\'export\'"')
    analysis, rejected = check([ok])
    assert analysis.rules[0].engine.value == "modsecurity" and not rejected
    bad = rule("bunkerweb", 'SecRule ARGS "@rx x" "id:99011,phase:1,pass,ctl:ruleEngine=Off"')
    analysis, rejected = check([bad])
    assert not analysis.rules and "ctl" in rejected[0].reason


QWEN_BROKEN = ('SecRule REQUEST_URI "@rx <script>" "id:99010,phase:2,deny,status:403,log,'
               'msg:\'Tentative d\'injection XSS via URI\',chain"\n'
               'SecRule ARGS_GET:q "@rx <script>",id:99011,phase:2,deny,status:403,log,msg:\'XSS\'')


@pytest.mark.parametrize("content, reason", [
    (QWEN_BROKEN, "syntaxe"),           # réellement produit par qwen2.5 : apostrophe corrigée, actions sans guillemets
    ('SecRule ARGS "@rx x" "id:99012,phase:1,deny,msg:\'a\',chain"\nSecRule ARGS:q "@rx y" "id:99013,deny"', "chaînée"),
    ('SecRule ARGS "@rx x" "id:99014,phase:1,deny,chain"', "chain"),            # chaîne sans suite
    ('SecRule ARGS @rx x id:99015,phase:1,deny', "syntaxe"),                   # guillemets manquants
])
def test_malformed_modsecurity_is_rejected(content, reason):
    analysis, rejected = check([rule("modsecurity", content)])
    assert not analysis.rules and reason in rejected[0].reason


@pytest.mark.parametrize("engine, content, expected", [
    ("bunkerweb", "USE_LIMIT_REQ=yes, LIMIT_REQ_URL_2=/api/payments, LIMIT_REQ_RATE_2=2r/s", 3),
    ("bunkerweb", "USE_LIMIT_REQ=yes / LIMIT_REQ_URL_2=/api/payments / LIMIT_REQ_RATE_2=2r/s", 3),
    ("bunkerweb", "USE_LIMIT_REQ=yes\nLIMIT_REQ_URL_2=/api/payments\nLIMIT_REQ_RATE_2=2r/s", 3),
    ("modsecurity", 'SecRule REQUEST_FILENAME "@streq /api/payments" "id:99001,phase:1,deny,log,msg:\'export\',chain" '
                    '/ SecRule ARGS_GET:limit "@gt 1000"', 2),
])
def test_separators_are_normalized_to_one_directive_per_line(engine, content, expected):
    analysis, rejected = check([rule(engine, content)])
    assert not rejected and len(analysis.rules[0].content.splitlines()) == expected


def test_french_apostrophe_in_msg_is_fixed_then_validated():
    content = ('SecRule ARGS_GET:q "@rx <script>" "id:99020,phase:1,deny,status:403,log,'
               'msg:\'Tentative d\'injection XSS\',chain"\nSecRule REQUEST_FILENAME "@streq /"')
    analysis, rejected = check([rule("modsecurity", content)])
    assert not rejected and "Tentative d’injection XSS" in analysis.rules[0].content


def test_global_measure_refused_when_waf_already_blocks_everything():
    xss = ClusterSummary.model_validate(load_cluster("xss"))            # 100 % bloqué par le WAF
    analysis, rejected = check([rule("bunkerweb", "USE_ANTIBOT=javascript")], cluster=xss)
    assert not analysis.rules and "disproportionnée" in rejected[0].reason
    ip = xss.top_ips[0].ip                                               # cibler l'IP reste possible
    analysis, rejected = check([rule("bunkerweb", f"BLACKLIST_IP={ip}")], cluster=xss)
    assert analysis.rules and not rejected


def test_toggle_alone_adds_nothing():
    analysis, rejected = check([rule("bunkerweb", "USE_LIMIT_REQ=yes")])
    assert not analysis.rules and "déjà en place" in rejected[0].reason


@pytest.mark.parametrize("content, reason", [
    # Les deux règles ci-dessous ont réellement passé l'ancienne validation (qwen2.5, cas injection).
    ('SecRule REQUEST_FILENAME "@streq /api/payments" "id:99006,phase:1,deny,status:403,log,msg:\'XSS\'"', "TOUT le trafic"),
    ('SecRule ARGS_GET:q "@rx (?i)<script)" "id:99005,phase:1,deny,status:403,log,msg:\'XSS\'"', "expression régulière"),
    ('SecRule REQUEST_METHOD "@streq GET" "id:99007,phase:1,deny,log,msg:\'x\',chain"\n'
     'SecRule REQUEST_FILENAME "@beginsWith /api"', "TOUT le trafic"),
])
def test_endpoint_wide_or_unloadable_rules_are_rejected(content, reason):
    analysis, rejected = check([rule("modsecurity", content)])
    assert not analysis.rules and reason in rejected[0].reason


# -- failles trouvées le 2026-10-21 en cherchant à contourner les garde-fous ---------------------
@pytest.mark.parametrize("content, reason", [
    ("USE_BLACKLIST=yes\nBLACKLIST_IP=2001:db8::/32", "trop large"),                 # IPv6 non contrôlée
    ("USE_BLACKLIST=yes\nBLACKLIST_IP=2001:db8::66", "aucune IP"),                   # IPv6 hors du cluster
    ("USE_BLACKLIST=yes\nBLACKLIST_USER_AGENT=Mozilla", "clients légitimes"),        # tous les navigateurs
    ("USE_BLACKLIST=yes\nBLACKLIST_USER_AGENT=python-requests", "clients légitimes"),  # l'intégration marchand
    ("USE_BLACKLIST=yes\nBLACKLIST_URI=/api", "endpoints légitimes"),                # toute l'API
    ("USE_LIMIT_REQ=yes\nLIMIT_REQ_URL_3=/\nLIMIT_REQ_RATE_3=1r/m", "trop bas"),     # déni de service auto-infligé
    ("USE_LIMIT_REQ=yes\nLIMIT_REQ_URL_3=/api/payments\nLIMIT_REQ_RATE_3=10r/m", "trop bas"),
])
def test_bypasses_found_by_review_are_rejected(content, reason):
    analysis, rejected = check([rule("bunkerweb", content)])
    assert not analysis.rules and reason in rejected[0].reason


def test_ipv6_in_modsecurity_is_checked_too():
    content = 'SecRule REMOTE_ADDR "@ipMatch 2001:db8::/16" "id:99030,phase:1,deny,status:403,log,msg:\'v6\'"'
    analysis, rejected = check([rule("modsecurity", content)])
    assert not analysis.rules and "trop large" in rejected[0].reason


@pytest.mark.parametrize("content", [
    "USE_BLACKLIST=yes\nBLACKLIST_USER_AGENT=resilience-labtest",                    # l'outil de l'attaque
    "USE_BLACKLIST=yes\nBLACKLIST_URI=/wp-admin",                                    # chemin de scan
    "USE_LIMIT_REQ=yes\nLIMIT_REQ_URL_2=/api/payments\nLIMIT_REQ_RATE_2=2r/s",
    'SecRule REQUEST_HEADERS:User-Agent "@rx resilience-labtest" "id:99031,phase:1,deny,status:403,log,msg:\'outil\'"',
])
def test_targeted_measures_still_pass(content):
    engine = "modsecurity" if content.startswith("SecRule") else "bunkerweb"
    analysis, rejected = check([rule(engine, content)])
    assert analysis.rules and not rejected


# -- trous révélés par le test de mutation (2026-10-21) : limites exactes et cas jamais exercés ---
def _with_collateral():
    data = load_cluster("distributed_flood")
    data["top_ips"][1]["assessment"] = "possible_waf_collateral"
    return ClusterSummary.model_validate(data)


@pytest.mark.parametrize("network, ok", [("10.66.0.0/24", True), ("10.66.0.0/23", False)])
def test_ipv4_prefix_limit_is_exactly_24(network, ok):
    data = load_cluster("distributed_flood")
    data["top_ips"][0]["ip"] = "10.66.0.59"
    analysis, _ = check([rule("bunkerweb", f"BLACKLIST_IP={network}")], cluster=ClusterSummary.model_validate(data))
    assert bool(analysis.rules) is ok


@pytest.mark.parametrize("network, ok", [("2001:db8:0:1::/64", True), ("2001:db8::/63", False)])
def test_ipv6_prefix_limit_is_exactly_64(network, ok):
    data = load_cluster("distributed_flood")
    data["top_ips"][0]["ip"] = "2001:db8:0:1::66"
    analysis, _ = check([rule("bunkerweb", f"BLACKLIST_IP={network}")], cluster=ClusterSummary.model_validate(data))
    assert bool(analysis.rules) is ok


@pytest.mark.parametrize("blocked, ok", [(0.94, True), (0.95, False)])
def test_global_measure_threshold_is_exactly_95_percent(blocked, ok):
    data = load_cluster("distributed_flood")
    data["blocked_ratio"] = blocked
    analysis, _ = check([rule("bunkerweb", "USE_ANTIBOT=javascript")], cluster=ClusterSummary.model_validate(data))
    assert bool(analysis.rules) is ok


@pytest.mark.parametrize("url, rate, ok", [("/", "5r/s", True), ("/", "4r/s", False),
                                           ("/api/payments", "1r/s", True), ("/api/payments", "59r/m", False)])
def test_rate_floors_are_exact(url, rate, ok):
    analysis, _ = check([rule("bunkerweb", f"USE_LIMIT_REQ=yes\nLIMIT_REQ_URL_4={url}\nLIMIT_REQ_RATE_4={rate}")])
    assert bool(analysis.rules) is ok


def test_attacker_can_still_be_targeted_when_cluster_has_a_collateral_ip():
    cluster = _with_collateral()
    analysis, rejected = check([rule("bunkerweb", f"BLACKLIST_IP={cluster.top_ips[0].ip}")], cluster=cluster)
    assert analysis.rules and not rejected


@pytest.mark.parametrize("engine, content, reason", [
    ("bunkerweb", "set USE_ANTIBOT javascript", "non conforme"),                   # plantait sans ce contrôle
    ("bunkerweb", "BLACKLIST_IP=999.1.1.1", "invalide"),
    ("bunkerweb", "BLACKLIST_USER_AGENT=sqlmap(", "invalide"),
    ("modsecurity", 'SecRule ARGS "@rx x" "id:99040,deny,log"', "phase"),          # sans phase
    ("modsecurity", 'SecRule ARGS "@rx x" "id:99041,phase:1,log"', "action"),      # sans action
    ("modsecurity", 'SecRule ARGS "@rx x" "id:99042,phase:1,deny,tag:\'abc"', "apostrophe"),
    ("modsecurity", "# seulement un commentaire", "aucune directive"),
])
def test_cases_never_exercised_before(engine, content, reason):
    analysis, rejected = check([rule(engine, content)])
    assert not analysis.rules and reason in rejected[0].reason


@pytest.mark.parametrize("engine, content", [                                   # commentaires : produits par qwen
    ("bunkerweb", "# Limiter l'export\nUSE_LIMIT_REQ=yes\nLIMIT_REQ_URL_2=/api/payments\nLIMIT_REQ_RATE_2=2r/s"),
    ("modsecurity", "# Plafonner les exports\n" + 'SecRule ARGS_GET:limit "@gt 1000" "id:99043,phase:1,deny,log,msg:\'x\'"'),
    ("modsecurity", 'SecRule ARGS_GET:q "@rx a,b" "id:99044,phase:1,deny,log,msg:\'a, b et c\'"'),  # virgule dans msg
])
def test_comment_lines_and_commas_in_quotes_are_accepted(engine, content):
    analysis, rejected = check([rule(engine, content)])
    assert analysis.rules and not rejected


def test_normalization_keeps_a_slash_value():
    """Bug trouvé par le test de mutation : « LIMIT_REQ_URL=/ » perdait son « / » (règle cassée,
    plancher de débit contourné)."""
    analysis, _ = check([rule("bunkerweb", "USE_LIMIT_REQ=yes\nLIMIT_REQ_URL_4=/\nLIMIT_REQ_RATE_4=5r/s")])
    assert "LIMIT_REQ_URL_4=/\n" in analysis.rules[0].content


@pytest.mark.parametrize("content, reason", [
    ("# seulement un commentaire", "aucun réglage"),                                # survivant du test de mutation
    ("# activer la limitation\nUSE_LIMIT_REQ=yes", "déjà en place"),                # idem : le commentaire ne compte pas
])
def test_comments_do_not_turn_an_empty_or_useless_rule_into_a_valid_one(content, reason):
    analysis, rejected = check([rule("bunkerweb", content)])
    assert not analysis.rules and reason in rejected[0].reason
