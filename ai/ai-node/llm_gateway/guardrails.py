"""Revalidation déterministe de la sortie du LLM avant toute exposition à l'opérateur.

La réponse du LLM est NON FIABLE : elle dépend de données contrôlées par l'attaquant (URI,
user-agents) et une injection de prompt peut lui faire proposer « mettre 10.0.0.66 en liste
blanche » ou « désactiver ModSecurity ». Aucune règle n'est appliquée automatiquement, mais un
opérateur pressé copie-colle : seules passent les règles qui RESSERRENT la protection, sur des
cibles présentes dans le cluster. Ce module ne s'appuie sur aucun jugement du LLM.
"""
from __future__ import annotations

import ipaddress
import re

from .config import GatewayConfig
from .contract import ClusterSummary, Engine, LlmAnalysis, ProposedRule, RejectedRule, Verdict

# Directives et actions qui désactivent, contournent ou affaiblissent le WAF, ou exécutent du code.
_MODSEC_FORBIDDEN = [
    (re.compile(p, re.IGNORECASE), why) for p, why in [
        (r"SecRuleEngine", "modifie l'état du moteur ModSecurity"),
        (r"\bctl\s*:", "action ctl: (peut couper le moteur ou retirer des règles)"),
        (r"SecRule(Remove|Update)", "retire ou modifie des règles existantes (CRS)"),
        (r"SecAction\b|SecDefaultAction|SecMarker", "directive globale, pas une règle ciblée"),
        (r"SecRuleScript|\bexec\s*:", "exécution de script"),
        (r"\bInclude\b|SecRemoteRules", "chargement de fichiers ou de règles distantes"),
        (r"Sec(Audit|Debug)\w*|Sec(Request|Response)BodyAccess", "modifie la journalisation ou l'inspection"),
        (r"\ballow\b", "action allow (laisse passer sans inspection)"),
        (r"\bnolog\b", "masque les déclenchements dans les journaux"),
    ]
]
_MODSEC_ID = re.compile(r"\bid\s*:\s*'?(\d+)'?")
_SECRULE = re.compile(r'^SecRule\s+(?P<vars>\S+)\s+"(?P<op>(?:[^"\\]|\\.)*)"(?:\s+"(?P<act>(?:[^"\\]|\\.)*)")?\s*$')
_DISRUPTIVE = {"deny", "drop", "block", "pass"}
# Variables qui ne décrivent que l'emplacement : une règle qui ne teste qu'elles vise tout un endpoint.
_LOCATION_VARIABLES = {"REQUEST_FILENAME", "REQUEST_BASENAME", "REQUEST_METHOD", "REQUEST_PROTOCOL",
                       "SERVER_NAME", "SERVER_PORT", "REQUEST_LINE"}
# Valeurs de paramètres que ModSecurity compare DÉCODÉES : une valeur écrite en %XX n'y correspond jamais.
_DECODED_VARIABLES = {"ARGS", "ARGS_GET", "ARGS_POST", "ARGS_NAMES", "ARGS_GET_NAMES", "ARGS_POST_NAMES"}
_PERCENT_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")
# Valeur de msg/logdata : jusqu'à l'apostrophe suivie d'une autre action, ou de la fin des actions.
_MSG_VALUE = re.compile(r"\b(msg|logdata):'(.*?)'(?=\s*(?:,\s*[A-Za-z]+\b|\"))")
_CHAINED_ALLOWED = {"chain", "t", "capture"}

# Réglages BunkerWeb autorisés (préfixe avant un éventuel suffixe _1, _2...). Tous resserrent.
_BW_ALLOWED = {
    "USE_ANTIBOT", "ANTIBOT_URI", "ANTIBOT_TIME_RESOLVE", "ANTIBOT_TIME_VALID",
    "USE_LIMIT_REQ", "LIMIT_REQ_URL", "LIMIT_REQ_RATE",
    "USE_LIMIT_CONN", "LIMIT_CONN_MAX_HTTP1", "LIMIT_CONN_MAX_HTTP2",
    "USE_BAD_BEHAVIOR", "BAD_BEHAVIOR_STATUS_CODES", "BAD_BEHAVIOR_THRESHOLD",
    "BAD_BEHAVIOR_COUNT_TIME", "BAD_BEHAVIOR_BAN_TIME",
    "USE_BLACKLIST", "BLACKLIST_IP", "BLACKLIST_USER_AGENT", "BLACKLIST_URI",
    "USE_DNSBL",
}
# Interrupteurs déjà actifs sur la plateforme (knowledge/plateforme.md) : seuls, ils ne changent rien.
_BW_TOGGLES_ALREADY_ON = {"USE_LIMIT_REQ", "USE_BAD_BEHAVIOR", "USE_BLACKLIST", "USE_LIMIT_CONN", "USE_DNSBL"}
# Mesures qui s'appliquent à tous les clients d'une URL ou du service, pas aux seules IP de la campagne.
_BW_GLOBAL_MEASURES = {"USE_ANTIBOT", "ANTIBOT_URI", "LIMIT_REQ_URL", "LIMIT_REQ_RATE", "LIMIT_CONN_MAX_HTTP1",
                       "LIMIT_CONN_MAX_HTTP2", "BAD_BEHAVIOR_THRESHOLD", "BAD_BEHAVIOR_COUNT_TIME"}
_WAF_HANDLES_IT = 0.95          # part déjà bloquée par le WAF au-delà de laquelle il « fait le travail »
_BW_ANTIBOT_MODES = {"cookie", "javascript", "captcha", "recaptcha", "hcaptcha", "turnstile", "mcaptcha"}
_BW_LINE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")
_BW_RATE = re.compile(r"^(\d+)r/([sm])$")
# Débit minimal d'une limitation (par IP) : un NAT d'entreprise fait jusqu'à ~1 req/s au total.
_MIN_RATE_PER_S = {"/": 5.0}     # « / » = toutes les URL du service
_MIN_RATE_PER_S_DEFAULT = 1.0

# Clients et endpoints légitimes connus (knowledge/plateforme.md) : une liste de blocage qui les
# toucherait (BLACKLIST_USER_AGENT=Mozilla, BLACKLIST_URI=/api) bloquerait les vrais clients.
_LEGIT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
    "python-requests/2.31.0", "axios/1.7.7",                       # intégration marchand
    "resilience-txprobe/1.0", "resilience-blackbox/1.0", "Blackbox Exporter/0.27.0",
    "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
]
_LEGIT_PATHS = ["/", "/api/payments", "/api/payments/0b6a6b0e-6f2c-4c5e-9a43-2d1f8c3b9e10",
                "/api/auth/login", "/api/payments/ready", "/api/auth/ready"]

_IPV4_OR_CIDR = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?(?![\d.])")
# Candidat IPv6 : validé ensuite par ipaddress (« 14:05:00 » d'un horodatage ne l'est pas).
_IPV6_OR_CIDR = re.compile(r"(?<![0-9A-Fa-f:])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?:/(\d{1,3}))?(?![0-9A-Fa-f:])")
_MIN_PREFIX = {4: 24, 6: 64}     # pas plus large qu'un /24 (IPv4) ou un /64 (un abonné IPv6)

# Conseils en texte libre : mêmes interdits (un « conseil » de liste blanche reste dangereux).
_ADVICE_FORBIDDEN = re.compile(
    r"whitelist|liste\s+blanche|allowlist|WHITELIST_|SecRuleEngine|ctl\s*:|"
    r"d[ée]sactiv\w*\s+(le\s+|la\s+|les\s+)?(waf|modsecurity|crs|bunkerweb|r[èe]gles?|protection)",
    re.IGNORECASE,
)


def validate(analysis: LlmAnalysis, cluster: ClusterSummary, config: GatewayConfig
             ) -> tuple[LlmAnalysis, list[RejectedRule]]:
    """Renvoie l'analyse avec seulement les règles et conseils acceptables, et les refus motivés."""
    rejected: list[RejectedRule] = []
    accepted: list[ProposedRule] = []
    for rule in analysis.rules:
        # Les petits modèles rangent parfois une SecRule dans « bunkerweb » : on la reclasse,
        # puis elle passe la validation ModSecurity comme les autres (aucun contrôle sauté).
        if rule.engine == Engine.BUNKERWEB and rule.content.lstrip().startswith("SecRule"):
            rule = rule.model_copy(update={"engine": Engine.MODSECURITY})
        rule = rule.model_copy(update={"content": _one_directive_per_line(rule)})
        reason = _rule_problem(rule, analysis.verdict, cluster, config)
        if reason:
            rejected.append(RejectedRule(engine=rule.engine.value, reason=reason))
        else:
            accepted.append(rule)

    actions = []
    for advice in analysis.operator_actions:
        if _ADVICE_FORBIDDEN.search(advice):
            rejected.append(RejectedRule(engine="conseil", reason="conseil retiré : liste blanche ou désactivation de protection"))
        else:
            actions.append(advice)
    ideas = []
    for idea in analysis.ideas_to_review:
        if _ADVICE_FORBIDDEN.search(idea):
            rejected.append(RejectedRule(engine="piste", reason="piste retirée : liste blanche ou désactivation de protection"))
        else:
            ideas.append(idea)
    return analysis.model_copy(update={"rules": accepted, "operator_actions": actions, "ideas_to_review": ideas}), rejected


def _rule_problem(rule: ProposedRule, verdict: Verdict, cluster: ClusterSummary, config: GatewayConfig) -> str | None:
    if verdict != Verdict.ATTACK:
        return f"règle proposée alors que le verdict est « {verdict.value} » (règles réservées aux attaques)"
    if "```" in rule.content or not rule.content.strip():
        return "contenu vide ou contenant un bloc de code Markdown"
    # La nature de la directive d'abord : le motif le plus grave est celui qu'on affiche.
    if rule.engine == Engine.MODSECURITY:
        problem = _modsecurity_problem(rule.content, config)
    else:
        problem = (_bunkerweb_problem(rule.content) or _bunkerweb_collateral_problem(rule.content)
                   or _bunkerweb_proportion_problem(rule.content, cluster))
    return problem or _ip_problem(rule.content, cluster)


def _ip_problem(content: str, cluster: ClusterSummary) -> str | None:
    """Toute IP visée doit appartenir au cluster et ne pas être marquée « collatéral »."""
    attackers = [_address(e.ip) for e in cluster.top_ips if not e.assessment]
    protected = [_address(e.ip) for e in cluster.top_ips if e.assessment]
    for text, net in _networks(content):
        if net is None:
            return f"adresse invalide : {text}"
        if net.prefixlen < _MIN_PREFIX[net.version]:
            return f"blocage trop large ({net}) : pas au-delà d'un /{_MIN_PREFIX[net.version]}"
        if any(a is not None and a.version == net.version and a in net for a in protected):
            return f"{net} couvre une IP marquée « bannissement collatéral possible »"
        if not any(a is not None and a.version == net.version and a in net for a in attackers):
            return f"{net} ne correspond à aucune IP au comportement d'attaque dans le cluster"
    return None


def _address(ip: str):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def _networks(content: str):
    """(texte, réseau) pour chaque IPv4/IPv6 citée ; réseau None si une IPv4 est invalide."""
    for match in _IPV4_OR_CIDR.finditer(content):
        try:
            yield match.group(0), ipaddress.ip_network(f"{match.group(1)}/{match.group(2) or 32}", strict=False)
        except ValueError:
            yield match.group(0), None
    for match in _IPV6_OR_CIDR.finditer(content):
        try:
            yield match.group(0), ipaddress.ip_network(f"{match.group(1)}/{match.group(2) or 128}", strict=False)
        except ValueError:
            continue                                     # pas une IPv6 (horodatage, id...)


def _modsecurity_problem(content: str, config: GatewayConfig) -> str | None:
    for pattern, why in _MODSEC_FORBIDDEN:
        if pattern.search(content):
            return f"ModSecurity : {why}"
    directives = [line.strip() for line in content.replace("\\\n", " ").splitlines()
                  if line.strip() and not line.strip().startswith("#")]
    if not directives:
        return "ModSecurity : aucune directive"
    other = next((d for d in directives if not d.startswith("SecRule ")), None)
    if other:
        return f"ModSecurity : seules des directives SecRule sont acceptées ({other[:60]})"
    problem = _secrule_syntax_problem(directives) or _secrule_scope_problem(directives)
    if problem:
        return f"ModSecurity : {problem}"
    ids = [int(i) for i in _MODSEC_ID.findall(content)]
    if not ids:
        return "ModSecurity : identifiant (id:) manquant"
    out = [i for i in ids if not config.rule_id_min <= i <= config.rule_id_max]
    if out:
        return f"ModSecurity : id {out} hors de la plage réservée {config.rule_id_min}-{config.rule_id_max}"
    return None


def _one_directive_per_line(rule: ProposedRule) -> str:
    r"""Remet une directive par ligne quand le modèle les a séparées par « \n » littéral, « / »,
    « , » ou « ; ». Ne coupe que devant un début de directive (RÉGLAGE= ou SecRule)."""
    text = rule.content.replace("\\n", "\n")
    if rule.engine == Engine.BUNKERWEB:
        # « / » ne sépare que s'il est précédé d'un espace : collé, c'est une valeur (LIMIT_REQ_URL=/).
        text = re.sub(r"\s*(?:[,;]|\s/)\s*(?=[A-Z][A-Z0-9_]*=)", "\n", text)
    else:
        text = re.sub(r"\s+/\s+(?=SecRule\b)", "\n", text)
        # Le français met des apostrophes dans msg:'Tentative d'injection', ce qui casse la
        # syntaxe : dans msg/logdata, elles deviennent typographiques (’). La règle est ensuite
        # revalidée comme les autres.
        text = _MSG_VALUE.sub(lambda m: f"{m.group(1)}:'{m.group(2).replace(chr(39), '’')}'", text)
    return text.strip()


def _secrule_syntax_problem(directives: list[str]) -> str | None:
    """Syntaxe vérifiée avant copie : une règle mal formée empêche BunkerWeb de recharger sa config.

    - SecRule VARIABLES "OPÉRATEUR" "ACTIONS" (guillemets doubles, apostrophes équilibrées) ;
    - la première règle porte id, phase et une action (deny/drop/block/pass) ;
    - dans une chaîne, les suivantes n'ont que chain et des transformations (t:...) ;
    - chaque règle sauf la dernière porte « chain ».
    """
    last = len(directives) - 1
    for i, directive in enumerate(directives):
        match = _SECRULE.match(directive)
        if not match:
            return f'syntaxe attendue : SecRule VARIABLES "OPÉRATEUR" "ACTIONS" ({directive[:60]})'
        operator = match.group("op").lstrip("!")
        if operator.startswith("@rx "):
            try:
                re.compile(operator[4:])
            except re.error as exc:
                return f"expression régulière invalide ({exc}) : ModSecurity refuserait de charger la configuration"
        if operator.startswith("@ipMatch "):
            for entry in operator[len("@ipMatch "):].split(","):
                try:
                    ipaddress.ip_network(entry.strip(), strict=False)
                except ValueError:
                    return (f"liste d'IP invalide pour @ipMatch ({entry.strip()[:40]}) : ModSecurity refuserait "
                            f"de charger la configuration")
        actions_text = match.group("act") or ""
        if len(re.findall(r"(?<!\\)'", actions_text)) % 2:
            return "apostrophe non échappée dans les actions (ex. msg:'Tentative d'injection')"
        names = {a.split(":", 1)[0].strip() for a in _split_actions(actions_text) if a.strip()}
        if i == 0:
            if not {"id", "phase"} <= names or not names & _DISRUPTIVE:
                return "la première règle doit porter id, phase et une action (deny, drop, block ou pass)"
        elif names - _CHAINED_ALLOWED:
            return f"règle chaînée avec des actions interdites dans une chaîne ({', '.join(sorted(names - _CHAINED_ALLOWED))})"
        if (i < last) != ("chain" in names):
            return "« chain » doit relier chaque règle à la suivante (et pas la dernière)"
    return None


def _secrule_scope_problem(directives: list[str]) -> str | None:
    """Portée d'une règle syntaxiquement valide : ce qu'elle bloquerait vraiment.

    - seulement le chemin ou la méthode : tout le trafic de l'endpoint ;
    - seulement des conditions inversées (« ne contient pas », « ne correspond pas ») : presque
      tout le trafic du site, puisque n'importe quelle requête ordinaire les remplit ;
    - valeur en %XX sur un paramètre : ModSecurity compare les paramètres DÉCODÉS, la règle ne
      correspondrait jamais (fausse impression de protection).
    """
    location_only, all_negated = True, True
    for directive in directives:
        match = _SECRULE.match(directive)
        variables = {v.lstrip("&!").split(":", 1)[0] for v in match.group("vars").split("|")}
        location_only &= variables <= _LOCATION_VARIABLES
        operator = match.group("op")
        all_negated &= operator.startswith("!")
        if variables & _DECODED_VARIABLES and _PERCENT_ENCODED.search(operator):
            return (f"valeur encodée ({_PERCENT_ENCODED.search(operator).group()}...) comparée à un paramètre que "
                    "ModSecurity a déjà décodé : la règle ne correspondrait jamais (écrire « ; » et non « %3B »)")
    if location_only:
        return ("ne filtre que sur le chemin ou la méthode : bloquerait TOUT le trafic de l'endpoint "
                "(ajouter une condition sur un paramètre, un en-tête ou une IP)")
    if all_negated:
        return ("toutes les conditions sont inversées : la règle correspondrait à presque TOUT le trafic "
                "(ajouter au moins une condition positive : chemin, paramètre, en-tête ou IP)")
    return None


def _split_actions(text: str) -> list[str]:
    """Découpe « id:1,msg:'a, b',deny » sur les virgules hors apostrophes."""
    parts, current, quoted = [], "", False
    for char in text:
        if char == "'":
            quoted = not quoted
        if char == "," and not quoted:
            parts.append(current)
            current = ""
        else:
            current += char
    return parts + [current]


def _bunkerweb_collateral_problem(content: str) -> str | None:
    """Listes de blocage ou limitations qui frapperaient les clients légitimes eux-mêmes."""
    settings = {}
    for line in content.splitlines():
        match = _BW_LINE.match(line.strip())
        if match:
            settings[match.group(1)] = match.group(2).strip()
    for key, value in settings.items():
        base = re.sub(r"_\d+$", "", key)
        if base in ("BLACKLIST_USER_AGENT", "BLACKLIST_URI"):
            samples, kind = ((_LEGIT_USER_AGENTS, "clients légitimes") if base == "BLACKLIST_USER_AGENT"
                             else (_LEGIT_PATHS, "endpoints légitimes"))
            for entry in value.split():
                try:
                    pattern = re.compile(entry, re.IGNORECASE)
                except re.error:
                    return f"BunkerWeb : {key} contient une expression invalide ({entry[:40]})"
                hit = next((s for s in samples if pattern.search(s)), None)
                if hit:
                    return f"BunkerWeb : {key} avec la valeur « {entry[:40]} » bloquerait des {kind} (ex. {hit[:50]})"
        if base == "LIMIT_REQ_RATE":
            match = _BW_RATE.match(value)
            if not match:
                continue                                    # format déjà contrôlé par _bunkerweb_problem
            per_s = int(match.group(1)) / (1 if match.group(2) == "s" else 60)
            url = settings.get(key.replace("LIMIT_REQ_RATE", "LIMIT_REQ_URL"), "/")
            floor = _MIN_RATE_PER_S.get(url, _MIN_RATE_PER_S_DEFAULT)
            if per_s < floor:
                return (f"BunkerWeb : débit {value} sur {url} trop bas (minimum {floor:g} req/s par IP : "
                        f"un NAT d'entreprise serait bloqué)")
    return None


def _bunkerweb_proportion_problem(content: str, cluster: ClusterSummary) -> str | None:
    """Mesures qui n'apportent rien, ou qui touchent tous les clients alors que le WAF suffit."""
    keys = {re.sub(r"_\d+$", "", line.split("=", 1)[0].strip())
            for line in content.splitlines() if "=" in line and not line.strip().startswith("#")}
    if keys and keys <= _BW_TOGGLES_ALREADY_ON:
        return "BunkerWeb : n'active qu'une protection déjà en place, sans réglage concret (URL, débit, IP...)"
    if cluster.blocked_ratio >= _WAF_HANDLES_IT and keys & _BW_GLOBAL_MEASURES:
        return (f"BunkerWeb : le WAF bloque déjà {cluster.blocked_ratio:.0%} de ce groupe ; une mesure qui touche "
                f"tous les clients ({', '.join(sorted(keys & _BW_GLOBAL_MEASURES))}) serait disproportionnée")
    return None


def _bunkerweb_problem(content: str) -> str | None:
    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")]
    if not lines:
        return "BunkerWeb : aucun réglage"
    for line in lines:
        match = _BW_LINE.match(line)
        if not match:
            return f"BunkerWeb : ligne non conforme à RÉGLAGE=valeur ({line[:60]})"
        key, value = match.group(1), match.group(2).strip()
        base = re.sub(r"_\d+$", "", key)
        if base.startswith("WHITELIST") or "WHITELIST" in base:
            return f"BunkerWeb : liste blanche interdite ({key})"
        if base not in _BW_ALLOWED:
            return f"BunkerWeb : réglage {key} hors de la liste autorisée"
        if base == "USE_ANTIBOT" and value not in _BW_ANTIBOT_MODES:
            return f"BunkerWeb : USE_ANTIBOT={value} (doit activer un mode de défi)"
        if base.startswith("USE_") and base != "USE_ANTIBOT" and value != "yes":
            return f"BunkerWeb : {key} doit valoir yes (reçu : {value[:40]})"
        if base == "LIMIT_REQ_RATE" and not _BW_RATE.match(value):
            return f"BunkerWeb : débit {value} invalide (format attendu : 10r/s ou 30r/m)"
    return None
