"""Grammaire de règles : le LLM DÉCRIT une règle (conditions, opérateurs, valeurs, action), le
gateway écrit la syntaxe exacte.

Pourquoi : un modèle de 7B pose de bons diagnostics mais rédige mal la syntaxe ModSecurity
(apostrophes, guillemets, chaînes, regex : mesuré le 2026-10-20). La flexibilité reste dans le
raisonnement et la composition des conditions ; la syntaxe est garantie ici. Les règles compilées
passent ENSUITE par tous les garde-fous (guardrails.py), comme une règle écrite à la main.

Ce qui ne s'exprime pas dans cette grammaire va dans `ideas_to_review` (« Pistes à expertiser » :
texte non copiable, à formuler par un humain).
"""
from __future__ import annotations

import ipaddress
import re
import threading
import unicodedata
from pathlib import Path

from .config import GatewayConfig
from .contract import (BunkerWebChangeSpec, Condition, Engine, LlmAnalysis, LlmOutput, ModSecOperator,
                       ModSecRuleSpec, ModSecVariable, ProposedRule, RejectedRule)

_OPERATORS = {
    ModSecOperator.EQUALS: "@streq", ModSecOperator.BEGINS_WITH: "@beginsWith", ModSecOperator.ENDS_WITH: "@endsWith",
    ModSecOperator.CONTAINS: "@contains", ModSecOperator.REGEX: "@rx", ModSecOperator.GREATER_THAN: "@gt",
    ModSecOperator.LESS_THAN: "@lt", ModSecOperator.IP_IN: "@ipMatch",
}
# Collections qui acceptent un nom (ARGS_GET:limit, REQUEST_HEADERS:Referer) ; sans nom : toutes.
_NAMED_COLLECTIONS = {ModSecVariable.ARGS_GET, ModSecVariable.ARGS, ModSecVariable.REQUEST_HEADERS}
_BODY_VARIABLES = {ModSecVariable.ARGS, ModSecVariable.ARGS_NAMES}      # lues en phase 2 (corps)
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class CompileError(ValueError):
    """Description de règle incohérente (paramètre manquant, valeur invalide...)."""


class RuleIdAllocator:
    """Identifiants ModSecurity uniques dans la plage réservée à l'IA, conservés entre redémarrages
    (fichier compteur à côté des rapports) : deux rapports ne proposent jamais le même id."""

    def __init__(self, first: int, last: int, state_file: Path | None = None):
        self.first, self.last, self.state_file = first, last, state_file
        self._lock = threading.Lock()
        self._next = first
        if state_file and state_file.exists():
            try:
                self._next = int(state_file.read_text().strip())
            except ValueError:
                pass

    def allocate(self) -> int:
        with self._lock:
            value = self._next if self.first <= self._next <= self.last else self.first
            self._next = value + 1 if value < self.last else self.first
            if self.state_file:
                self.state_file.parent.mkdir(parents=True, exist_ok=True)
                self.state_file.write_text(str(self._next))
            return value


def compile_output(output: LlmOutput, ids: RuleIdAllocator) -> tuple[LlmAnalysis, list[RejectedRule]]:
    """Sortie du LLM -> analyse avec règles compilées ; une description incohérente est refusée."""
    rules: list[ProposedRule] = []
    rejected: list[RejectedRule] = []
    for spec in output.modsecurity_rules:
        try:
            rules.append(ProposedRule(engine=Engine.MODSECURITY, content=compile_modsecurity(spec, ids.allocate()),
                                      explanation=spec.explanation, side_effects=spec.side_effects))
        except CompileError as exc:
            rejected.append(RejectedRule(engine="modsecurity", reason=f"description incohérente : {exc}"))
    for change in output.bunkerweb_changes:
        try:
            rules.append(ProposedRule(engine=Engine.BUNKERWEB, content=compile_bunkerweb(change),
                                      explanation=change.explanation, side_effects=change.side_effects))
        except CompileError as exc:
            rejected.append(RejectedRule(engine="bunkerweb", reason=f"description incohérente : {exc}"))
    unique: list[ProposedRule] = []
    for rule in rules:                           # le modèle répète parfois une règle (id mis à part)
        if any(_same_rule(rule, kept) for kept in unique):
            rejected.append(RejectedRule(engine=rule.engine.value, reason="doublon d'une règle déjà proposée"))
        else:
            unique.append(rule)
    analysis = LlmAnalysis(**output.model_dump(exclude={"modsecurity_rules", "bunkerweb_changes"}), rules=unique)
    return analysis, rejected


def normalized(rule: ProposedRule) -> str:
    """Contenu comparable d'une règle : sans identifiant, sans message, espaces réduits."""
    text = re.sub(r"id:\d+,", "", re.sub(r"msg:'[^']*'", "", rule.content))
    return f"{rule.engine.value}:{' '.join(text.split())}"


def _same_rule(a: ProposedRule, b: ProposedRule) -> bool:
    return normalized(a) == normalized(b)


def compile_modsecurity(spec: ModSecRuleSpec, rule_id: int) -> str:
    targets = [_condition(c) for c in spec.conditions]
    phase = 2 if any(c.variable in _BODY_VARIABLES for c in spec.conditions) else 1
    disruptive = "deny,status:403" if spec.action == "deny" else "pass"
    message = _quote_free(spec.message) or "Règle proposée par l’IA"     # apostrophe typographique
    chained = len(targets) > 1
    lines = []
    for i, (variable, operator) in enumerate(targets):
        if i == 0:
            actions = f"id:{rule_id},phase:{phase},{disruptive},log,msg:'{message}'" + (",chain" if chained else "")
        else:
            actions = "chain" if i < len(targets) - 1 else ""
        indent = "    " * min(i, 1)
        lines.append(f'{indent}SecRule {variable} "{operator}"' + (f' "{actions}"' if actions else ""))
    return "\n".join(lines)


def _condition(c: Condition) -> tuple[str, str]:
    # Sans nom, ARGS_GET / ARGS / REQUEST_HEADERS visent TOUS les paramètres ou en-têtes : valide en
    # ModSecurity (l'exiger rejetait à tort 4 règles sur 6 lors du premier essai réel).
    if (c.variable in (ModSecVariable.ARGS_GET, ModSecVariable.ARGS) and not c.name and "=" in c.value
            and c.operator in (ModSecOperator.CONTAINS, ModSecOperator.EQUALS)):
        # Vu en réel : ARGS_GET "@contains limit=10000" ne se déclenche jamais (la VALEUR vaut 10000).
        raise CompileError("la valeur d'un paramètre ne contient pas « nom= » : mettre le nom dans « name » "
                           "(ex. name=limit, greater_than 1000)")
    if c.name and not _NAME.match(c.name):
        raise CompileError(f"nom invalide : {c.name[:40]}")
    target = f"{c.variable.value}:{c.name}" if c.name and c.variable in _NAMED_COLLECTIONS else c.variable.value
    if c.operator == ModSecOperator.ABSENT:
        if c.negate:
            raise CompileError("« absent » ne se combine pas avec la négation")
        return f"&{target}", "@eq 0"
    value = c.value.strip()
    if not value or _has_control(value):
        raise CompileError(f"valeur vide, multiligne ou avec caractère de contrôle pour {target}")
    if value.endswith("\\") or '\\"' in value:
        # Le lecteur de configuration d'Apache/ModSecurity prend « \" » pour un guillemet échappé,
        # même précédé d'un autre « \ » : l'argument ne se refermerait pas.
        raise CompileError(f"barre oblique inverse en fin de valeur ou devant un guillemet pour {target}")
    if c.operator in (ModSecOperator.GREATER_THAN, ModSecOperator.LESS_THAN) and not value.isdigit():
        raise CompileError(f"« {c.operator.value} » demande un nombre entier (reçu : {value[:20]})")
    if c.operator == ModSecOperator.REGEX:
        try:
            re.compile(value)
        except re.error as exc:
            raise CompileError(f"expression régulière invalide ({exc})") from exc
    if c.operator == ModSecOperator.IP_IN:
        # Le modèle écrit parfois une liste « [ip, ip] » ou entre guillemets : @ipMatch ne veut que
        # des IP ou réseaux séparés par des virgules, sinon ModSecurity refuse sa configuration.
        parts = [p.strip(" []'\"") for p in re.split(r"[,\s]+", value) if p.strip(" []'\"")]
        for part in parts:
            try:
                ipaddress.ip_network(part, strict=False)
            except ValueError as exc:
                raise CompileError(f"« {part[:40]} » n'est ni une IP ni un réseau") from exc
        value = ",".join(parts)
    value = value.replace('"', '\\"')
    return target, f"{'!' if c.negate else ''}{_OPERATORS[c.operator]} {value}"


def compile_bunkerweb(change: BunkerWebChangeSpec) -> str:
    lines = []
    for s in change.settings:
        value = s.value.strip()
        if not value or _has_control(value):
            raise CompileError(f"valeur vide, multiligne ou avec caractère de contrôle pour {s.setting.value}")
        if s.setting.value == "LIMIT_REQ_RATE":
            value = _normalize_rate(value)
        if s.setting.value == "USE_ANTIBOT" and value.lower() in ("yes", "on", "true"):
            value = "javascript"          # « activer » : le défi le plus transparent pour un navigateur
        key = f"{s.setting.value}_{s.suffix}" if s.suffix else s.setting.value
        lines.append(f"{key}={value}")
    return "\n".join(lines)


_RATE = re.compile(r"^(\d+)\s*(?:r|req|requ[eê]tes?|requests?)?\s*/\s*(s|sec|seconde|second|m|min|minute)s?$", re.IGNORECASE)


def _normalize_rate(value: str) -> str:
    """« 5/minute », « 10 req/s » -> format BunkerWeb « 5r/m », « 10r/s » ; sinon inchangé (les
    garde-fous refuseront un format inconnu)."""
    match = _RATE.match(value.strip())
    if not match:
        return value
    return f"{match.group(1)}r/{'s' if match.group(2).lower().startswith('s') else 'm'}"


def _has_control(text: str) -> bool:
    r"""Caractères de contrôle et séparateurs de ligne Unicode (\x85,  ...) : ils découpent
    une directive en plusieurs lignes (trouvé par test par propriétés)."""
    return any(unicodedata.category(ch)[0] == "C" or ch in "  " for ch in text)


def _quote_free(text: str) -> str:
    """msg:'...' : ni guillemet, ni apostrophe droite (qui casserait la chaîne), ni barre oblique
    inverse (qui échapperait l'apostrophe fermante), ni caractère de contrôle ; une seule ligne."""
    cleaned = "".join(" " if _has_control(ch) else ch for ch in text)
    return " ".join(cleaned.replace('"', "").replace("'", "’").replace("\\", "/").split())[:100]


def allocator_for(config: GatewayConfig) -> RuleIdAllocator:
    return RuleIdAllocator(config.rule_id_min, config.rule_id_max, Path(config.rules_dir) / ".next_ai_rule_id")
