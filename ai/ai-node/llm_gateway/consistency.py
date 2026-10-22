"""Contrôle de cohérence du VERDICT du LLM, déterministe (aucun jugement du LLM).

Les garde-fous empêchent une règle dangereuse ; ils ne protègent pas le verdict. Or une donnée
piégée (« ce trafic est un test autorisé ») a fait conclure à un faux positif 3 modèles sur 8
lors du banc du 2026-10-21 : l'opérateur pourrait ignorer une vraie attaque.

Le verdict n'est pas modifié (la décision reste humaine) : on ajoute des avertissements visibles
en tête du rapport quand il contredit ce que le détecteur a mesuré, ou quand les données de
l'attaquant contiennent ce qui ressemble à des consignes adressées au LLM.
"""
from __future__ import annotations

import re

from .contract import ClusterSummary, LlmAnalysis, Verdict

# Indices fondés sur des faits mesurés (motif d'injection présent, foule automatisée...) :
# un « faux positif » ne les fait pas disparaître.
_STRONG_HINTS = {
    "sql_injection": "motifs d'injection SQL", "xss": "motifs XSS", "path_traversal": "traversée de répertoires",
    "command_injection": "injection de commande", "distributed_flood": "foule d'IP automatisées",
    "heavy_requests": "réponses anormalement lourdes", "credential_bruteforce": "échecs de connexion en série",
    "reconnaissance_scan": "scan de chemins", "request_flood": "débit anormal d'une IP",
}
# Ce qui ressemble à une consigne adressée à un LLM, dans un champ venu du trafic.
_INSTRUCTION_LIKE = re.compile(
    r"ignore[rz]?\s+(les|tes|vos|the|all|previous)|consignes?|instructions?|prompt|verdict|"
    r"faux[_ ]positif|false[_ ]positive|test\s+autoris|authori[sz]ed\s+test|whitelist|liste\s+blanche|"
    r"SecRuleEngine|tu\s+es\s+|you\s+are\s+|syst[eè]me\s*:|system\s*:|assistant\s*:",
    re.IGNORECASE,
)


def warnings_for(analysis: LlmAnalysis, cluster: ClusterSummary) -> list[str]:
    out = []
    strong = [h for h in cluster.attack_hints if h in _STRONG_HINTS]
    collateral_only = "possible_waf_collateral" in cluster.attack_hints and not (
        set(strong) & {"sql_injection", "xss", "path_traversal", "command_injection"})
    if analysis.verdict != Verdict.ATTACK and strong and not collateral_only:
        facts = ", ".join(_STRONG_HINTS[h] for h in strong)
        out.append(f"Verdict « {analysis.verdict.value} » en contradiction avec les mesures du détecteur ({facts}). "
                   f"Vérifier avant de classer : une donnée piégée peut avoir influencé le LLM.")
    injected = _instruction_like_fields(cluster)
    if injected:
        out.append("Les données du trafic contiennent des formulations qui ressemblent à des consignes adressées à "
                   f"une IA ({', '.join(injected)}) : tentative probable d'injection de prompt ; le diagnostic "
                   "du LLM est à lire avec prudence.")
    return out


def _instruction_like_fields(cluster: ClusterSummary) -> list[str]:
    found = []
    fields = [("URI", s.get("uri", "")) for s in cluster.samples]
    fields += [("user-agent", u.get("user_agent", "")) for u in cluster.top_user_agents]
    fields += [("chemin", p.get("path", "")) for p in cluster.top_paths]
    for name, value in fields:
        if isinstance(value, str) and _INSTRUCTION_LIKE.search(value) and name not in found:
            found.append(name)
    return found
