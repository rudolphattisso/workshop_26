"""Attaques simulées.

Bruyantes (charges de attack/attack.py, outils identifiables, débit élevé) :
    xss, sqli, traversal, scan, bruteforce, flood
Discrètes : MÊMES charges, mais comportement qui se fond dans le trafic légitime
(user-agent de navigateur, débit lent, plusieurs IP, chemins plausibles) :
    sqli_slow               injection SQL au compte-gouttes (~1 requête / 30 s)
    xss_slow                XSS au compte-gouttes
    scan_slow               reconnaissance lente de chemins d'API plausibles (~1 requête / 10 s)
    bruteforce_distributed  force brute répartie sur plusieurs IP (~1 essai / min / IP)
Les variantes discrètes servent à MESURER où la détection décroche, pas à la flatter.

DDoS conçus pour passer SOUS les seuils du WAF (limitation de débit et bannissement par IP) :
    ddos_distributed  botnet : des centaines d'IP à ~0,5 req/s chacune sur la page d'accueil,
                      réponses 200 => aucune IP limitée ni bannie, mais le service sature
    ddos_cachebust    quelques dizaines d'IP, paramètre anti-cache aléatoire (« ?_=<horodatage> »,
                      comme la SPA légitime) pour que chaque requête atteigne l'application
    ddos_heavy        requêtes coûteuses (export ?limit=10000) à faible débit depuis des comptes
                      connectés : le coût, pas le volume, fait tomber le service
La limitation de débit (429) et le bannissement sont appliqués ensuite par la couche WAF du
simulateur (simulated.py), par IP, comme BunkerWeb.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import quote

from .sim_common import BROWSER_UAS, PUBLIC_HOST, LabeledRecord, make_req

# Charges de attack/attack.py (pôle cyber).
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "<body onload=alert(document.cookie)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
]
SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "1; DROP TABLE transactions;--",
    "' UNION SELECT username,password_hash FROM users--",
    "1' OR SLEEP(5)--",
]
TRAVERSAL_PAYLOADS = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"]
SCAN_PATHS = [
    "/.env", "/.git/config", "/wp-admin/", "/wp-login.php", "/phpmyadmin/", "/admin", "/server-status",
    "/backup.sql", "/config.php", "/cgi-bin/test.cgi", "/api/v1/users", "/api/admin", "/api/debug",
    "/api/internal", "/swagger.json", "/openapi.json", "/console", "/backup.zip", "/index.php", "/test",
]
# Reconnaissance discrète : chemins qui RESSEMBLENT à l'API réelle (pas de /wp-admin).
PLAUSIBLE_PATHS = [
    "/api/payments/export", "/api/payments/admin", "/api/auth/register", "/api/auth/reset",
    "/api/users", "/api/users/me", "/api/v2/payments", "/api/payments/stats", "/api/config",
    "/api/auth/token", "/api/health", "/api/version", "/api/payments/refund", "/api/merchants",
]
TOOL_UAS = {
    "scan": ["gobuster/3.6", "ffuf/2.1.0"],
    "default": ["resilience-labtest/1.0", "sqlmap/1.8.9#stable (https://sqlmap.org)", "python-requests/2.32.3"],
}

LOUD_KINDS = ("xss", "sqli", "traversal", "scan", "bruteforce", "flood")
STEALTH_KINDS = ("sqli_slow", "xss_slow", "scan_slow", "bruteforce_distributed")
DDOS_KINDS = ("ddos_distributed", "ddos_cachebust", "ddos_heavy")
ATTACK_KINDS = LOUD_KINDS + STEALTH_KINDS + DDOS_KINDS
HEAVY_LIMIT = 10_000          # ddos_heavy : taille d'export demandée (le front n'envoie jamais > 100)


@dataclass(frozen=True)
class AttackSpec:
    kind: str                 # un de ATTACK_KINDS
    start_offset_s: float     # début, en secondes après le début de la simulation
    duration_s: float
    rate_per_s: float = 3.0   # débit TOTAL de l'attaque (toutes IP confondues)
    n_ips: int = 1            # > 1 : attaque distribuée
    first_ip: int = 200       # IP = 192.168.137.<first_ip + i> (évite que deux attaques partagent une IP)
                              # DDoS : 10.<first_ip>.<i // 250>.<i % 250 + 1> (botnet, centaines d'IP)


def generate_attack(spec: AttackSpec, start: datetime, end: datetime, rng: random.Random,
                    waf_blocking: bool) -> list[LabeledRecord]:
    stealth = spec.kind in STEALTH_KINDS + DDOS_KINDS
    if spec.kind in DDOS_KINDS:
        ips = [f"10.{spec.first_ip}.{i // 250}.{i % 250 + 1}" for i in range(spec.n_ips)]
    else:
        ips = [f"192.168.137.{spec.first_ip + i}" for i in range(spec.n_ips)]
    # Discret : chaque IP a son navigateur (un botnet usurpe des UA de navigateur) ; bruyant : un outil commun.
    if stealth:
        uas = {ip: rng.choice(BROWSER_UAS) for ip in ips}
    else:
        ua = rng.choice(TOOL_UAS.get(spec.kind, TOOL_UAS["default"]))
        uas = {ip: ua for ip in ips}

    out, t, logged_in = [], start, set()
    while t < end:
        ip = rng.choice(ips)
        if spec.kind == "ddos_heavy" and ip not in logged_in:     # compte (volé ou créé) connecté d'abord
            logged_in.add(ip)
            out.append(make_req(t, ip, "POST", "/api/auth/login", 200, rng.randint(380, 420), uas[ip],
                                PUBLIC_HOST, label=spec.kind))
        else:
            out.append(_request(spec.kind, t, ip, uas[ip], rng, waf_blocking))
        t += timedelta(seconds=rng.expovariate(spec.rate_per_s))
    return out


def _request(kind, t, ip, ua, rng, blocked) -> LabeledRecord:
    base = kind.split("_")[0]                     # sqli_slow -> sqli
    referer = PUBLIC_HOST if kind in STEALTH_KINDS else ""

    def enc(payload: str) -> str:
        # Les clients encodent la charge ; certains l'envoient presque brute.
        return quote(payload, safe="") if rng.random() < 0.7 else payload.replace(" ", "%20")

    def req(method, uri, status, size):
        return make_req(t, ip, method, uri, status, size, ua, referer, label=kind)

    if base == "xss":
        uri = rng.choice(["/?q=", "/api/payments?search=", "/api/payments?merchant="]) + enc(rng.choice(XSS_PAYLOADS))
        return req("GET", uri, 403 if blocked else 200, 555 if blocked else 2412)
    if base == "sqli":
        p = enc(rng.choice(SQLI_PAYLOADS))
        uri = rng.choice([f"/api/payments?limit={p}", f"/api/payments/{p}", f"/api/payments?id={p}"])
        return req("GET", uri, 403 if blocked else 422, 555 if blocked else 180)
    if base == "traversal":
        p = rng.choice(TRAVERSAL_PAYLOADS)
        uri = rng.choice([f"/?file={p}", f"/api/payments/{p}", f"/static/{p}"])
        return req("GET", uri, 403 if blocked else 404, 555 if blocked else 153)
    if kind == "scan":
        path = rng.choice(SCAN_PATHS)
        status = 403 if blocked and path.startswith(("/.env", "/.git")) else 404
        return req(rng.choice(["GET", "GET", "HEAD"]), path, status, 153)
    if kind == "scan_slow":
        return req("GET", rng.choice(PLAUSIBLE_PATHS), 404, 153)
    if kind in ("bruteforce", "bruteforce_distributed"):
        return req("POST", "/api/auth/login", 401, 44)
    if kind == "flood":
        uri = rng.choice(["/", "/api/payments/ready", "/api/payments"])
        return req("GET", uri, 401 if uri == "/api/payments" else 200, 2412 if uri == "/" else 30)
    if kind == "ddos_distributed":
        return req("GET", "/", 200, 2412)
    if kind == "ddos_cachebust":
        uri = rng.choice(["/", "/api/payments/ready"]) + f"?_={int(t.timestamp() * 1000) + rng.randrange(1000)}"
        return req("GET", uri, 200, 2412 if uri.startswith("/?") else 30)
    if kind == "ddos_heavy":
        return req("GET", f"/api/payments?limit={HEAVY_LIMIT}", 200, rng.randint(1_500_000, 2_500_000))
    raise ValueError(f"type d'attaque inconnu : {kind}")
