"""Trafic légitime simulé, volontairement varié pour ne pas apprendre un « normal » trop sage.

Profils (chacun reproduit un comportement réel qui piège souvent les détecteurs naïfs) :
  - txprobe / blackbox / uptime : sondes régulières (machines, débit constant) ;
  - utilisateurs à domicile     : sessions navigateur variées (liens marketing avec utm_*,
                                  rechargements, doubles clics, session expirée, réseau mobile
                                  instable avec relances, fichiers d'icône absents en 404...) ;
  - entreprise derrière un NAT  : plusieurs personnes derrière UNE seule IP (débit par IP élevé) ;
  - intégration marchand        : un back-end qui envoie des lots de paiements avec une
                                  bibliothèque HTTP (python-requests / axios) : légitime, rapide ;
  - robots et aperçus de liens  : Googlebot (robots.txt, sitemap.xml en 404), WhatsApp, Slack ;
  - afflux (« rush »)           : campagne promo, des dizaines de nouveaux utilisateurs d'un coup
                                  (le faux positif DDoS classique) ;
  - incidents mineurs           : quelques 502/503 et 499 (client parti avant la réponse).
"""
from __future__ import annotations

import math
import random
from datetime import datetime, timedelta

from .sim_common import BROWSER_UAS, PUBLIC_HOST, LabeledRecord, make_req, rand_uuid

PROBE_IP, PROBE_UA = "172.30.20.9", "resilience-txprobe/1.0"
BLACKBOX_IP, BLACKBOX_UA = "172.30.40.7", "Blackbox Exporter/0.27.0"
UPTIME_IP, UPTIME_UA = "192.168.137.5", "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)"
CORP_NAT_IP = "192.168.137.100"
RUSH_NET = "10.50."                 # afflux légitime : 10.50.<k // 250>.<k % 250 + 1>


def rush_ip(k: int) -> str:
    return f"{RUSH_NET}{k // 250}.{k % 250 + 1}"


MERCHANT_IP = "192.168.137.90"
MERCHANT_UAS = ["python-requests/2.31.0", "axios/1.7.7"]
BOTS = [
    ("192.168.137.240", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    ("192.168.137.241", "WhatsApp/2.24.20.79 A"),
    ("192.168.137.242", "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"),
]
LANDING_QUERIES = [
    "", "", "", "", "",
    "?lang=fr", "?lang=en",
    "?utm_source=newsletter&utm_medium=email&utm_campaign=rentree_2026",
    "?utm_source=facebook&utm_medium=social&utm_campaign=promo_oct&fbclid=IwAR2xK9vQ7hL3mN8pR4sT6uW1yZ0aB5cD7eF9gH",
    "?utm_source=google&utm_medium=cpc&utm_term=paiement%20en%20ligne&gclid=Cj0KCQjw4Oe4BhCcARIsADQ0csmX7",
    "?ref=partenaire-cafe-de-l%27opera",
]


class NormalTraffic:
    def __init__(self, rng: random.Random, n_users: int, rushes: tuple[float, ...], origin: datetime,
                 rush_visitors: int = 40):
        self.rng = rng
        self.n_users = n_users
        self.rushes = rushes        # débuts d'afflux, en secondes après origin (durée 3 min)
        self.origin = origin
        self.rush_visitors = rush_visitors

    def generate(self, start: datetime, end: datetime) -> list[LabeledRecord]:
        out: list[LabeledRecord] = []
        out += self._periodic(start, end, 5, self._probe)
        out += self._periodic(start, end, 15, self._blackbox)
        out += self._periodic(start, end, 60, self._uptime)
        for u in range(self.n_users):
            out += self._user_stream(start, end, f"192.168.137.{20 + u}", self.rng.choice(BROWSER_UAS), 120)
        for _ in range(8):                                    # 8 collègues derrière le même NAT
            out += self._user_stream(start, end, CORP_NAT_IP, self.rng.choice(BROWSER_UAS), 180)
        out += self._merchant(start, end)
        out += self._bots(start, end)
        out += self._rushes(start, end)
        return out

    # -- machines ------------------------------------------------------------------------
    def _periodic(self, start, end, period_s, emit):
        out, t = [], start + timedelta(seconds=self.rng.uniform(0, period_s))
        while t < end:
            out += emit(t)
            t += timedelta(seconds=period_s)
        return out

    def _probe(self, t):
        r = self.rng
        return [
            make_req(t, PROBE_IP, "POST", "/api/auth/login", 200, r.randint(380, 420), PROBE_UA),
            make_req(t + timedelta(milliseconds=60), PROBE_IP, "POST", "/api/payments", 201, r.randint(90, 110), PROBE_UA),
            make_req(t + timedelta(milliseconds=120), PROBE_IP, "GET", f"/api/payments/{rand_uuid(r)}", 200,
                     r.randint(180, 220), PROBE_UA),
        ]

    def _blackbox(self, t):
        status = 503 if self.rng.random() < 0.003 else 200        # rare indisponibilité
        return [
            make_req(t, BLACKBOX_IP, "GET", "/api/payments/ready", status, 15, BLACKBOX_UA),
            make_req(t, BLACKBOX_IP, "GET", "/api/auth/ready", 200, 15, BLACKBOX_UA),
            make_req(t, BLACKBOX_IP, "GET", "/", 200, 2412, BLACKBOX_UA),
        ]

    def _uptime(self, t):
        return [make_req(t, UPTIME_IP, "HEAD", "/", 200, 0, UPTIME_UA)]

    # -- humains -------------------------------------------------------------------------
    def _intensity(self, t: datetime) -> float:
        """Charge variable : vague lente (période 20 min) entre 0,5x et 1,5x."""
        minutes = (t - self.origin).total_seconds() / 60
        return 1.0 + 0.5 * math.sin(2 * math.pi * minutes / 20)

    def _user_stream(self, start, end, ip, ua, mean_gap_s):
        out, r = [], self.rng
        t = start + timedelta(seconds=r.expovariate(1 / mean_gap_s))
        while t < end:
            out += self._session(t, ip, ua)
            t += timedelta(seconds=r.expovariate(self._intensity(t) / mean_gap_s))
        return out

    def _session(self, t, ip, ua):
        r = self.rng
        out: list[LabeledRecord] = []
        step = lambda: timedelta(seconds=r.uniform(0.4, 9))  # noqa: E731

        def add(method, uri, status, size, referer=PUBLIC_HOST):
            nonlocal t
            out.append(make_req(t, ip, method, uri, status, size, ua, referer))
            if r.random() < 0.03:                                  # réseau instable : relance
                out.append(make_req(t + timedelta(seconds=1), ip, method, uri, 499 if r.random() < 0.3 else status, size, ua, referer))
            t += step()

        add("GET", "/" + r.choice(LANDING_QUERIES), 200, 2412, "")
        if r.random() < 0.10:
            add("GET", "/favicon.ico", 404, 153)
        if "iPhone" in ua and r.random() < 0.5:
            add("GET", "/apple-touch-icon.png", 404, 153)
        if r.random() < 0.05:
            add("GET", "/manifest.json", 404, 153)

        for _ in range(r.choice([1] * 18 + [2, 3])):              # fautes de mot de passe
            ok = r.random() > 0.1
            add("POST", "/api/auth/login", 200 if ok else 401, r.randint(380, 420) if ok else 44)
            if r.random() < 0.03:                                  # double-clic sur « connexion »
                add("POST", "/api/auth/login", 200 if ok else 401, 44)

        known: list[str] = []
        for _ in range(r.randint(1, 8)):
            action = r.random()
            if action < 0.05:                                      # session expirée -> relogin
                add("GET", "/api/payments", 401, 44)
                add("POST", "/api/auth/login", 200, r.randint(380, 420))
            elif action < 0.12:                                    # rechargement de page
                add("GET", "/", 200, 2412)
            elif action < 0.45:
                query = r.choice(["", "?limit=10", "?limit=20", "?limit=50", "?limit=100"])
                if r.random() < 0.3:                               # anti-cache de la SPA
                    query += ("&" if query else "?") + f"_={int(t.timestamp() * 1000)}"
                add("GET", f"/api/payments{query}", 200 if r.random() > 0.002 else 502, r.randint(150, 9000))
            elif action < 0.78:
                status = r.choices([201, 422, 400], weights=[94, 4, 2])[0]
                add("POST", "/api/payments", status, r.randint(90, 160))
                if status == 201:
                    known.append(rand_uuid(r))
            else:
                tx = r.choice(known) if known and r.random() > 0.05 else rand_uuid(r)
                add("GET", f"/api/payments/{tx}", 200 if tx in known else 404, r.randint(150, 230))
        return out

    def _merchant(self, start, end):
        """Back-end marchand : un lot de paiements toutes les ~5 min, 1 à 2 requêtes/s."""
        out, r = [], self.rng
        ua = r.choice(MERCHANT_UAS)
        t = start + timedelta(seconds=r.uniform(0, 300))
        while t < end:
            out.append(make_req(t, MERCHANT_IP, "POST", "/api/auth/login", 200, 400, ua))
            u = t + timedelta(seconds=1)
            for _ in range(r.randint(20, 60)):
                status = r.choices([201, 422], weights=[97, 3])[0]
                out.append(make_req(u, MERCHANT_IP, "POST", "/api/payments", status, r.randint(90, 160), ua))
                u += timedelta(seconds=r.uniform(0.4, 1.2))
            out.append(make_req(u, MERCHANT_IP, "GET", "/api/payments?limit=100", 200, r.randint(5000, 15000), ua))
            t += timedelta(seconds=r.uniform(240, 360))
        return out

    def _bots(self, start, end):
        out, r = [], self.rng
        t = start + timedelta(seconds=r.expovariate(1 / 240))
        while t < end:
            ip, ua = r.choice(BOTS)
            if "Googlebot" in ua:
                out += [make_req(t, ip, "GET", "/robots.txt", 404, 153, ua),
                        make_req(t + timedelta(seconds=2), ip, "GET", "/", 200, 2412, ua),
                        make_req(t + timedelta(seconds=5), ip, "GET", "/sitemap.xml", 404, 153, ua)]
            else:
                out.append(make_req(t, ip, r.choice(["GET", "HEAD"]), "/" + r.choice(LANDING_QUERIES), 200, 2412, ua))
            t += timedelta(seconds=r.expovariate(1 / 240))
        return out

    def _rushes(self, start, end):
        """Afflux : `rush_visitors` nouveaux visiteurs (nouvelles IP, sessions normales) sur 3 minutes."""
        out, r = [], self.rng
        for rush in self.rushes:
            r_start = self.origin + timedelta(seconds=rush)
            if not (start <= r_start < end):
                continue
            for k in range(self.rush_visitors):
                t = r_start + timedelta(seconds=r.uniform(0, 180))
                out += self._session(t, rush_ip(k), r.choice(BROWSER_UAS))
        return out
