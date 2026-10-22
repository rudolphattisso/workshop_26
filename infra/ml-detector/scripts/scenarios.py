"""Scénarios simulés partagés par l'entraînement, la démo et les tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from detector.sources.simulated import AttackSpec, LabeledRecord, SimulatedSource

T0 = datetime(2026, 10, 20, 14, 0, tzinfo=timezone.utc)

# Une attaque de chaque type, l'une après l'autre : sert de canaris à la validation du modèle.
CANARY_ATTACKS = (
    AttackSpec("xss", 60, 45, rate_per_s=2, first_ip=200),
    AttackSpec("sqli", 120, 45, rate_per_s=2, first_ip=205),
    AttackSpec("traversal", 180, 45, rate_per_s=2, first_ip=210),
    AttackSpec("scan", 240, 45, rate_per_s=6, first_ip=215),
    AttackSpec("bruteforce", 300, 45, rate_per_s=8, first_ip=220),
    AttackSpec("flood", 360, 45, rate_per_s=60, n_ips=2, first_ip=225),
    AttackSpec("ddos_distributed", 420, 60, rate_per_s=50, n_ips=100, first_ip=66),
    AttackSpec("ddos_cachebust", 480, 45, rate_per_s=30, n_ips=20, first_ip=67),
    AttackSpec("ddos_heavy", 540, 45, rate_per_s=1, n_ips=8, first_ip=68),
)

# Démo : attaques plus réalistes, dont certaines se chevauchent et une distribuée.
# Une plage d'IP par attaque (first_ip) : sinon toutes partaient de .200, le scan la faisait bannir
# et le détecteur ne voyait plus que « IP déjà bannie » (fuite constatée le 2026-10-20).
# Plages libres : .90 marchand, .100 NAT, .240/.241 robots sont pris par le trafic normal.
DEMO_ATTACKS = (
    AttackSpec("scan", 120, 60, rate_per_s=5, first_ip=215),
    AttackSpec("sqli", 270, 90, rate_per_s=1.5, first_ip=205),
    AttackSpec("xss", 300, 60, rate_per_s=1, first_ip=200),
    AttackSpec("bruteforce", 450, 60, rate_per_s=7, first_ip=220),
    AttackSpec("traversal", 600, 40, rate_per_s=1, first_ip=210),
    AttackSpec("flood", 720, 60, rate_per_s=80, n_ips=6, first_ip=225),
)


# Démo DDoS, WAF actif : ce que le WAF arrête, ce qui passe sous ses seuils, et un piège à faux positifs.
#   03:00  flood depuis UNE IP (30 req/s)       -> limité puis banni par le WAF
#   06:00  afflux promo : 200 nouveaux clients  -> légitime, ne doit PAS être signalé
#   10:00  botnet : 300 IP à 0,5 req/s chacune  -> sous les seuils par IP, sature le service
#   14:00  contournement de cache : 40 IP       -> sous les seuils, chaque requête atteint l'appli
#   17:00  exports coûteux : 15 comptes         -> faible débit, le coût fait tomber le service
DDOS_RUSH_AT_S = 360
DDOS_ATTACKS = (
    AttackSpec("flood", 180, 60, rate_per_s=30, first_ip=225),
    AttackSpec("ddos_distributed", 600, 180, rate_per_s=150, n_ips=300, first_ip=66),
    AttackSpec("ddos_cachebust", 840, 120, rate_per_s=70, n_ips=40, first_ip=67),
    AttackSpec("ddos_heavy", 1020, 120, rate_per_s=2, n_ips=15, first_ip=68),
)


def ddos_traffic(minutes: int = 20, seed: int = 11) -> list[LabeledRecord]:
    src = SimulatedSource(seed=seed, attacks=DDOS_ATTACKS, rushes=(DDOS_RUSH_AT_S,), rush_visitors=200)
    return src.generate(T0, T0 + timedelta(minutes=minutes))


def baseline_traffic(minutes: int = 30, seed: int = 1) -> list[LabeledRecord]:
    return SimulatedSource(seed=seed).generate(T0, T0 + timedelta(minutes=minutes))


def canary_traffic(seed: int = 99) -> list[LabeledRecord]:
    # WAF inactif (ni blocage, ni limitation de débit, ni bannissement) et service sans saturation :
    # on vérifie que le modèle détecte chaque type d'attaque par son seul signal, SANS l'aide du
    # WAF (avec bannissement, le flood est coupé en ~1 s et il ne reste que sa première seconde).
    src = SimulatedSource(seed=seed, n_users=10, attacks=CANARY_ATTACKS, waf_blocking=False,
                          bad_behavior=None, rate_limit=None, capacity=None)
    return src.generate(T0, T0 + timedelta(minutes=10))


def demo_traffic(minutes: int = 15, seed: int = 7, waf_blocking: bool = True) -> list[LabeledRecord]:
    src = SimulatedSource(seed=seed, attacks=DEMO_ATTACKS, waf_blocking=waf_blocking)
    return src.generate(T0, T0 + timedelta(minutes=minutes))
