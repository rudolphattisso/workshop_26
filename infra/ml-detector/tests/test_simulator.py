"""Le simulateur doit se comporter comme BunkerWeb : tous les résultats de détection en dépendent."""
import random
from collections import Counter
from datetime import timedelta

from detector.sources.sim_attacks import HEAVY_LIMIT
from detector.sources.sim_common import make_req
from detector.sources.simulated import BadBehavior, Capacity, RateLimit, SimulatedSource
from scripts.scenarios import T0


def burst(ip, n, per_s, uri="/", status=200, start=0.0):
    return [make_req(T0 + timedelta(seconds=start + i / per_s), ip, "GET", uri, status, 100, "x") for i in range(n)]


def test_rate_limit_is_counted_per_ip_and_per_second():
    one_ip = SimulatedSource._apply_rate_limit(burst("10.0.0.1", 60, per_s=30), RateLimit())
    # 30 req/s pendant 2 s depuis une IP : 20 passent par seconde, le reste reçoit 429.
    assert Counter(lr.record.status for lr in one_ip) == {200: 40, 429: 20}
    many_ips = [lr for k in range(30) for lr in burst(f"10.0.1.{k}", 2, per_s=1)]
    # Le même volume réparti sur 30 IP sous le seuil : aucun 429 (c'est le DDoS distribué).
    assert all(lr.record.status == 200 for lr in SimulatedSource._apply_rate_limit(many_ips, RateLimit()))


def test_login_has_its_own_lower_limit():
    out = SimulatedSource._apply_rate_limit(burst("10.0.0.2", 8, per_s=100, uri="/api/auth/login", status=401), RateLimit())
    assert sum(lr.record.status == 429 for lr in out) == 3                 # 5 req/s sur la connexion


def test_bad_behavior_bans_after_threshold_and_ban_expires():
    bb = BadBehavior()
    errors = burst("10.0.0.3", bb.threshold, per_s=1, status=404)
    after = burst("10.0.0.3", 1, per_s=1, start=bb.threshold + 5)                      # pendant le bannissement
    later = burst("10.0.0.3", 1, per_s=1, start=bb.threshold + bb.ban_time_s + 5)      # après
    out = SimulatedSource._apply_bans(errors + after + later, bb)
    assert out[-2].record.status == 403 and out[-1].record.status == 200


def test_saturation_hits_everyone_but_waf_refusals_do_not_load_the_service():
    rng = random.Random(0)
    flood = [lr for k in range(150) for lr in burst(f"10.0.2.{k}", 1, per_s=1)]       # 150 req dans la même seconde
    legit = burst("192.168.0.1", 1, per_s=1)
    out = SimulatedSource._apply_saturation(flood + legit, Capacity(units_per_s=60), rng)
    assert 70 < sum(lr.record.status == 503 for lr in out) < 110                      # ~60 % au-delà de 60 unités
    refused = [lr for k in range(150) for lr in burst(f"10.0.3.{k}", 1, per_s=1, status=403)]
    out = SimulatedSource._apply_saturation(refused + legit, Capacity(units_per_s=60), rng)
    assert out[-1].record.status == 200                                               # les 403 n'atteignent pas l'appli


def test_heavy_requests_saturate_at_low_rate():
    rng = random.Random(0)
    heavy = burst("10.0.4.1", 3, per_s=10, uri=f"/api/payments?limit={HEAVY_LIMIT}")   # 3 exports = 120 unités
    out = SimulatedSource._apply_saturation(heavy, Capacity(units_per_s=60, heavy_cost=40), rng)
    assert any(lr.record.status == 503 for lr in out)


def test_normal_traffic_does_not_saturate_the_service():
    labeled = SimulatedSource(seed=4).generate(T0, T0 + timedelta(minutes=10))
    per_second = Counter(int(lr.record.ts.timestamp()) for lr in labeled)
    assert max(per_second.values()) < Capacity().units_per_s / 2
