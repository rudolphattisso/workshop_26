"""LED du back-office (consigne additionnelle 1) : étape identifiant, effet des connexions, route de l'ESP32."""

import pytest
from conftest import TEST_PASSWORDS
from fastapi.testclient import TestClient

from app import routes
from app.iot import LedPattern, LedState
from app.main import app

client = TestClient(app)
DEVICE_TOKEN = "test-device-token"


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture(autouse=True)
def fresh_led(monkeypatch, clock):
    state = LedState(clock=clock)
    monkeypatch.setattr(routes, "led", state)
    monkeypatch.setenv("IOT_DEVICE_TOKEN", DEVICE_TOKEN)
    monkeypatch.delenv("IOT_DEVICE_TOKEN_FILE", raising=False)
    return state


def led_status():
    response = client.get("/api/auth/iot/led", headers={"X-Device-Token": DEVICE_TOKEN})
    assert response.status_code == 200
    return response.json()


def identify(username):
    return client.post("/api/auth/login/identify", json={"username": username})


def login(username, password):
    return client.post("/api/auth/login", json={"username": username, "password": password})


# ------------------------------------------------------------ route ESP32


def test_led_is_off_by_default():
    assert led_status()["pattern"] == "OFF"


def test_led_route_rejects_missing_or_wrong_token():
    assert client.get("/api/auth/iot/led").status_code == 401
    assert client.get("/api/auth/iot/led", headers={"X-Device-Token": "wrong"}).status_code == 401


def test_led_route_disabled_without_configured_token(monkeypatch):
    monkeypatch.delenv("IOT_DEVICE_TOKEN")
    assert client.get("/api/auth/iot/led", headers={"X-Device-Token": "x"}).status_code == 503


def test_led_response_is_not_cached():
    response = client.get("/api/auth/iot/led", headers={"X-Device-Token": DEVICE_TOKEN})
    assert response.headers["Cache-Control"] == "no-store"


# ------------------------------------------------------- parcours opérateur


def test_known_operator_is_recognized_and_led_blinks_green():
    response = identify("operator")
    assert response.status_code == 200 and response.json() == {"recognized": True}
    assert led_status()["pattern"] == "GREEN_BLINK"


@pytest.mark.parametrize("username", ["mallory", "alice"])  # inconnu, ou client sans accès au back-office
def test_unrecognized_identifier_turns_led_red(username):
    assert identify(username).json() == {"recognized": False}
    assert led_status()["pattern"] == "RED_FIXED_30S"


def test_operator_good_password_turns_led_fixed_green():
    identify("operator")
    assert login("operator", TEST_PASSWORDS["OPERATOR_PASSWORD"]).status_code == 200
    assert led_status()["pattern"] == "GREEN_FIXED_30S"


def test_operator_wrong_password_blinks_red():
    identify("operator")
    assert login("operator", "not-the-password").status_code == 401
    assert led_status()["pattern"] == "RED_BLINK_X10"


@pytest.mark.parametrize(
    "username,password",
    [
        ("smoke-client", TEST_PASSWORDS["SMOKE_CLIENT_PASSWORD"]),  # preuve de reprise
        ("alice", "not-the-password"),
        ("mallory", "not-the-password"),
    ],
)
def test_non_operator_logins_leave_led_untouched(username, password):
    before = led_status()
    login(username, password)
    assert led_status() == before


# ------------------------------------------------------------- séquence et durées


def test_each_event_increments_seq_even_for_same_pattern():
    identify("operator")
    first = led_status()["seq"]
    identify("operator")
    assert led_status()["seq"] == first + 1


def test_reading_does_not_change_seq():
    identify("operator")
    assert led_status() == led_status()


@pytest.mark.parametrize(
    "pattern,ttl",
    [
        (LedPattern.GREEN_BLINK, 120),
        (LedPattern.GREEN_FIXED_30S, 30),
        (LedPattern.RED_BLINK_X10, 5),
        (LedPattern.RED_FIXED_30S, 30),
    ],
)
def test_pattern_falls_back_to_off_after_its_duration(fresh_led, clock, pattern, ttl):
    fresh_led.set(pattern)
    clock.now += ttl - 0.1
    assert led_status()["pattern"] == pattern.value
    seq = led_status()["seq"]
    clock.now += 0.2
    status = led_status()
    assert status["pattern"] == "OFF" and status["seq"] == seq + 1
