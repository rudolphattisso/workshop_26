"""État de la LED de statut du back-office, lu par l'objet connecté ESP32 (docs/IOT.md, consigne additionnelle 1).

Un seul poste opérateur et une seule LED : l'état tient dans une variable en mémoire, sans base de données.
Le serveur publie un motif et un numéro de séquence ; l'ESP32 joue le motif lui-même et ne démarre un
nouveau motif que lorsque `seq` change. Chaque motif retombe à OFF côté serveur une fois sa durée écoulée,
pour qu'un ESP32 qui redémarre ne rejoue pas un motif périmé.
"""

import enum
import hmac
import threading
import time

from resilience_common.config import secret


class LedPattern(str, enum.Enum):
    OFF = "OFF"
    GREEN_BLINK = "GREEN_BLINK"  # identifiant reconnu, en attente du mot de passe
    GREEN_FIXED_30S = "GREEN_FIXED_30S"  # mot de passe valide
    RED_BLINK_X10 = "RED_BLINK_X10"  # mot de passe invalide
    RED_FIXED_30S = "RED_FIXED_30S"  # identifiant non reconnu


# Durée de publication de chaque motif avant retour à OFF (secondes). GREEN_BLINK : l'opérateur a
# abandonné s'il n'a pas saisi son mot de passe en 2 min. RED_BLINK_X10 : 10 × 500 ms côté firmware.
PATTERN_TTL_SECONDS = {
    LedPattern.GREEN_BLINK: 120.0,
    LedPattern.GREEN_FIXED_30S: 30.0,
    LedPattern.RED_BLINK_X10: 5.0,
    LedPattern.RED_FIXED_30S: 30.0,
}


class LedState:
    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()  # les routes synchrones de FastAPI tournent dans un pool de threads
        self._pattern = LedPattern.OFF
        self._seq = 0
        self._set_at = clock()

    def set(self, pattern: LedPattern) -> None:
        with self._lock:
            self._publish(pattern)

    def current(self) -> tuple[LedPattern, int]:
        with self._lock:
            ttl = PATTERN_TTL_SECONDS.get(self._pattern)
            if ttl is not None and self._clock() - self._set_at >= ttl:
                self._publish(LedPattern.OFF)
            return self._pattern, self._seq

    def _publish(self, pattern: LedPattern) -> None:
        self._pattern = pattern
        self._seq += 1
        self._set_at = self._clock()


led = LedState()


def device_token_valid(presented: str | None) -> bool | None:
    """True/False selon le jeton présenté ; None si IOT_DEVICE_TOKEN n'est pas configuré (fonction désactivée)."""
    expected = secret("IOT_DEVICE_TOKEN", required=False)
    if not expected:
        return None
    # Comparaison à temps constant : la durée de la réponse ne révèle pas le jeton caractère par caractère.
    return presented is not None and hmac.compare_digest(presented.encode(), expected.encode())
