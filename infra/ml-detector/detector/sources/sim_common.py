"""Éléments communs au simulateur de trafic (normal et attaques)."""
from __future__ import annotations

import random
import uuid
from dataclasses import dataclass
from datetime import datetime

from ..models import HttpRequestLog

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36",
]
PUBLIC_HOST = "http://192.168.137.1/"


@dataclass(frozen=True)
class LabeledRecord:
    record: HttpRequestLog
    label: str                # "normal" ou type d'attaque (vérité terrain, jamais montrée au modèle)


def make_req(ts: datetime, ip: str, method: str, uri: str, status: int, size: int, ua: str,
             referer: str = "", label: str = "normal") -> LabeledRecord:
    return LabeledRecord(
        HttpRequestLog(ts=ts.replace(microsecond=0), client_ip=ip, method=method, uri=uri,
                       protocol="HTTP/1.1", status=status, bytes_sent=size, referer=referer, user_agent=ua),
        label,
    )


def rand_uuid(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))
