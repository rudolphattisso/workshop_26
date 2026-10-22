"""Parsing des journaux d'accès BunkerWeb (nginx).

Format attendu : « combined » de nginx, éventuellement précédé de $host (selon la version de
BunkerWeb). Exemple :
    192.168.137.20 - - [20/Oct/2026:14:03:11 +0000] "GET /api/payments?limit=20 HTTP/1.1" 200 512 "-" "Mozilla/5.0 ..."
    bunkerweb 192.168.137.20 - - [20/Oct/2026:14:03:11 +0000] "GET / HTTP/1.1" 200 2400 "-" "curl/8.5"

Format réel de BunkerWeb (validé sur l'export Wazuh du 19/10/2026) : $request_id inséré avant
$remote_user :
    localhost 172.30.10.1 - 68b7cd9283258c88b03e70f37c2a147a - [19/Oct/2026:12:50:05 +0000] "GET /?q=... HTTP/1.1" 403 69298 "-" "ua"

Les lignes qui ne correspondent pas (journal d'erreurs, ModSecurity...) sont ignorées : parse_line
renvoie None.
"""
from __future__ import annotations

import re
from datetime import datetime

from .models import HttpRequestLog

_IP = r"[0-9a-fA-F:.]+"
_ACCESS_RE = re.compile(
    rf'^(?:(?P<host>\S+)\s+)?(?P<ip>{_IP})\s+-\s+(?:(?P<request_id>[0-9a-fA-F]{{32}})\s+)?(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _unescape_nginx(value: str) -> str:
    """nginx écrit les guillemets et caractères non imprimables sous la forme \\xHH."""
    if "\\x" not in value:
        return value
    return re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), value)


def _dash(value: str | None) -> str:
    return "" if value in (None, "-") else value


def parse_line(line: str) -> HttpRequestLog | None:
    match = _ACCESS_RE.match(line.strip())
    if not match:
        return None
    try:
        ts = datetime.strptime(match["time"], _TIME_FMT)
    except ValueError:
        return None

    # Requête malformée (scanners, flood bas niveau) : on garde la ligne avec une méthode vide.
    parts = _unescape_nginx(match["request"]).split(" ")
    if len(parts) == 3:
        method, uri, protocol = parts
    else:
        method, uri, protocol = "", " ".join(parts), ""

    return HttpRequestLog(
        ts=ts,
        client_ip=match["ip"],
        method=method,
        uri=uri,
        protocol=protocol,
        status=int(match["status"]),
        bytes_sent=0 if match["bytes"] == "-" else int(match["bytes"]),
        referer=_dash(_unescape_nginx(match["referer"] or "")),
        user_agent=_dash(_unescape_nginx(match["ua"] or "")),
        host=match["host"] or "",
    )


def _escape_nginx(value: str) -> str:
    return "".join(f"\\x{ord(c):02X}" if c in '"\\' or ord(c) < 0x20 or ord(c) == 0x7F else c for c in value)


def format_line(rec: HttpRequestLog) -> str:
    """Inverse de parse_line : utilisé par le simulateur pour produire des lignes réalistes."""
    request = _escape_nginx(f"{rec.method} {rec.uri} {rec.protocol}" if rec.method else rec.uri)
    prefix = f"{rec.host} " if rec.host else ""
    return (
        f'{prefix}{rec.client_ip} - - [{rec.ts.strftime(_TIME_FMT)}] "{request}" {rec.status} {rec.bytes_sent} '
        f'"{_escape_nginx(rec.referer) or "-"}" "{_escape_nginx(rec.user_agent) or "-"}"'
    )
