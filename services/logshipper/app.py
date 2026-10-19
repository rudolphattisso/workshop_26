"""Log-forwarder pour Wazuh (contrainte Docker Desktop : les logs des conteneurs ne sont
pas lisibles en tant que fichiers par l'agent). Ce service lit en continu les journaux de
tous les conteneurs du projet via le proxy Docker EN LECTURE SEULE, et les écrit dans des
fichiers sous /var/log/agent/<service>.log que l'agent Wazuh analyse (localfile).

Sécurité : aucun accès direct au socket Docker (passe par docker-proxy-ro, GET seulement) ;
n'écrit que dans le volume agent-logs ; tourne en non-root.
"""
import asyncio
import os
import struct
import time

import httpx

DOCKER_API = os.getenv("DOCKER_API", "http://docker-proxy-ro:2375")
PROJECT = os.getenv("COMPOSE_PROJECT", "resilience")
OUT_DIR = os.getenv("OUT_DIR", "/var/log/agent")
POLL = float(os.getenv("POLL_SECONDS", "15"))
SELF = os.getenv("SERVICE_NAME", "logshipper")

os.makedirs(OUT_DIR, exist_ok=True)
_streaming: set[str] = set()


def _writer(service: str):
    path = os.path.join(OUT_DIR, f"{service}.log")
    fh = open(path, "a", buffering=1, encoding="utf-8", errors="replace")
    return fh


async def stream_container(client: httpx.AsyncClient, cid: str, service: str):
    """Lit le flux multiplexé des logs d'un conteneur et écrit chaque ligne dans son fichier."""
    _streaming.add(cid)
    fh = _writer(service)
    buf = b""
    try:
        async with client.stream(
            "GET", f"/containers/{cid}/logs",
            params={"follow": "1", "stdout": "1", "stderr": "1", "tail": "0", "timestamps": "0"},
            timeout=httpx.Timeout(None, connect=10),
        ) as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes():
                buf += chunk
                # Démultiplexage du flux Docker : en-tête de 8 octets [stream,0,0,0,taille(4)]
                while len(buf) >= 8:
                    if buf[0] in (0, 1, 2) and buf[1:4] == b"\x00\x00\x00":
                        size = struct.unpack(">I", buf[4:8])[0]
                        if len(buf) < 8 + size:
                            break
                        payload = buf[8:8 + size]
                        buf = buf[8 + size:]
                    else:
                        # pas de multiplexage (TTY) : on écrit tel quel
                        payload, buf = buf, b""
                    for line in payload.decode("utf-8", "replace").splitlines():
                        if line.strip():
                            fh.write(line + "\n")
    except Exception as exc:  # noqa: BLE001
        fh.write(f'{{"ts":"{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}",'
                 f'"service":"{SELF}","level":"warn","msg":"stream_ended","target":"{service}",'
                 f'"error":"{type(exc).__name__}"}}\n')
    finally:
        fh.close()
        _streaming.discard(cid)


async def discover(client: httpx.AsyncClient):
    import json
    filters = {"label": [f"com.docker.compose.project={PROJECT}"]}
    r = await client.get("/containers/json", params={"filters": json.dumps(filters)})
    r.raise_for_status()
    result = {}
    for c in r.json():
        service = c["Labels"].get("com.docker.compose.service", c["Id"][:12])
        if service != SELF:
            result[c["Id"]] = service
    return result


async def main():
    async with httpx.AsyncClient(base_url=DOCKER_API) as client:
        while True:
            try:
                containers = await discover(client)
                for cid, service in containers.items():
                    if cid not in _streaming:
                        asyncio.create_task(stream_container(client, cid, service))
            except httpx.HTTPError:
                pass
            await asyncio.sleep(POLL)


if __name__ == "__main__":
    asyncio.run(main())
