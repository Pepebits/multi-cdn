"""Salud del origen (señal S6): ¿responde el servidor, independientemente del CDN?

Cada 2 min, por servidor: HTTPS directo a su IP de origen con el SNI y el Host de uno de sus
hostnames y la cabecera secreta, como haría un CDN. Desde el panel en el propio VPS el firewall
lo permite (tráfico interno). Avisa tras 2 fallos seguidos y cuando vuelve a responder.
Usa HEAD: la respuesta llega completa (sin cuerpo) y el proxy no registra conexiones cortadas.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime

from .i18n import tn

INTERVAL = 120
FAILS_TO_ALERT = 2


@dataclass
class OriginHealth:
    server: str
    hostname: str
    ok: bool
    detail: str
    checked_at: datetime
    fails: int = 0
    alerted: bool = False


async def probe(ip: str, hostname: str, headers: dict[str, str], timeout: float = 10) -> tuple[bool, str]:
    ctx = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=hostname), timeout)
    except ssl.SSLCertVerificationError as exc:
        return False, tn("invalid certificate at the origin ({error})", error=exc.verify_message)
    except (ssl.SSLError, OSError, asyncio.TimeoutError) as exc:
        return False, tn("cannot connect ({error})", error=type(exc).__name__)
    extra = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    writer.write(f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: multicdn-health\r\n{extra}Connection: close\r\n\r\n".encode())
    try:
        await writer.drain()
        status = (await asyncio.wait_for(reader.readline(), timeout)).decode(errors="replace").split()
    except (OSError, asyncio.TimeoutError) as exc:
        return False, tn("no response ({error})", error=type(exc).__name__)
    finally:
        writer.close()
    code = status[1] if len(status) > 1 else "?"
    return (code.isdigit() and int(code) < 500), f"HTTP {code}"


def targets(state) -> dict[str, tuple[str, str]]:
    """servidor -> (IP de origen, hostname con el que probar). Primero los dominios críticos."""
    out: dict[str, tuple[str, str]] = {}
    for _, domain in state.inventory.ordered_domains():
        for h in domain.hostnames:
            server = state.inventory.servers.get(h.server)
            if server and server.origin_ipv4 and h.server not in out and h.origin_kind != "tunnel":
                out[h.server] = (str(server.origin_ipv4), h.name)
    return out


async def check(state, now: datetime | None = None, prober=probe) -> None:
    from .gcore_setup import origin_secret

    now = now or datetime.now(UTC)
    headers = {"X-Origin-Auth": origin_secret(state.secrets, "gcore")}
    for server, (ip, hostname) in targets(state).items():
        ok, detail = await prober(ip, hostname, headers)
        prev = state.origin_health.get(server)
        cur = OriginHealth(server, hostname, ok, detail, now,
                           fails=0 if ok else (prev.fails + 1 if prev else 1),
                           alerted=bool(prev and prev.alerted))
        if not ok and cur.fails >= FAILS_TO_ALERT and not cur.alerted:
            cur.alerted = True
            state.events.add(actor="auto", kind="alert",
                             summary=tn("Origin {server} is not responding ({host}: {detail}); the problem is not the CDN",
                                        server=server, host=hostname, detail=detail))
        elif ok and cur.alerted:
            cur.alerted = False
            state.events.add(actor="auto", kind="alert", summary=tn("Origin {server} is responding again ({host}: {detail})", server=server, host=hostname,
                                        detail=detail))
        state.origin_health[server] = cur


def down_note(state, domain_name: str) -> str:
    """Texto a añadir a un fallo de cambio si el origen de ese dominio no responde."""
    domain = state.inventory.domains.get(domain_name)
    for h in domain.hostnames if domain else []:
        health = state.origin_health.get(h.server)
        if health and not health.ok:
            return tn(" (origin {server} does not respond directly either: {detail})", server=h.server, detail=health.detail)
    return ""
