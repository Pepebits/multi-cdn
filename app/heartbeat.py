"""Aviso externo si el panel deja de funcionar (plan §9.6), con healthchecks.io o compatible.

Cada 5 min el panel llama a la URL configurada si sus tareas siguen vivas; si alguna se ha
parado llama a <URL>/fail con el motivo. Si el panel se cuelga o el VPS cae, deja de llamar y
el servicio externo avisa al cumplirse el plazo. Configura allí: periodo 5 min, margen 10 min.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx

from .i18n import N_, tn

INTERVAL = 300
DNS_MAX = timedelta(minutes=5)
CF_MAX = timedelta(minutes=15)
FEED_WARN = timedelta(minutes=30)
STARTUP_GRACE = timedelta(minutes=3)  # /healthz answers 200 while the loops make their first round


@dataclass
class Beat:
    at: datetime
    ok: bool
    result: str      # "ok" o el error al llamar
    detail: str      # lo que se envió


_LOCAL_SUFFIXES = (".local", ".internal", ".localhost")


def valid_url(url: str) -> bool:
    """https://<public hostname>[:443]/…: no IP literal, no local names, no credentials. The
    panel calls it from the server, so it must not be usable to reach the server's own network."""
    if not url or len(url) >= 300 or "\\" in url or any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in url):
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    host = (parts.hostname or "").rstrip(".")
    if parts.scheme != "https" or not host or parts.username is not None or parts.password is not None:
        return False
    return port in (None, 443) and public_hostname(host)


def public_hostname(host: str) -> bool:
    """A public DNS name: not an IP literal, not localhost or a local suffix."""
    host = (host or "").rstrip(".").lower()
    if not host or "." not in host or host == "localhost" or host.endswith(_LOCAL_SUFFIXES):
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    # A name, not a number in another notation (127.1, 0x7f.1): top-level domains have letters.
    return any(c.isalpha() for c in host.rsplit(".", 1)[-1])


Resolver = Callable[[str], Awaitable[Iterable[str]]]


async def _resolve(host: str) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


def is_public_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                                 or ip.is_multicast or ip.is_unspecified)


async def host_is_public(host: str, origin_ips: Iterable[str] = (), resolver: Resolver | None = None) -> bool:
    """When the URL is saved: every address the name resolves to is public and none is an
    origin IP. A name that does not resolve is rejected too."""
    origins = set()
    for raw in origin_ips or ():
        try:
            origins.add(ipaddress.ip_address(str(raw)))
        except ValueError:
            pass
    try:
        addresses = list(await (resolver or _resolve)(host))
    except (OSError, UnicodeError):
        return False
    if not addresses:
        return False
    for raw in addresses:
        try:
            ip = ipaddress.ip_address(str(raw).split("%")[0])
        except ValueError:
            return False
        if not is_public_address(ip) or ip in origins or (getattr(ip, "ipv4_mapped", None) in origins):
            return False
    return True


ENGINE_MAX = timedelta(minutes=10)


def _engine_should_run(state) -> bool:
    from .engine import failover
    return failover.auto_enabled(state) and any(failover.eligible(d) for d in state.inventory.domains.values())


def _needs_cf(state) -> list[str]:
    return [n for n, d in state.inventory.domains.items() if d.cloudflare_credential and d.zone_id]


def liveness(state, now: datetime) -> list[str]:
    """The panel's own loops that have stopped: "dns", "cloudflare", "engine" (ADR-002)."""
    stale = []
    if state.dns_checked_at is None or now - state.dns_checked_at > DNS_MAX:
        stale.append("dns")
    if _needs_cf(state) and (state.cf_sync_at is None or now - state.cf_sync_at > CF_MAX):
        stale.append("cloudflare")
    ok_at = getattr(state, "engine_ok_at", None)
    if ok_at is not None and now - ok_at > ENGINE_MAX and _engine_should_run(state):
        stale.append("engine")
    return stale


STALE_TEXT = {
    "dns": N_("the DNS check has been stopped for more than 5 min"),
    "cloudflare": N_("reading Cloudflare has been stopped for more than 15 min"),
    "engine": N_("the switching engine has not completed a cycle for more than 10 min"),
}


CF_FAILING = N_("reading Cloudflare has been failing for more than 15 min")
FEED_OLD = N_("block feed without recent data")
FEED_STALE = N_("block feed answering with old data: automatic switching is not deciding")
CALENDAR_DOWN = N_("match calendar not available")
DRY_RUN = N_("dry run mode")
LIVE = N_("live mode")


def checks(state, now: datetime | None = None) -> tuple[list[str], list[str]]:
    """(failures, notes), untranslated (N_): only the panel's own tasks count as failures;
    what depends on third parties (feed, calendar) is a note. Translate with tr() to show them
    or tn() to send them."""
    now = now or datetime.now(UTC)
    stale = liveness(state, now)
    failures, notes = [STALE_TEXT[k] for k in stale], []
    if "cloudflare" not in stale:
        # The loop runs but its reads fail (token revoked, API down): a switch would fail too.
        since = getattr(state, "started_at", None)
        cf_ok_at = getattr(state, "cf_ok_at", {})
        if any((last := cf_ok_at.get(n, since)) is None or now - last > CF_MAX for n in _needs_cf(state)):
            failures.append(CF_FAILING)
    if state.feed is None or now - state.feed.fetched_at > FEED_WARN:
        notes.append(FEED_OLD)
    elif state.feed.is_stale(now):
        notes.append(FEED_STALE)
    if state.calendar_error:
        notes.append(CALENDAR_DOWN)
    notes.append(DRY_RUN if state.dry_run else LIVE)
    return failures, notes


def health(state, now: datetime | None = None) -> tuple[bool, list[str]]:
    """(¿funciona el panel?, mensajes en el idioma de los avisos) for the heartbeat."""
    failures, notes = checks(state, now)
    return not failures, [tn(x) for x in failures + notes]


async def beat(state, now: datetime | None = None) -> Beat | None:
    url = state.secrets.get("heartbeat_url")
    if not url:
        return None
    now = now or datetime.now(UTC)
    ok, messages = health(state, now)
    detail = "; ".join(messages)
    try:
        r = await state.client.post(url.rstrip("/") + ("" if ok else "/fail"), content=detail.encode(), timeout=15,
                                    follow_redirects=False)
        result = "ok" if r.status_code < 300 else f"HTTP {r.status_code}"  # a redirect is not followed: not delivered
    except httpx.HTTPError as exc:
        result = type(exc).__name__
    state.last_beat = Beat(now, ok, result, detail)
    return state.last_beat
