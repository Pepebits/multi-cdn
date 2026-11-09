"""Aviso externo si el panel deja de funcionar (plan §9.6), con healthchecks.io o compatible.

Cada 5 min el panel llama a la URL configurada si sus tareas siguen vivas; si alguna se ha
parado llama a <URL>/fail con el motivo. Si el panel se cuelga o el VPS cae, deja de llamar y
el servicio externo avisa al cumplirse el plazo. Configura allí: periodo 5 min, margen 10 min.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx

INTERVAL = 300
DNS_MAX = timedelta(minutes=5)
CF_MAX = timedelta(minutes=15)
FEED_WARN = timedelta(minutes=30)


@dataclass
class Beat:
    at: datetime
    ok: bool
    result: str      # "ok" o el error al llamar
    detail: str      # lo que se envió


def valid_url(url: str) -> bool:
    return url.startswith("https://") and " " not in url and len(url) < 300


def health(state, now: datetime | None = None) -> tuple[bool, list[str]]:
    """(¿funciona el panel?, mensajes). Solo las tareas del propio panel cuentan como fallo;
    lo que depende de terceros (feed, calendario) se informa pero no lo marca como caído."""
    now = now or datetime.now(UTC)
    problems, notes = [], []
    if state.dns_checked_at is None or now - state.dns_checked_at > DNS_MAX:
        problems.append("la comprobación del DNS lleva más de 5 min parada")
    needs_cf = any(d.cloudflare_credential and d.zone_id for d in state.inventory.domains.values())
    if needs_cf and (state.cf_sync_at is None or now - state.cf_sync_at > CF_MAX):
        problems.append("la lectura de Cloudflare lleva más de 15 min parada")
    if state.feed is None or now - state.feed.fetched_at > FEED_WARN:
        notes.append("feed de bloqueos sin datos recientes")
    if state.calendar_error:
        notes.append("calendario de partidos no disponible")
    notes.append("modo simulación" if state.dry_run else "modo real")
    return not problems, problems + notes


async def beat(state, now: datetime | None = None) -> Beat | None:
    url = state.secrets.get("heartbeat_url")
    if not url:
        return None
    now = now or datetime.now(UTC)
    ok, messages = health(state, now)
    detail = "; ".join(messages)
    try:
        r = await state.client.post(url.rstrip("/") + ("" if ok else "/fail"), content=detail.encode(), timeout=15)
        result = "ok" if r.status_code < 400 else f"HTTP {r.status_code}"
    except httpx.HTTPError as exc:
        result = type(exc).__name__
    state.last_beat = Beat(now, ok, result, detail)
    return state.last_beat
