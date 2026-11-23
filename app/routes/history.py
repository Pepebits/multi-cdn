"""History and statistics pages."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from .. import i18n
from ..engine import failover
from ..gcore_usage import human as human_bytes
from ..i18n import N_, tr
from ..providers import gcore
from ..signals import calendar as match_calendar
from ..signals import hayahora
from ..state import State
from .common import (
    _common,
    _state,
    templates,
)

router = APIRouter()


# ---------------------------------------------------------------- Historial

@router.get("/historial", response_class=HTMLResponse)
async def historial(request: Request, dominio: str | None = None, actor: str | None = None):
    s = _state(request)
    return templates.TemplateResponse(request, "historial.html", _common(
        request, "historial",
        events=s.events.list(domain=dominio or None, actor=actor or None, limit=200),
        domain_names=[n for n, _ in s.inventory.ordered_domains()],
        f_domain=dominio or "", f_actor=actor or "",
    ))


# ---------------------------------------------------------------- Estadísticas

STATS_CACHE_TTL = timedelta(minutes=30)
CDN_LABEL = {"cloudflare": "Cloudflare", "gcore": "Gcore", "mixed": N_("Mixed"), "unknown": N_("No data")}


async def _cached(state: State, key, factory):
    hit = state.stats_cache.get(key)
    if hit and datetime.now(UTC) - hit[0] < STATS_CACHE_TTL:
        return hit[1]
    value = await factory()
    state.stats_cache[key] = (datetime.now(UTC), value)
    return value


async def _stats_matches(s: State, start: datetime, end: datetime) -> tuple[list, str | None]:
    """Partidos del periodo: el calendario actual y los pasados de LaLiga (football-data.org)."""
    matches = list(s.calendar.matches) if s.calendar else []
    note = None
    token = s.secrets.get("football_data_token")
    if token and os.environ.get("MULTICDN_OFFLINE") != "1":
        try:
            past = await _cached(s, ("fd", start.date()), lambda: match_calendar.fetch_past_laliga(s.http, token, start, end))
            matches = match_calendar.merge(matches, past)
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            note = tr("no past matches ({error})", error=type(exc).__name__)
    elif not token:
        note = tr("past matches not available: add the football-data.org key")
    return [m for m in matches if m.kickoff + match_calendar.MATCH_LENGTH > start and m.kickoff < end], note


async def _stats_traffic(s: State, start: datetime, end: datetime) -> tuple[dict, str | None]:
    """Tráfico diario por dominio (suma de todas las cuentas de Gcore)."""
    if os.environ.get("MULTICDN_OFFLINE") == "1":
        return {}, None
    by_resource: dict[int, list] = {}
    errors = []
    for cred in s.creds.list("gcore"):
        token = s.creds.secret(cred.id)
        if not token:
            errors.append(f"{cred.label}: {tr('the credential cannot be decrypted')}")
            continue
        secret: str = token  # narrowed for the lambda below
        try:
            by_resource |= await _cached(s, ("gc", cred.id, start.date()), lambda: gcore.traffic_series(secret, start, end))
        except (RuntimeError, httpx.HTTPError) as exc:
            errors.append(f"{cred.label}: {exc}")
    names = {d.gcore_resource_id: n for n, d in s.inventory.domains.items() if d.gcore_resource_id}
    out: dict[str, dict] = {}
    for rid, rows in by_resource.items():
        name = names.get(rid) or tr("other resources")
        for day, value in rows:
            out.setdefault(name, {})
            out[name][day.date()] = out[name].get(day.date(), 0) + value
    return out, "; ".join(errors) or None


@router.get("/estadisticas", response_class=HTMLResponse)
async def estadisticas(request: Request, dias: int = 7):
    from .. import charts, stats
    s = _state(request)
    days = dias if dias in stats.PERIODS else 7
    now = datetime.now(UTC)
    start, end, step = stats.period(days, now)

    matches, match_note = await _stats_matches(s, start, end)
    bands = [(m.kickoff, m.kickoff + match_calendar.MATCH_LENGTH, f"{m.competition}: {m.name}") for m in matches]
    series = stats.mass_series(s.feed, start, end, step) if s.feed else []
    mass_hours = sum(step.total_seconds() for _, v in series if v >= failover.MASS_BLOCK) / 3600

    known = s.engine.known_ips()
    rows, episodes = [], []
    gcore_time, switches = timedelta(0), {"auto": 0, "manual": 0}
    exposed_time = timedelta(0)  # blocked at some ISP while still served by Cloudflare
    for name, _cfg in s.inventory.ordered_domains():
        dp = stats.domain_period(s, name, start, end, now, known)
        switches["auto"] += dp.switches_auto
        switches["manual"] += dp.switches_manual
        gcore_time += dp.gcore_time
        exposed_time += dp.exposed_total
        segs, ivs = dp.segments, dp.blocks
        for iv, on_gcore, exposed in zip(ivs, dp.on_gcore, dp.exposed):
            iv_end = iv.end or now
            match = next((label for b0, b1, label in bands if b0 < iv_end and b1 > iv.start), None)
            episodes.append({"domain": name, "start": iv.start, "end": iv.end, "duration": stats.fmt_duration(iv.duration(now)),
                             "isps": iv.max_isps, "isp_names": ", ".join(sorted(hayahora.ISPS.get(i) or i for i in iv.isps)),
                             "gcore_pct": round(100 * on_gcore / iv.duration(now)) if iv.duration(now) else 0,
                             "exposed": stats.fmt_duration(exposed) if exposed >= timedelta(minutes=1) else "—",
                             "match": match})
        rows.append({
            "name": name,
            "segments": [(g.start, g.end, g.kind, f"{tr(CDN_LABEL[g.kind])}: {i18n.format_when(g.start)} – {i18n.format_when(g.end)} "
                                                  f"({stats.fmt_duration(g.end - g.start)})") for g in segs],
            "blocks": [(max(iv.start, start), iv.end or now,
                        tr("Blocked IPs: {start} – {end} · up to {n} ISPs", start=i18n.format_when(iv.start),
                           end=i18n.format_when(iv.end or now), n=iv.max_isps)) for iv in ivs],
            "has_ips": bool(known.get(name)),
        })
    episodes.sort(key=lambda e: e["start"], reverse=True)

    traffic, traffic_error = await _stats_traffic(s, start, end)
    day_list = [(start + timedelta(days=i)).replace(hour=0) for i in range(days + 1)]
    day_list = [d for d in day_list if d < end]
    names = [n for n, _ in s.inventory.ordered_domains() if n in traffic] + sorted(n for n in traffic if n not in s.inventory.domains)
    tseries = [{"name": n, "slot": i % 4 + 1, "values": [traffic[n].get(d.date(), 0) for d in day_list]} for i, n in enumerate(names)]
    traffic_total = sum(sum(t["values"]) for t in tseries)

    return templates.TemplateResponse(request, "estadisticas.html", _common(
        request, "estadisticas", days=days, periods=list(stats.PERIODS), start=start, end=end,
        kpi={"mass_hours": mass_hours, "episodes": len(episodes), "gcore_time": stats.fmt_duration(gcore_time),
             "exposed_time": stats.fmt_duration(exposed_time),
             "switches": switches, "traffic": human_bytes(traffic_total)},
        mass=charts.line_chart(series, start, end, step, bands) if series else None,
        daily_mass=_daily_max(series),
        timeline=charts.timeline(rows, start, end) if rows else None, rows=rows,
        traffic=charts.columns(day_list, tseries, start, end, fmt=human_bytes) if tseries else None,
        tseries=tseries, day_list=day_list, traffic_error=traffic_error,
        episodes=episodes, matches=matches, match_note=match_note, feed_note=None if s.feed else tr("block feed not read yet"),
    ))


def _daily_max(series):
    out: dict = {}
    for t, v in series:
        out[t.date()] = max(out.get(t.date(), 0), v)
    return sorted(out.items())
