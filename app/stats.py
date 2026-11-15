"""Estadísticas: se reconstruyen a partir de datos que ya existen.

- Bloqueos: el feed trae el historial de cambios de cada IP y operadora (unos 2 meses).
- Por dónde se ha servido cada dominio: el diff DNS de cada cambio real del historial.
- Tráfico de Gcore: su API de estadísticas, por día y recurso.
- Partidos: el calendario actual y, para días pasados, football-data.org (solo LaLiga).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import lru_cache

PERIODS = {7: timedelta(hours=1), 30: timedelta(hours=2), 60: timedelta(hours=4)}  # días -> paso de la serie
MASS_MIN_ISPS = 3


@dataclass
class Interval:
    start: datetime
    end: datetime | None  # None: sigue abierto
    max_isps: int = 0
    isps: set = field(default_factory=set)

    def duration(self, now: datetime) -> timedelta:
        return (self.end or now) - self.start


@dataclass
class Segment:
    start: datetime
    end: datetime
    kind: str  # cloudflare | gcore | mixed | unknown


def period(days: int, now: datetime) -> tuple[datetime, datetime, timedelta]:
    step = PERIODS.get(days, PERIODS[7])
    end = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    return end - timedelta(days=days), end, step


# ---------------------------------------------------------------- bloqueos (feed)

def mass_series(feed, start: datetime, end: datetime, step: timedelta, min_isps: int = MASS_MIN_ISPS,
                provider: str = "Cloudflare") -> list[tuple[datetime, int]]:
    """Máximo, en cada paso, de IPs del proveedor bloqueadas a la vez en ≥ min_isps operadoras."""
    events = sorted((ts, ip, isp, blocked) for ip, changes in feed.history.items()
                    if provider in feed.providers.get(ip, "") for ts, isp, blocked in changes)
    state: dict[tuple[str, str], bool] = {}
    per_ip: dict[str, int] = {}
    current = 0
    out: list[tuple[datetime, int]] = []
    i = 0

    def apply(ev) -> None:
        nonlocal current
        _ts, ip, isp, blocked = ev
        if state.get((ip, isp), False) == blocked:
            return
        state[(ip, isp)] = blocked
        before = per_ip.get(ip, 0)
        per_ip[ip] = before + (1 if blocked else -1)
        if before < min_isps <= per_ip[ip]:
            current += 1
        elif per_ip[ip] < min_isps <= before:
            current -= 1

    t = start
    while t < end:
        t_next = t + step
        while i < len(events) and events[i][0] <= t:  # estado al empezar el tramo
            apply(events[i])
            i += 1
        peak = current
        while i < len(events) and events[i][0] < t_next:  # máximo dentro del tramo
            apply(events[i])
            i += 1
            peak = max(peak, current)
        out.append((t, peak))
        t = t_next
    return out


def block_intervals(feed, ips: list[str], start: datetime, end: datetime) -> list[Interval]:
    """Periodos en que alguna de las IPs estuvo bloqueada en al menos una operadora."""
    events = sorted((ts, ip, isp, blocked) for ip in ips for ts, isp, blocked in feed.history.get(ip, []))
    state: dict[tuple[str, str], bool] = {}
    by_isp: dict[str, int] = {}
    intervals: list[Interval] = []
    open_iv: Interval | None = None
    for ts, ip, isp, blocked in events:
        if ts >= end:
            break
        if state.get((ip, isp), False) == blocked:
            continue
        state[(ip, isp)] = blocked
        by_isp[isp] = by_isp.get(isp, 0) + (1 if blocked else -1)
        active = {k for k, v in by_isp.items() if v > 0}
        if active and open_iv is None:
            open_iv = Interval(ts, None)
        if open_iv is not None:
            open_iv.isps |= active
            open_iv.max_isps = max(open_iv.max_isps, len(active))
            if not active:
                open_iv.end = ts
                intervals.append(open_iv)
                open_iv = None
    if open_iv is not None:
        intervals.append(open_iv)
    out = []
    for iv in intervals:
        if (iv.end or end) <= start:
            continue
        out.append(iv)
    return out


# ---------------------------------------------------------------- por dónde se sirvió (historial)

SEGMENT_KINDS = ("cloudflare", "gcore")  # el resto (origen, otro destino, sin resolver) cuenta como «unknown»


@lru_cache(maxsize=1)
def _known_labels() -> dict[str, str | None]:
    """Textos exactos del «antes» del diff (failover.DNS_BEFORE) en todos los idiomas -> tipo.
    «unknown» (tn("unknown")) no dice nada del estado: None."""
    from .engine.failover import DNS_BEFORE
    from .i18n import LANGS, translate
    labels: dict[str, str | None] = {}
    for kind, text in DNS_BEFORE.items():
        for lang in LANGS:
            labels[translate(text, lang).casefold()] = kind
    for lang in LANGS:
        labels[translate("unknown", lang).casefold()] = None
    return labels


def _kind(dns_text: str) -> str | None:
    """Tipo de destino de un texto del diff DNS: cloudflare | gcore | origin | other | unresolved | None."""
    text = " ".join(dns_text.split()).casefold()
    labels = _known_labels()
    if text in labels:
        return labels[text]
    # Textos de DnsChange.describe(): «Cloudflare proxied» o «CNAME → destino · TTL n».
    if "not proxied" in text or "sin proxy" in text or "proxy off" in text or "proxy desactivado" in text:
        return "origin"
    if text.startswith("cloudflare proxied"):
        return "cloudflare"
    if "gcore" in text or "gcdn" in text:
        return "gcore"
    return None


def _segment_kind(kind: str | None) -> str:
    return kind if kind in SEGMENT_KINDS else "unknown"


def cdn_segments(events, failover_hosts: list[str], current: dict[str, str], start: datetime,
                 end: datetime) -> list[Segment]:
    """events: cambios reales del dominio (cualquier orden). current: proveedor actual por hostname."""
    changes = sorted((e for e in events if e.kind == "switch" and not e.simulated), key=lambda e: e.ts)
    hosts = set(failover_hosts)
    state: dict[str, str] = {}
    # Estado inicial de cada hostname: el «antes» de su primer cambio o, si nunca cambió, el actual.
    for e in changes:
        for host, before, _after in e.dns_diff:
            if host in hosts and host not in state and (kind := _kind(before)):
                state[host] = _segment_kind(kind)
    for host in hosts:
        state.setdefault(host, _segment_kind(current.get(host)))

    def domain_kind() -> str:
        kinds = {state[h] for h in hosts}
        return kinds.pop() if len(kinds) == 1 else ("unknown" if "unknown" in kinds else "mixed")

    timeline: list[tuple[datetime, str]] = [(datetime.min.replace(tzinfo=UTC), domain_kind())]
    for e in changes:
        for host, _before, after in e.dns_diff:
            if host in hosts and (kind := _kind(after)):
                state[host] = _segment_kind(kind)
        timeline.append((e.ts, domain_kind()))
    segments: list[Segment] = []
    for (t0, kind), (t1, _) in zip(timeline, timeline[1:] + [(end, None)]):
        s, e_ = max(t0, start), min(t1, end)
        if s < e_:
            if segments and segments[-1].kind == kind and segments[-1].end == s:
                segments[-1].end = e_
            else:
                segments.append(Segment(s, e_, kind))
    return segments


def overlap(a0: datetime, a1: datetime, b0: datetime, b1: datetime) -> timedelta:
    return max(timedelta(0), min(a1, b1) - max(a0, b0))


def fmt_duration(td: timedelta) -> str:
    minutes = int(td.total_seconds() // 60)
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} h {minutes:02d} min" if minutes else f"{hours} h"
    days, hours = divmod(hours, 24)
    return f"{days} d {hours} h"


# ---------------------------------------------------------------- línea temporal de un dominio

@dataclass
class Period:
    """A stretch on Gcore, a block or a match, cut to the window. ``start_before``: it began
    before the window (``start`` is then the window start); ``end`` None: still going on."""
    kind: str  # gcore | blocked | match
    start: datetime
    end: datetime | None
    start_before: bool = False
    actor: str | None = None      # who moved it to Gcore: "auto" or the username
    ended_by: str | None = None   # who brought it back
    detail: str = ""              # blocked: max ISPs at once; match: competition and teams

    def duration(self, now: datetime) -> timedelta:
        return (self.end or now) - self.start


def timeline_window(days: int, now: datetime) -> tuple[datetime, datetime]:
    """Whole UTC days: today and the ``days - 1`` before it, so the day ticks are evenly spaced."""
    end = now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    return end - timedelta(days=days), end


def domain_timeline(events, failover_hosts: list[str], current: dict[str, str], start: datetime, end: datetime,
                    now: datetime, *, feed=None, ips=(), matches=(),
                    match_length: timedelta = timedelta(hours=2, minutes=30)) -> dict:
    """One domain over [start, end): the "served by" segments (cdn_segments, up to now), the
    periods on Gcore with who started and ended them, the block intervals of its Cloudflare IPs
    (feed history, block_intervals) and the matches of the calendar."""
    upto = min(end, now)
    segments = cdn_segments(events, failover_hosts, current, start, upto) if upto > start else []
    changes = sorted((e for e in events if e.kind == "switch" and not e.simulated), key=lambda e: e.ts)

    def who(e) -> str:
        return "auto" if e.actor == "auto" else e.actor

    periods: list[Period] = []
    for seg in segments:
        if seg.kind != "gcore":
            continue
        began = [e for e in changes if e.ts <= seg.start]
        start_before = seg.start <= start and not any(e.ts == start for e in changes)
        still = seg.end >= upto and upto == now
        ended = None if still else next((e for e in changes if e.ts >= seg.end), None)
        periods.append(Period("gcore", seg.start, None if still else seg.end, start_before,
                              actor=who(began[-1]) if began else None, ended_by=who(ended) if ended else None))
    for iv in (block_intervals(feed, list(ips), start, end) if feed is not None and ips else []):
        periods.append(Period("blocked", max(iv.start, start), iv.end, iv.start < start, detail=str(iv.max_isps)))
    for m in matches:
        if m.kickoff + match_length > start and m.kickoff < end:
            periods.append(Period("match", m.kickoff, m.kickoff + match_length, detail=f"{m.competition}: {m.name}"))
    periods.sort(key=lambda p: (p.start, p.kind))
    return {"start": start, "end": end, "now": now, "segments": segments, "periods": periods}
