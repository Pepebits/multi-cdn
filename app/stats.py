"""Estadísticas: se reconstruyen a partir de datos que ya existen.

- Bloqueos: el feed trae el historial de cambios de cada IP y operadora (unos 2 meses).
- Por dónde se ha servido cada dominio: el diff DNS de cada cambio real del historial.
- Tráfico de Gcore: su API de estadísticas, por día y recurso.
- Partidos: el calendario actual y, para días pasados, football-data.org (solo LaLiga).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

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

def _kind(dns_text: str) -> str | None:
    text = dns_text.lower()
    if "gcore" in text or "gcdn" in text:
        return "gcore"
    if "proxied" in text or "cloudflare" in text:
        return "cloudflare"
    return None


def cdn_segments(events, failover_hosts: list[str], current: dict[str, str], start: datetime,
                 end: datetime) -> list[Segment]:
    """events: cambios reales del dominio (cualquier orden). current: proveedor actual por hostname."""
    changes = sorted((e for e in events if e.kind == "switch" and not e.simulated), key=lambda e: e.ts)
    hosts = set(failover_hosts)
    state: dict[str, str] = {}
    # Estado inicial de cada hostname: el «antes» de su primer cambio o, si nunca cambió, el actual.
    for e in changes:
        for host, before, _after in e.dns_diff:
            if host in hosts and host not in state and _kind(before):
                state[host] = _kind(before)
    for host in hosts:
        state.setdefault(host, current.get(host, "unknown"))

    def domain_kind() -> str:
        kinds = {state[h] for h in hosts}
        return kinds.pop() if len(kinds) == 1 else ("unknown" if "unknown" in kinds else "mixed")

    timeline: list[tuple[datetime, str]] = [(datetime.min.replace(tzinfo=UTC), domain_kind())]
    for e in changes:
        for host, _before, after in e.dns_diff:
            if host in hosts and _kind(after):
                state[host] = _kind(after)
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
