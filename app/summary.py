"""Weekly summary: every Monday morning, one message with the last 7 days per domain (block
episodes, time unprotected, time on Gcore, switches), the mass-block hours and the problems still
open. Sent like any alert (Telegram and email) and kept in the history. On/off in Settings →
Notifications ("weekly_summary").
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from . import event_codes, stats
from .engine import failover
from .i18n import format_when, notify_lang, tn, tnn

WEEKDAY, HOUR = 0, 7          # Monday, 07:00 UTC (08:00 in Spain in winter)
CHECK_INTERVAL = 3600         # the task looks every hour whether it is due
LAST_KEY = "weekly_summary_last"


def _week(now: datetime) -> str:
    year, week, _ = now.isocalendar()
    return f"{year}-W{week:02d}"


def due(state, now: datetime) -> bool:
    if not state.events.get_setting("weekly_summary"):
        return False
    if now.weekday() != WEEKDAY or now.hour < HOUR:
        return False
    return state.events.get_value(LAST_KEY) != _week(now)


def build(state, now: datetime) -> tuple[str, list[str]]:
    """(title, one line per domain plus totals) for the 7 days before `now`."""
    start = now - timedelta(days=7)
    known = state.engine.known_ips()
    lines, episodes, exposed = [], 0, timedelta(0)
    for name, _cfg in state.inventory.ordered_domains():
        dp = stats.domain_period(state, name, start, now, now, known)
        episodes += len(dp.blocks)
        exposed += dp.exposed_total
        if not dp.blocks and not (dp.switches_auto + dp.switches_manual) and not dp.gcore_time:
            lines.append(tn("{domain}: no blocks", domain=name))
            continue
        parts = [tnn("{n} block episode", "{n} block episodes", len(dp.blocks))]
        if dp.blocks:
            parts.append(tn("{time} unprotected", time=stats.fmt_duration(dp.exposed_total)))
        if dp.gcore_time:
            parts.append(tn("{time} on Gcore", time=stats.fmt_duration(dp.gcore_time)))
        if switches := dp.switches_auto + dp.switches_manual:
            parts.append(tnn("{n} switch ({auto} automatic)", "{n} switches ({auto} automatic)", switches,
                             auto=dp.switches_auto))
        lines.append(f"{name}: " + " · ".join(parts))
    if state.feed is not None:
        series = stats.mass_series(state.feed, start, now, timedelta(hours=1))
        hours = sum(1 for _, v in series if v >= failover.MASS_BLOCK)
        if hours:
            lines.append(tnn("Mass block: {n} hour", "Mass block: {n} hours", hours))
    from .problems import open_problems
    if problems := open_problems(state, now):
        lines.append(tnn("{n} problem still open in the panel", "{n} problems still open in the panel", len(problems)))
    lang = notify_lang()
    title = tn("Weekly summary {start} – {end}: {episodes}, {exposed} unprotected",
               start=format_when(start, lang, time=False), end=format_when(now, lang, time=False),
               episodes=tnn("{n} block episode", "{n} block episodes", episodes),
               exposed=stats.fmt_duration(exposed))
    return title, lines


def send_if_due(state, now: datetime | None = None) -> bool:
    now = now or datetime.now(UTC)
    if not due(state, now):
        return False
    title, lines = build(state, now)
    state.events.set_value(LAST_KEY, _week(now))  # before adding: a failure must not resend every hour
    state.events.add(actor="auto", kind="config", summary=title, signals=lines, code=event_codes.WEEKLY_SUMMARY)
    return True


async def weekly_summary(state) -> None:
    send_if_due(state)
