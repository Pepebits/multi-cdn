"""Tareas periódicas del controlador: leer el feed, el DNS, Cloudflare y el calendario, avisar
de bloqueos y lanzar el motor de conmutación. `main.lifespan` las arranca con `_loop`."""

from __future__ import annotations

import asyncio
import logging
import os
from collections import Counter
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import httpx

from . import alerts, error_reporting, event_codes, i18n
from .engine import failover
from .i18n import tn, tnn
from .providers import cloudflare as cf
from .signals import calendar as match_calendar
from .signals import dnscheck, hayahora
from .state import State

log = logging.getLogger("multicdn")
FEED_FAST = 90          # seconds between feed reads while something is going on (ADR-001)
FEED_INTERVAL_OPTIONS = (90, 120, 180, 300)  # idle interval, Settings → Automatic switching; never above 300 (is_stale: 10 min)
FEED_FAST_MASS = 10     # Cloudflare IPs blocked at ≥3 ISPs that already count as "something going on" (not validated)
FEED_DOWN_AFTER = timedelta(seconds=90)    # second failure in a row
CF_READ_AFTER = timedelta(minutes=8)
DNS_INTERVAL = 60
CF_SYNC_INTERVAL = 300
PRUNE_INTERVAL = 6 * 3600
RENEW_INTERVAL = 24 * 3600
CALENDAR_INTERVAL = 3 * 3600
USAGE_INTERVAL = 3600
BACKUP_INTERVAL = 24 * 3600
HEARTBEAT_INTERVAL = 300
ORIGIN_HEALTH_INTERVAL = 120
GCORE_WATCH_INTERVAL = 300
GCORE_READY_INTERVAL = 6 * 3600  # check prepared domains still on Cloudflare
GCORE_READY_RETRY = 600          # after a failure, look again soon; alert if it still fails
GCORE_WATCH_AFTER = timedelta(minutes=4)  # alert on the second failed check in a row (5 min apart)


async def refresh_feed(state: State, now: datetime | None = None) -> None:
    try:
        snapshot, etag = await hayahora.fetch_feed(state.http, state.feed_etag if state.feed else None)
        if snapshot is not None:
            fresh = state.feed if state.feed is not None and not state.feed.is_stale(now) else None
            hayahora.check_feed(snapshot, fresh)  # a broken feed must not read as "no blocks"
            state.feed = snapshot
        elif state.feed is not None:  # 304: same data, read just now
            state.feed.fetched_at = datetime.now(UTC)
        state.feed_etag = etag
        state.feed_error = None
    except Exception as exc:  # el feed no es oficial: nunca debe tumbar el controlador
        state.feed_error = f"{type(exc).__name__}: {exc}"
        log.warning("hayahora feed unavailable: %s", state.feed_error)
        # An isolated failure is retried in 90 s; alert from the second one in a row.
        error = str(exc) if isinstance(exc, hayahora.FeedFormatError) else type(exc).__name__
        alerts.problem(state, "feed_down", tn("Block feed unavailable ({error})", error=error),
                       after=FEED_DOWN_AFTER, now=now)
        return
    alerts.clear(state, "feed_down", lambda lasted: tn("Block feed available again (down {minutes} min)",
                                                       minutes=alerts.minutes(lasted)), now=now)
    check_stale_feed(state)
    check_block_transitions(state)
    await run_engine(state)


FEED_LOG_REASON = {"feed": "feed failing or stale", "calendar": "no match calendar", "match": "match window",
                   "gcore": "serving from Gcore", "blocks": "blocks underway"}


def feed_mode(state: State, now: datetime | None = None) -> tuple[int, str | None]:
    """(seconds until the next feed read, why it is fast: feed | calendar | match | gcore |
    blocks, or None when idle). ADR-001: 90 s while something is going on, else the idle
    interval from Settings → Automatic switching (300 s by default)."""
    now = now or datetime.now(UTC)
    calendar = state.calendar
    feed = state.feed
    reason = None
    if feed is None or state.feed_error or feed.is_stale(now):
        reason = "feed"
    elif calendar is None or calendar.is_stale(now):
        reason = "calendar"
    elif calendar.active(now, max(failover.match_lead(state, p) for p in failover.PRIORITIES)):
        reason = "match"
    elif any(r.provider == "gcore" for r in state.resolutions.values()) \
            or any(state.engine.get(n).sim_backup for n in state.inventory.domains):
        reason = "gcore"
    elif state.blocked_domains or feed.blocked_ips() >= FEED_FAST_MASS:
        reason = "blocks"
    idle = state.events.get_setting("feed_interval")
    return (FEED_FAST if reason else (idle if idle in FEED_INTERVAL_OPTIONS else FEED_INTERVAL_OPTIONS[-1])), reason


def feed_interval(state: State, now: datetime | None = None, *, quiet: bool = False) -> int:
    """Seconds until the next feed read (see feed_mode). Logs each change of mode."""
    seconds, reason = feed_mode(state, now)
    mode = "fast" if reason else "idle"
    if not quiet and mode != state.feed_mode:
        log.info("feed polling: every %s s (%s)", seconds, FEED_LOG_REASON.get(reason or "", "idle"))
        state.feed_mode = mode
    return seconds


def check_stale_feed(state: State) -> None:
    """El feed puede responder bien con datos viejos: entonces el motor no decide (ni va ni vuelve).
    Avisar al empezar y al terminar."""
    if state.feed is None:
        return
    stale = state.feed.is_stale()
    if stale and not state.feed_stale_alerted:
        state.feed_stale_alerted = True
        state.events.add(actor="auto", kind="alert", summary=tn(
            "Block feed is answering with old data (last update {time}): automatic switching is not deciding",
            time=i18n.format_when(state.feed.last_update, i18n.notify_lang())))
    elif not stale and state.feed_stale_alerted:
        state.feed_stale_alerted = False
        state.events.add(actor="auto", kind="alert", summary=tn("Block feed up to date again"))


async def refresh_calendar(state: State) -> None:
    was_down = state.calendar_error is not None
    try:
        previous = state.calendar.sources if state.calendar else {}
        state.calendar = await match_calendar.fetch_calendar(
            state.http, football_data_token=state.secrets.get("football_data_token"))
        state.calendar_error = None
        for source, result in state.calendar.sources.items():
            if result != "ok" and previous.get(source, "ok") == "ok":
                state.events.add(actor="auto", kind="alert", summary=tn("Calendar: {source} is not responding ({result}); using the other source",
                                                                                 source=source, result=result[:120]))
    except Exception as exc:  # fuente no oficial: si cae se sigue con el feed de bloqueos
        state.calendar_error = f"{type(exc).__name__}: {exc}"
        log.warning("match calendar unavailable: %s", state.calendar_error)
        if not was_down:
            state.events.add(actor="auto", kind="alert",
                             summary=tn("Match calendar unavailable ({error}): the preventive policy only uses the feed",
                                        error=type(exc).__name__))


async def run_engine(state: State) -> None:
    """Un ciclo de la conmutación automática (no se solapan dos ciclos)."""
    if state.engine_lock.locked():
        return
    async with state.engine_lock:
        def recheck(domain: str, target: str, hostnames: list[str]):
            expect_dns(state, domain, target, hostnames)
            if os.environ.get("MULTICDN_OFFLINE") != "1":
                asyncio.create_task(recheck_dns_soon(state))
        await failover.evaluate(state, on_switched=recheck)


# Sin bloqueo durante este tiempo antes de avisar de que ha terminado: el feed puede ir y venir.
BLOCK_END_GRACE = timedelta(minutes=10)


# Avisos de bloqueo guardados antes de 0.3.4, sin código: se reconocen por el texto en cada idioma.
LEGACY_BLOCK_START = ("Cloudflare IPs blocked", "IPs de Cloudflare bloqueadas")
LEGACY_BLOCK_END = ("Block ended", "Fin del bloqueo")


def restore_block_state(state: State) -> None:
    """Tras un reinicio, recupera del historial qué dominios ya tienen el aviso de bloqueo enviado."""
    codes = (event_codes.BLOCK_START, event_codes.BLOCK_END)
    for name in state.inventory.domains:
        last = state.events.last_with_code(name, codes)
        if last is None:  # historial anterior a los códigos
            legacy = next((e for e in state.events.list(domain=name, limit=200) if e.kind == "alert"
                           and e.summary.startswith(LEGACY_BLOCK_START + LEGACY_BLOCK_END)), None)
            if legacy and legacy.summary.startswith(LEGACY_BLOCK_START):
                state.blocked_domains.add(name)
        elif last.code == event_codes.BLOCK_START:
            state.blocked_domains.add(name)


def check_block_transitions(state: State, now: datetime | None = None) -> None:
    """Avisa cuando las IPs de Cloudflare de un dominio empiezan o dejan de estar bloqueadas.
    El fin solo se avisa tras BLOCK_END_GRACE seguido sin bloqueo."""
    now = now or datetime.now(UTC)
    if state.feed is None or state.dns_checked_at is None:
        return  # sin DNS comprobado el estado del dominio aún no es fiable
    pending_cf = any(d.cloudflare_credential and d.zone_id for d in state.inventory.domains.values())
    if pending_cf and state.cf_sync_at is None:
        return  # esperar a leer los registros reales (p. ej. un apex aplanado hacia Gcore)
    auto = failover.auto_enabled(state)
    for d in state.views():
        blocked = d.blocked_count > 0
        cfg = state.inventory.domains[d.name]
        is_auto = auto and failover.eligible(cfg) and cfg.gcore_resource_id
        if blocked:
            state.block_clear_since.pop(d.name, None)
        if blocked and d.name not in state.blocked_domains:
            state.blocked_domains.add(d.name)
            if d.status == "cloudflare":
                where = (tn("still on Cloudflare: automatic switching will switch it to Gcore") if is_auto
                         else tn("still on Cloudflare: consider switching to Gcore"))
            elif d.status == "gcore":
                where = tn("already served by Gcore")
            else:
                from .views import STATUS
                where = tn("current status: {status}", status=tn(STATUS[d.status][0]).lower())
            state.events.add(actor="auto", kind="alert", domain=d.name, code=event_codes.BLOCK_START,
                             summary=tnn("Cloudflare IPs blocked at {n} ISP; {where}", "Cloudflare IPs blocked at {n} ISPs; {where}",
                                         d.blocked_count, where=where),
                             signals=[tn("{isp}: blocked", isp=r.name) for r in d.isp_rows if r.state == "blocked"])
        elif not blocked and d.name in state.blocked_domains:
            clear_since = state.block_clear_since.setdefault(d.name, now)
            if now - clear_since < BLOCK_END_GRACE:
                continue
            state.block_clear_since.pop(d.name, None)
            state.blocked_domains.discard(d.name)
            if d.status in ("cloudflare", "unknown"):
                summary = tn("Block ended on its Cloudflare IPs")
            elif is_auto:
                mins = int(failover.return_after(state, cfg.priority).total_seconds() // 60)
                summary = tn("Block ended on its Cloudflare IPs; automatic return to Cloudflare after {mins} min without blocks",
                             mins=mins)
            else:
                summary = tn("Block ended on its Cloudflare IPs; it can now return to Cloudflare")
            state.events.add(actor="auto", kind="alert", domain=d.name, summary=summary, code=event_codes.BLOCK_END)


async def refresh_dns(state: State) -> None:
    if not state.cf_ranges:
        with suppress(Exception):
            state.cf_ranges = await dnscheck.fetch_cloudflare_ranges(state.http)
    hostnames = [h.name for d in state.inventory.domains.values() for h in d.hostnames]
    state.resolutions = await dnscheck.resolve_all(hostnames, state.cf_ranges, state.inventory.origin_ips)
    apply_cf_live(state)
    state.dns_checked_at = datetime.now(UTC)
    for name, domain in state.inventory.domains.items():
        ips = {ip for h in domain.hostnames if (r := state.resolutions.get(h.name)) and r.provider == "cloudflare" for ip in r.ips}
        state.engine.remember_ips(name, sorted(ips))
    check_block_transitions(state)
    check_propagation(state)
    await run_engine(state)
    for res in state.resolutions.values():
        exposed = res.provider == "origin"
        if exposed and res.hostname not in state.exposure_alerted:
            state.exposure_alerted.add(res.hostname)
            domain = next((n for n, d in state.inventory.domains.items() if any(h.name == res.hostname for h in d.hostnames)), None)
            state.events.add(
                actor="auto", kind="alert", domain=domain,
                summary=tn("{hostname} resolves to the origin IP (Cloudflare proxy disabled)", hostname=res.hostname),
                signals=[tn("Public DNS: A record without proxy")],
            )
        elif not exposed:
            state.exposure_alerted.discard(res.hostname)


async def refresh_cloudflare(state: State, alert: bool = True) -> None:
    """Lee los registros reales en Cloudflare (tipo, proxy, túnel) de los dominios con credencial.
    alert=False: no alerts (the terminal, app.cli, reads too; only the panel alerts)."""
    changed = False
    for name, domain in state.inventory.domains.items():
        token = state.creds.secret(domain.cloudflare_credential)
        if not token or not domain.zone_id:
            continue
        try:
            listed = await cf.list_web_records(token, domain.zone_id)
            records = {r["name"]: r for r in listed}
            state.cf_sync_errors.pop(name, None)
            # A + AAAA (o varios A) en un hostname que conmuta: Cloudflare no deja convertir uno en
            # CNAME mientras existan los otros, así que el cambio a Gcore fallaría en pleno bloqueo.
            counts = Counter(r["name"] for r in listed)
            multi = sorted(h.name for h in domain.hostnames if h.failover and counts[h.name] > 1)
            state.cf_multi_records[name] = multi
            state.cf_ok_at[name] = datetime.now(UTC)
        except (RuntimeError, ValueError, httpx.HTTPError) as exc:  # ValueError: a 5xx HTML page, not JSON
            state.cf_sync_errors[name] = error_reporting.scrub_origin(str(exc) or type(exc).__name__)[:200]
            continue
        for h in domain.hostnames:
            r = records.get(h.name)
            if r:
                state.cf_live[h.name] = {"to_backup": r.get("to_backup", False), "target": r.get("cname_target")}
            # Solo mientras sigue en Cloudflare: si ya apunta a Gcore, el registro actual no es el original.
            if r and r["proxied"] and (r["id"], r["origin_kind"], r["tunnel_target"], r["cname_target"]) != (
                    h.cloudflare_record_id, h.origin_kind, h.tunnel_target, h.cname_target):
                changed |= state.store.set_cloudflare_record(h.name, r["id"], r["origin_kind"], r["tunnel_target"], r["cname_target"])
    state.cf_sync_at = datetime.now(UTC)
    apply_cf_live(state)
    if changed:
        state.reload()
    if alert:
        check_cloudflare_read(state)


def check_cloudflare_read(state: State, now: datetime | None = None) -> None:
    """One alert per Cloudflare credential whose reads keep failing (after 8 min), and one when
    they work again: until then a switch to Gcore would fail too."""
    by_cred: dict[int, list[str]] = {}
    for name, domain in state.inventory.domains.items():
        if domain.cloudflare_credential and domain.zone_id and state.creds.secret(domain.cloudflare_credential):
            by_cred.setdefault(domain.cloudflare_credential, []).append(name)
    for cred_id, names in by_cred.items():
        try:
            label = state.creds.get(cred_id).label
        except ValueError:
            label = str(cred_id)
        failing = [n for n in names if n in state.cf_sync_errors]
        key = f"cf_read:{cred_id}"
        if failing:
            alerts.problem(state, key, tn(
                'Cloudflare cannot be read with the credential "{label}" ({error}): {n} domain(s) affected. '
                "Switching would fail; check the token in Settings",
                label=label, error=state.cf_sync_errors[failing[0]], n=len(failing)), after=CF_READ_AFTER, now=now)
        else:
            alerts.clear(state, key, lambda lasted, label=label: tn(
                'Cloudflare can be read again with the credential "{label}" (failing for {minutes} min)',
                label=label, minutes=alerts.minutes(lasted)), now=now)
    for key in alerts.active(state, "cf_read:"):  # credential no longer used by any domain: drop it
        if key.removeprefix("cf_read:") not in {str(c) for c in by_cred}:
            alerts.clear(state, key, now=now)


def apply_cf_live(state: State) -> None:
    """Cloudflare aplana el CNAME del dominio raíz: el DNS público solo muestra las IPs de Gcore.
    Si el registro real (API) es un CNAME sin proxy hacia Gcore, ese hostname está en Gcore."""
    for name, res in list(state.resolutions.items()):
        live = state.cf_live.get(name)
        if live and live["to_backup"] and res.provider == "other":
            state.resolutions[name] = replace(res, provider="gcore", cname=(live["target"] or "") + ".")


async def check_firewall(state: State) -> None:
    from . import firewall_status
    firewall_status.check(state)


async def daily_backup(state: State, now: datetime | None = None) -> None:
    """The daily copy of the database, checked right after: a copy nobody can restore is no copy."""
    from .backup import backup, verify
    try:
        path = await asyncio.to_thread(backup)
        problem = await asyncio.to_thread(verify, path)
    except Exception as exc:  # disk full, permissions…: alert instead of only logging
        path, problem = None, f"{type(exc).__name__}: {exc}"
    if problem:
        log.error("backup failed: %s", problem)
        alerts.problem(state, "backup", tn("The daily database backup failed: {problem}", problem=problem[:200]),
                       kind="error", now=now)
        return
    log.info("backup: %s (verified)", path)
    alerts.clear(state, "backup", tn("The daily database backup works again"), kind="alert", now=now)


async def prune_events(state: State) -> None:
    deleted = state.events.prune()
    if deleted:
        log.info("retention: %s old events deleted", deleted)


async def _delayed_loop(delay: int, interval: float | Callable[[], float], fn, *args) -> None:
    await asyncio.sleep(delay)  # no competir con el arranque
    await _loop(interval, fn, *args)


async def _loop(interval: float | Callable[[], float], fn: Callable[..., Awaitable[object]], *args: object) -> None:
    """interval: seconds, or a callable that returns them after each run (adaptive interval)."""
    while True:
        try:
            await fn(*args)
        except Exception:
            log.exception("background task %s failed", getattr(fn, "__name__", fn))
        try:
            wait = interval() if callable(interval) else interval
        except Exception:
            log.exception("interval of background task %s failed", getattr(fn, "__name__", fn))
            wait = FEED_FAST
        await asyncio.sleep(wait)


async def recheck_dns_soon(state: State) -> None:
    """Tras un cambio de CDN, comprobar el DNS público enseguida y unas cuantas veces más."""
    for delay in (10, 20, 30, 60):
        await asyncio.sleep(delay)
        try:
            await refresh_cloudflare(state)
            await refresh_dns(state)
        except Exception:
            log.exception("DNS re-check after a switch failed")


async def watch_gcore(state: State, now: datetime | None = None) -> None:
    """While a domain is served by Gcore (public DNS), check every 5 min that Gcore still serves it: the same
    checks as before a switch (resource active, edge resolves and answers HTTPS for each hostname).
    From the VPS this cannot see blocks inside Spanish ISPs, only Gcore failing for everyone."""
    for view in state.views():
        key = f"gcore_serving:{view.name}"
        if view.status != "gcore":
            alerts.clear(state, key, now=now)  # left Gcore: nothing to report
            continue
        problem = await failover.check_backup(state, view.name)
        if problem:
            alerts.problem(state, key, tn("Gcore is not serving {domain}: {problem}", domain=view.name, problem=problem),
                           domain=view.name, kind="error", after=GCORE_WATCH_AFTER, now=now)
        else:
            alerts.clear(state, key, lambda lasted, name=view.name: tn(
                "Gcore serves {domain} again (it failed for {minutes} min)", domain=name,
                minutes=alerts.minutes(lasted)), domain=view.name, now=now)


DNS_PROPAGATION_LIMIT = timedelta(minutes=30)
CDN_NAME = {"gcore": "Gcore", "cloudflare": "Cloudflare"}


def expect_dns(state: State, domain: str, target: str, hostnames: list[str], now: datetime | None = None) -> None:
    """After a real switch: note where the public DNS should end up, to measure how long it takes."""
    if hostnames:
        state.pending_dns[domain] = (target, hostnames, now or datetime.now(UTC))


def _seconds(delta: timedelta) -> str:
    total = max(0, round(delta.total_seconds()))
    return f"{total} s" if total < 60 else f"{total // 60} min {total % 60:02d} s"


def check_propagation(state: State, now: datetime | None = None) -> None:
    """Records in the history how long public DNS took to show each switch, and alerts if it still
    does not after DNS_PROPAGATION_LIMIT (a record that did not change, a resolver stuck on it)."""
    now = now or datetime.now(UTC)
    for domain, (target, hostnames, since) in list(state.pending_dns.items()):
        seen = {(r.provider if (r := state.resolutions.get(h)) else None) for h in hostnames}
        cdn = CDN_NAME.get(target, target)
        if seen == {target}:
            del state.pending_dns[domain]
            state.events.add(actor="auto", kind="verify", domain=domain, summary=tn(
                "Public DNS shows {domain} on {cdn} {time} after the switch", domain=domain, cdn=cdn,
                time=_seconds(now - since)))
        elif now - since > DNS_PROPAGATION_LIMIT:
            del state.pending_dns[domain]
            state.events.add(actor="auto", kind="alert", domain=domain, summary=tn(
                "Public DNS still does not show {domain} on {cdn} {minutes} min after the switch: check its "
                "records in Cloudflare", domain=domain, cdn=cdn, minutes=int(DNS_PROPAGATION_LIMIT.total_seconds() // 60)))


def gcore_ready_interval(state: State) -> int:
    """Every 6 h; every 10 min while some domain failed its last check."""
    failing = any(problem for _, problem in state.gcore_ready.values())
    return GCORE_READY_RETRY if failing else GCORE_READY_INTERVAL


async def check_gcore_ready(state: State, name: str, now: datetime | None = None) -> str | None:
    """Could Gcore serve this domain right now? The pre-switch checks (resource active, edge
    resolves, HTTPS answers with the real hostname, edge not blocked), without touching DNS."""
    problem = await failover.check_backup(state, name)
    state.gcore_ready[name] = (now or datetime.now(UTC), problem)
    return problem


async def check_gcore_readiness(state: State, now: datetime | None = None) -> None:
    """A drill without DNS changes: for each domain prepared on Gcore and still on Cloudflare, check
    that the backup would work, so a broken token, certificate or origin shows up before a match."""
    now = now or datetime.now(UTC)
    for view in state.views():
        cfg = state.inventory.domains[view.name]
        key = f"gcore_ready:{view.name}"
        if not cfg.gcore_resource_id or not view.gcore_ready or view.status == "gcore":
            alerts.clear(state, key, now=now)  # not prepared, or on Gcore (watch_gcore covers it)
            state.gcore_ready.pop(view.name, None)
            continue
        problem = await check_gcore_ready(state, view.name, now)
        if problem:
            alerts.problem(state, key, tn("Gcore could not serve {domain} if it had to switch now: {problem}",
                                          domain=view.name, problem=problem),
                           domain=view.name, after=timedelta(seconds=GCORE_READY_RETRY - 60), now=now)
        else:
            alerts.clear(state, key, lambda lasted, name=view.name: tn(
                "Gcore is ready to serve {domain} again (it was failing for {minutes} min)", domain=name,
                minutes=alerts.minutes(lasted)), domain=view.name, now=now)

