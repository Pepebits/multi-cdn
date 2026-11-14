"""Conmutación automática Cloudflare ⇄ Gcore.

Cada ciclo (tras leer el feed de bloqueos o comprobar el DNS) decide por dominio:

  - Pasar a Gcore si sus IPs de Cloudflare están bloqueadas en alguna operadora
    (política reactiva o preventiva) o si hay un bloqueo masivo de IPs de Cloudflare
    (solo preventiva). Antes comprueba que Gcore sirve cada hostname (HTTPS contra su
    borde con el SNI real) y que el borde no figura como bloqueado.
  - Volver a Cloudflare cuando lleva un tiempo sin ninguna de esas señales (configurable
    por prioridad en Ajustes → Operación; ver DEFAULT_RETURN_AFTER).

Salvaguardas:
  - Política «manual»: nunca cambia nada, solo avisa.
  - Feed caído o desactualizado: no decide nada (ni ir ni volver).
  - Como mínimo 15 min entre cambios de un mismo dominio; con más de 4 cambios en 6 h
    se pausa el automático de ese dominio y avisa.
  - Un cambio hecho a mano desde el panel pausa el automático de ese dominio 1 h.
  - Si la comprobación previa de Gcore falla, no cambia: sigue en Cloudflare y avisa
    (nunca se recurre a exponer el origen).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx

from ..providers import cloudflare as cf
from ..providers import gcore
from ..providers.cloudflare import OriginExposureError, plan_to_gcore
from ..i18n import N_, tn, tnn, tr
from ..signals.hayahora import ISPS

log = logging.getLogger(__name__)

# Tiempos por prioridad, en minutos; se cambian en Ajustes → Operación. Valores por defecto
# sacados del historial del feed (15/09–08/11/2026, 6.103 fines de bloqueo y 95 partidos):
#  - una IP liberada se volvió a bloquear en menos de 15 min el 0,05 % de las veces y en menos
#    de 30 el 0,3 %: esperar más apenas protege y alarga el tiempo en Gcore;
#  - los bloqueos empiezan una mediana de 68 min antes del saque, y el 90 % dentro de las 2 h
#    previas: con 45 min de antelación el cambio preventivo llegaba tarde la mayoría de veces.
DEFAULT_RETURN_AFTER = {"critical": 20, "medium": 15, "low": 15}
DEFAULT_MATCH_LEAD = {"critical": 120, "medium": 90, "low": 90}
TIMING_LIMITS = {"return_after": (10, 180), "match_lead": (15, 240)}
TIMING_DEFAULTS = {"return_after": DEFAULT_RETURN_AFTER, "match_lead": DEFAULT_MATCH_LEAD}
PRIORITIES = ("critical", "medium", "low")
MIN_GAP = timedelta(minutes=15)
FLAP_WINDOW, FLAP_MAX = timedelta(hours=6), 4
MANUAL_HOLD = timedelta(hours=1)
MASS_BLOCK = 50  # IPs de Cloudflare bloqueadas en ≥3 operadoras


def timing_key(kind: str, priority: str) -> str:
    return f"{kind}_{priority}"


def timing(state, kind: str, priority: str) -> timedelta:
    """Espera para volver (return_after) o antelación antes de un partido (match_lead)."""
    default = TIMING_DEFAULTS[kind][priority]
    raw = state.events.get_value(timing_key(kind, priority)) if state is not None else None
    lo, hi = TIMING_LIMITS[kind]
    try:
        minutes = int(raw) if raw is not None else default
    except ValueError:
        minutes = default
    return timedelta(minutes=minutes if lo <= minutes <= hi else default)


def return_after(state, priority: str) -> timedelta:
    return timing(state, "return_after", priority)


def match_lead(state, priority: str) -> timedelta:
    return timing(state, "match_lead", priority)

DNS_BEFORE = {
    "cloudflare": "Cloudflare proxied", "gcore": "CNAME → Gcore", "origin": N_("A → origin IP (not proxied)"),
    "other": N_("other target"), "unresolved": N_("unresolved"),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS failover_state (
    domain TEXT PRIMARY KEY,
    cf_ips TEXT NOT NULL DEFAULT '[]',     -- últimas IPs de Cloudflare vistas (para seguir el bloqueo estando en Gcore)
    sim_backup INTEGER,                    -- modo simulación: 1/0 = el motor «cree» que está en Gcore/Cloudflare; NULL = el DNS real
    hold_until TEXT,                       -- pausa tras un cambio manual
    paused INTEGER NOT NULL DEFAULT 0,     -- pausa por demasiados cambios: hasta reanudar a mano
    clear_since TEXT,                      -- desde cuándo no hay señales de bloqueo
    switches TEXT NOT NULL DEFAULT '[]',   -- marcas de tiempo de los cambios automáticos recientes
    last_error TEXT,                       -- último fallo avisado (texto, para el panel)
    hold_reason TEXT,                      -- motivo de la pausa: manual | mantenimiento | demasiados cambios
    error_code TEXT                        -- tipo del último fallo avisado (para no repetirlo cada ciclo)
);
"""


@dataclass
class DomainState:
    domain: str
    cf_ips: list[str] = field(default_factory=list)
    sim_backup: bool | None = None  # solo en simulación; None = seguir el DNS real
    hold_until: datetime | None = None
    paused: bool = False
    clear_since: datetime | None = None
    switches: list[datetime] = field(default_factory=list)
    last_error: str | None = None
    hold_reason: str | None = None
    error_code: str | None = None

    def held(self, now: datetime) -> bool:
        return self.paused or (self.hold_until is not None and now < self.hold_until)


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class EngineStore:
    """Estado del motor por dominio, en la misma base de datos que el inventario."""

    def __init__(self, conn):
        self.conn = conn
        cols = {r[1]: r[3] for r in self.conn.execute("PRAGMA table_info(failover_state)")}
        if cols.get("sim_backup") == 1:  # primera versión: sim_backup NOT NULL; el estado se puede regenerar
            self.conn.execute("DROP TABLE failover_state")
        self.conn.executescript(SCHEMA)
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(failover_state)")}
        for col in ("hold_reason", "error_code"):
            if col not in cols:
                self.conn.execute(f"ALTER TABLE failover_state ADD COLUMN {col} TEXT")
        self._cache: dict[str, DomainState] = {}
        self.reload()

    def reload(self) -> None:
        """Vuelve a leer el estado de la base de datos: la terminal (app.cli switch) escribe en
        ella desde otro proceso, y su pausa de 1 h tiene que verla el panel."""
        cache = {}
        for row in self.conn.execute("SELECT domain, cf_ips, sim_backup, hold_until, paused, clear_since, switches,"
                                     " last_error, hold_reason, error_code FROM failover_state"):
            cache[row[0]] = DomainState(
                domain=row[0], cf_ips=json.loads(row[1]), sim_backup=None if row[2] is None else bool(row[2]), hold_until=_dt(row[3]),
                paused=bool(row[4]), clear_since=_dt(row[5]), switches=[datetime.fromisoformat(t) for t in json.loads(row[6])],
                last_error=row[7], hold_reason=row[8], error_code=row[9])
        self._cache = cache

    def held_now(self, domain: str, now: datetime) -> bool:
        """¿Está en pausa según la base de datos? Justo antes de tocar el DNS (otro proceso o una
        acción del panel ha podido pausarlo mientras se comprobaba Gcore)."""
        row = self.conn.execute("SELECT paused, hold_until FROM failover_state WHERE domain = ?", (domain,)).fetchone()
        if row is None:
            return False
        until = _dt(row[1])
        return bool(row[0]) or (until is not None and now < until)

    def get(self, domain: str) -> DomainState:
        return self._cache.get(domain) or DomainState(domain)

    def save(self, st: DomainState) -> None:
        self._cache[st.domain] = st
        self.conn.execute(
            "INSERT INTO failover_state (domain, cf_ips, sim_backup, hold_until, paused, clear_since, switches, last_error,"
            " hold_reason, error_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(domain) DO UPDATE SET cf_ips=excluded.cf_ips,"
            " sim_backup=excluded.sim_backup, hold_until=excluded.hold_until, paused=excluded.paused,"
            " clear_since=excluded.clear_since, switches=excluded.switches, last_error=excluded.last_error,"
            " hold_reason=excluded.hold_reason, error_code=excluded.error_code",
            (st.domain, json.dumps(st.cf_ips), None if st.sim_backup is None else int(st.sim_backup), st.hold_until and st.hold_until.isoformat(),
             int(st.paused), st.clear_since and st.clear_since.isoformat(),
             json.dumps([t.isoformat() for t in st.switches]), st.last_error, st.hold_reason, st.error_code))
        self.conn.commit()

    def forget(self, domain: str) -> None:
        self._cache.pop(domain, None)
        self.conn.execute("DELETE FROM failover_state WHERE domain = ?", (domain,))
        self.conn.commit()

    def known_ips(self) -> dict[str, list[str]]:
        return {d: st.cf_ips for d, st in self._cache.items() if st.cf_ips}

    def remember_ips(self, domain: str, ips: list[str]) -> None:
        st = self.get(domain)
        if ips and sorted(ips) != sorted(st.cf_ips):
            st.cf_ips = sorted(ips)
            self.save(st)

    def manual_change(self, domain: str, *, to_backup: bool, simulated: bool, now: datetime | None = None) -> None:
        """Un cambio hecho a mano manda: el automático de ese dominio espera 1 h."""
        st = self.get(domain)
        st.hold_until = (now or datetime.now(UTC)) + MANUAL_HOLD
        st.hold_reason = "manual"
        st.sim_backup = to_backup if simulated else None
        st.clear_since = None
        self.save(st)

    def maintenance(self, domain: str, until: datetime | None) -> None:
        """Pausa el automático de un dominio hasta `until` (None: hasta reanudar a mano)."""
        st = self.get(domain)
        if until is None:
            st.paused, st.hold_until = True, None
        else:
            st.paused, st.hold_until = False, until
        st.hold_reason = "mantenimiento"
        self.save(st)

    def clear_error(self, domain: str) -> None:
        """Descartar el último fallo avisado (sin tocar pausas ni el contador de cambios)."""
        st = self.get(domain)
        st.last_error = st.error_code = None
        self.save(st)

    def resume(self, domain: str) -> None:
        """Reanudar a mano: también olvida los cambios recientes, o la protección contra cambios
        en bucle volvería a pausarlo en el siguiente ciclo."""
        st = self.get(domain)
        st.hold_until, st.paused, st.hold_reason = None, False, None
        st.last_error = st.error_code = None
        st.switches = []
        self.save(st)


# ---------------------------------------------------------------- acciones DNS

def dns_before(provider: str) -> str:
    """Texto del estado DNS anterior para el diff del historial (idioma de las notificaciones)."""
    return tn(DNS_BEFORE[provider]) if provider in DNS_BEFORE else provider

class SwitchFailed(Exception):
    def __init__(self, message: str, diff: list):
        super().__init__(message)
        self.diff = diff


async def switch_to_gcore(state, name: str) -> tuple[list, bool]:
    """Pasa a Gcore los hostnames que conmutan. Devuelve (diff DNS, simulado)."""
    domain = state.inventory.domains[name]
    switchable = [h for h in domain.hostnames if h.failover]
    if not switchable:
        raise SwitchFailed(tn("No hostname is marked to switch"), [])
    missing = [h.name for h in switchable if not h.gcore_target]
    if missing:
        raise SwitchFailed(tn("Gcore not configured for: {hosts}", hosts=", ".join(missing)), [])
    from ..firewall_status import request_refresh
    request_refresh()  # que el firewall tenga los rangos de Gcore al día cuando llegue el tráfico
    client = state.cloudflare_for(domain)
    diff: list = []
    try:
        for h in switchable:
            before = state.resolutions.get(h.name)
            if before and before.provider == "gcore" and not client.dry_run:
                continue
            change = plan_to_gcore(h.name, h.gcore_target)
            await client.apply(domain.zone_id, h.cloudflare_record_id, change)
            diff.append([h.name, dns_before(before.provider) if before else tn("unknown"),
                         change.describe()])
    except (OriginExposureError, ValueError, RuntimeError, httpx.HTTPError) as exc:
        raise SwitchFailed(str(exc) or type(exc).__name__, diff) from exc
    return diff, client.dry_run


async def return_to_cloudflare(state, name: str, *, force_all: bool = False) -> tuple[list, bool]:
    """Restaura con proxy en Cloudflare los hostnames que no estén ya en Cloudflare.
    force_all: en simulación el DNS no ha cambiado; se simula la vuelta de los que conmutan."""
    domain = state.inventory.domains[name]
    client = state.cloudflare_for(domain)
    diff: list = []
    try:
        for h in domain.hostnames:
            current = state.resolutions.get(h.name)
            provider = current.provider if current else "unresolved"
            if provider == "cloudflare" and not (force_all and h.failover):
                continue
            server = state.inventory.servers.get(h.server)
            origin = server.origin_ipv4 if server else None
            change = cf.plan_restore(h, str(origin) if origin else None)
            await client.apply(domain.zone_id, h.cloudflare_record_id, change)
            diff.append([h.name, "CNAME → Gcore" if force_all else dns_before(provider), change.describe()])
    except (OriginExposureError, ValueError, RuntimeError, httpx.HTTPError) as exc:
        raise SwitchFailed(str(exc) or type(exc).__name__, diff) from exc
    return diff, client.dry_run


# ---------------------------------------------------------------- comprobaciones previas

async def check_backup(state, name: str) -> str | None:
    """None si Gcore puede servir el dominio; si no, el motivo."""
    domain = state.inventory.domains[name]
    token = state.creds.secret(domain.gcore_credential)
    if token and domain.gcore_resource_id:
        try:
            status = await gcore.resource_status(token, domain.gcore_resource_id)
        except (RuntimeError, httpx.HTTPError) as exc:
            return tn("could not query the resource on Gcore ({error})", error=exc)
        if status != "active":
            return tn("the Gcore resource is not active on the whole edge yet (status «{status}»)", status=status)
    for h in (h for h in domain.hostnames if h.failover):
        if not h.gcore_target:
            return tn("{host} has no Gcore target (prepare the domain on Gcore)", host=h.name)
        ips = await gcore.edge_ipv4s(h.gcore_target)
        if not ips:
            return tn("the Gcore edge {target} does not resolve", target=h.gcore_target)
        blocked = [tn("{ip} on {isp}", ip=ip, isp=ISPS[isp]) for ip in ips for isp in ISPS
                   if state.feed and (s := state.feed.state(ip, isp)) and s.blocked]
        if blocked:
            return tn("the Gcore edge is blocked too ({blocked})", blocked=", ".join(blocked[:3]))
        try:
            ok, detail = await gcore.probe_all_edges(h.gcore_target, h.name)
        except (OSError, asyncio.TimeoutError) as exc:
            ok, detail = False, tn("{host}: no response from the Gcore edge ({error})", host=h.name, error=type(exc).__name__)
        if not ok:
            return detail
    return None


# ---------------------------------------------------------------- motor

def auto_enabled(state) -> bool:
    return state.events.get_setting("auto_switch") == 1


def eligible(domain) -> bool:
    return domain.policy != "manual" and bool(domain.cloudflare_credential and domain.zone_id)


def _fmt(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%H:%M UTC")


@dataclass
class Decision:
    action: str  # switch | return | none
    reasons: list[str]


def decide(view, cfg, st: DomainState, *, dry_run: bool, mass: int, now: datetime,
           match=None, feed_ok: bool = True, wait: timedelta | None = None) -> Decision:
    """Decisión pura (sin efectos) a partir del estado del dominio. Actualiza st.clear_since.

    match: partido en cuya ventana estamos (solo cuenta con política preventiva).
    feed_ok: con el feed caído o desactualizado no se sabe si hay bloqueo: se puede ir a
    Gcore por el calendario, pero nunca volver.
    wait: tiempo sin bloqueos antes de volver (por defecto, el de su prioridad)."""
    wait = wait if wait is not None else timedelta(minutes=DEFAULT_RETURN_AFTER[cfg.priority])
    reasons = []
    if feed_ok and view.blocked_count:
        reasons.append(tnn("Cloudflare IPs blocked at {n} ISP", "Cloudflare IPs blocked at {n} ISPs", view.blocked_count))
    elif feed_ok and cfg.policy == "preventive" and mass >= MASS_BLOCK:
        reasons.append(tn("mass block underway ({count} Cloudflare IPs blocked)", count=mass))
    if cfg.policy == "preventive" and match is not None:
        reasons.append(tn("{competition} match ({match}, {time})", competition=match.competition, match=match.name,
                          time=_fmt(match.kickoff)))
    if reasons or not feed_ok:
        st.clear_since = None
    elif st.clear_since is None:
        st.clear_since = now
    hosts = [h for h in view.hosts if h.failover]
    on_backup = any(h.provider == "gcore" for h in hosts)
    on_cf = any(h.provider == "cloudflare" for h in hosts)
    if dry_run and st.sim_backup is not None:  # cambios simulados: el DNS real no se movió
        on_backup, on_cf = st.sim_backup, not st.sim_backup
    if reasons and on_cf:
        return Decision("switch", reasons)
    if not reasons and feed_ok and on_backup and now - st.clear_since >= wait:
        return Decision("return", [tn("no blocks since {time}", time=_fmt(st.clear_since))])
    return Decision("none", reasons)


async def evaluate(state, now: datetime | None = None, on_switched=None) -> None:
    """Un ciclo del motor. on_switched(): se llama tras un cambio real (p. ej. recomprobar el DNS)."""
    from ..views import build_all  # evita import circular

    now = now or datetime.now(UTC)
    if not auto_enabled(state) or state.dns_checked_at is None:
        return
    if any(eligible(d) for d in state.inventory.domains.values()) and state.cf_sync_at is None:
        return  # sin leer los registros reales de Cloudflare el estado no es fiable
    feed_ok = state.feed is not None and not state.feed.is_stale(now)
    calendar = getattr(state, "calendar", None)
    if calendar is not None and calendar.is_stale(now):
        calendar = None
    mass = state.feed.blocked_ips() if feed_ok else 0
    state.engine.reload()
    healthy = True
    for view in build_all(state.inventory, state.resolutions, state.feed, state.engine.known_ips()):
        cfg = state.inventory.domains.get(view.name)
        if cfg is None or not eligible(cfg) or not any(h.failover for h in view.hosts):
            continue
        # Un fallo inesperado en un dominio no debe dejar sin motor a los demás.
        try:
            st = state.engine.get(view.name)
            match = calendar.active(now, match_lead(state, cfg.priority)) if calendar else None
            decision = decide(view, cfg, st, dry_run=state.dry_run, mass=mass, now=now, match=match, feed_ok=feed_ok,
                              wait=return_after(state, cfg.priority))
            if decision.action == "none" and st.error_code:
                st.last_error = st.error_code = None  # ya no hace falta cambiar: el próximo fallo vuelve a avisar
            if decision.action != "none" and not st.held(now):
                await _act(state, view, cfg, st, decision, now, on_switched)
            if view.name in state.inventory.domains:  # no resucitar un dominio eliminado mientras tanto
                state.engine.save(st)
        except Exception:
            healthy = False
            log.exception("engine: unexpected error on %s", view.name)
    if healthy:
        state.engine_ok_at = now  # el latido externo avisa si deja de avanzar


async def _act(state, view, cfg, st: DomainState, decision: Decision, now: datetime, on_switched) -> None:
    name = view.name
    st.switches = [t for t in st.switches if now - t < FLAP_WINDOW]
    if st.switches and now - max(st.switches) < MIN_GAP:
        return
    if len(st.switches) >= FLAP_MAX:
        st.paused = True
        st.hold_reason = "demasiados cambios"
        state.events.add(actor="auto", kind="alert", domain=name,
                         summary=tn("Automatic switching paused: {count} switches in 6 h. "
                                    "Check the domain and resume it from the panel", count=len(st.switches)))
        return
    signals = [tn("{isp}: blocked", isp=r.name) for r in view.isp_rows if r.state == "blocked"]

    def fail(code: str, msg: str, diff=None) -> None:
        """Avisa una vez por tipo de fallo mientras dure la necesidad de cambiar (el detalle puede
        variar de un ciclo a otro); el texto del panel se mantiene al día."""
        if code != st.error_code:
            state.events.add(actor="auto", kind="error", domain=name, summary=msg, dns_diff=diff or [], signals=signals)
        st.error_code, st.last_error = code, msg

    def still_wanted() -> bool:
        """Tras la comprobación de Gcore (segundos): ¿sigue el dominio y no lo han pausado?"""
        return name in state.inventory.domains and not state.engine.held_now(name, now)

    if decision.action == "switch":
        if not cfg.gcore_resource_id or not view.gcore_ready:
            return fail("not_prepared", tn("Automatic switch to Gcore not possible: the domain is not prepared on Gcore. Stays on Cloudflare"))
        problem = await check_backup(state, name)
        if problem:
            from ..origin_health import down_note
            return fail("backup_check", tn("Automatic switch to Gcore cancelled: {problem}{note}. Stays on Cloudflare",
                                           problem=problem, note=down_note(state, name)))
        if not still_wanted():
            return
        try:
            diff, simulated = await switch_to_gcore(state, name)
        except SwitchFailed as exc:
            return fail("switch_failed", tn("Automatic switch to Gcore failed: {error}", error=exc), exc.diff)
        st.sim_backup = True if simulated else None
        transition, summary = "CF → GCORE", tn("Automatic switch to Gcore: {reasons}", reasons="; ".join(decision.reasons))
    else:
        try:
            diff, simulated = await return_to_cloudflare(state, name, force_all=state.dry_run and st.sim_backup is True)
        except SwitchFailed as exc:
            return fail("return_failed", tn("Automatic return to Cloudflare failed: {error}", error=exc), exc.diff)
        st.sim_backup = False if simulated else None
        transition, summary = "GCORE → CF", tn("Automatic return to Cloudflare: {reasons}", reasons="; ".join(decision.reasons))
    st.switches.append(now)
    st.last_error = st.error_code = None
    state.events.add(actor="auto", kind="switch", domain=name, transition=transition, summary=summary,
                     dns_diff=diff, signals=signals, simulated=simulated)
    if on_switched and not simulated:
        on_switched()


def describe(state, name: str, now: datetime | None = None) -> dict:
    """Estado del automático para el panel.

    tone: ok | warn | error | neutral; text: frase completa (ficha del dominio); short: aviso de
    una línea para el resumen y la lista (solo si hay algo que mirar); action: botón de la ficha,
    "resume" (quitar la pausa) o "clear" (descartar el último fallo)."""
    now = now or datetime.now(UTC)
    cfg = state.inventory.domains[name]
    st = state.engine.get(name)
    if not auto_enabled(state):
        return {"tone": "neutral", "text": tr("Automatic switching off in Settings → Operation"), "resumable": False, "action": None}
    if cfg.policy == "manual":
        return {"tone": "neutral", "text": tr("Manual policy: only alerts, never changes anything"), "resumable": False, "action": None}
    if not eligible(cfg):
        text = tr("No Cloudflare credential or zone: cannot switch automatically")
        return {"tone": "warn", "text": text, "short": text, "resumable": False, "action": None}
    if st.paused:
        text = tr("In maintenance until you resume it") if st.hold_reason == "mantenimiento" \
            else tr("Paused after too many switches in a row")
        return {"tone": "warn", "text": text, "short": text, "resumable": True, "action": "resume"}
    if st.hold_until and now < st.hold_until:
        maintenance = st.hold_reason == "mantenimiento"
        if st.hold_until - now > timedelta(hours=20):
            date = f"{st.hold_until.astimezone(UTC):%d/%m %H:%M} UTC"
            text = tr("Paused until {date} for maintenance", date=date) if maintenance \
                else tr("Paused until {date} after a manual change", date=date)
        else:
            time = _fmt(st.hold_until)
            text = tr("Paused until {time} for maintenance", time=time) if maintenance \
                else tr("Paused until {time} after a manual change", time=time)
        return {"tone": "warn", "text": text, "short": text, "resumable": True, "action": "resume"}
    calendar = getattr(state, "calendar", None)
    if cfg.policy == "preventive":
        text = tr("Active: switches to Gcore if its Cloudflare IPs get blocked, a mass block is underway or a match "
                  "starts ({minutes} min before)", minutes=int(match_lead(state, cfg.priority).total_seconds() // 60))
        nxt = calendar.upcoming(now) if calendar else None
        if nxt:
            text = tr("{text}. Next match: {match}, {when}", text=text, match=nxt.name,
                      when=f"{nxt.kickoff.astimezone(UTC):%d/%m %H:%M} UTC")
    else:
        text = tr("Active: switches to Gcore if its Cloudflare IPs get blocked")
    on_backup = any((r := state.resolutions.get(h.name)) and r.provider == "gcore" for h in cfg.hostnames if h.failover)
    if state.dry_run and st.sim_backup is not None:
        on_backup = st.sim_backup
    match = calendar.active(now, match_lead(state, cfg.priority)) if calendar and cfg.policy == "preventive" else None
    wait = int(return_after(state, cfg.priority).total_seconds() // 60)
    if on_backup and match:
        text = tr("On Gcore during the {match} match; then waits {minutes} min without blocks", match=match.name, minutes=wait)
    elif on_backup and st.clear_since:
        text = tr("On Gcore. No blocks since {since}: back to Cloudflare around {eta}", since=_fmt(st.clear_since),
                  eta=_fmt(st.clear_since + return_after(state, cfg.priority)))
    elif on_backup:
        text = tr("On Gcore while the block lasts; returns to Cloudflare after {minutes} min without blocks", minutes=wait)
    if st.last_error:
        # El fallo primero: es lo que hay que leer. No hay pausa que quitar: el botón lo descarta.
        return {"tone": "error", "text": tr("Last automatic switch failed: {error}. It retries while the need to switch "
                                            "lasts. {text}", error=st.last_error, text=text),
                "short": tr("Last automatic switch failed"), "resumable": True, "action": "clear"}
    return {"tone": "ok", "text": text, "resumable": False, "action": None}


CDN_NAME = {"gcore": "Gcore", "cloudflare": "Cloudflare"}
PROPAGATION_WINDOW = timedelta(minutes=30)
UPCOMING_WINDOW = timedelta(hours=6)


def change_indicator(state, name: str, now: datetime | None = None) -> dict | None:
    """Cambio en curso o previsto, para la lista de dominios y el resumen.

    - «propagating»: hubo un cambio real hace menos de 30 min y el DNS público de algún hostname
      que conmuta aún no apunta al destino.
    - «pending»: está en Gcore esperando el plazo sin bloqueos, o (preventiva) hay un partido en
      las próximas 6 h. No se muestra si el automático está en pausa o desactivado."""
    now = now or datetime.now(UTC)
    cfg = state.inventory.domains[name]
    hosts = [h for h in cfg.hostnames if h.failover]
    last = next((e for e in state.events.list(domain=name, limit=30) if e.kind == "switch" and not e.simulated), None)
    if last and now - last.ts < PROPAGATION_WINDOW and last.transition in ("CF → GCORE", "GCORE → CF"):
        target = "gcore" if last.transition.endswith("GCORE") else "cloudflare"
        waiting = [h.name for h in hosts if (r := state.resolutions.get(h.name)) is None or r.provider != target]
        if waiting:
            return {"kind": "propagating", "target": target,
                    "text": tr("Switching to {cdn}… propagating DNS", cdn=CDN_NAME[target])}
    if not auto_enabled(state) or not eligible(cfg):
        return None
    st = state.engine.get(name)
    if st.held(now):
        return None
    on_backup = any((r := state.resolutions.get(h.name)) and r.provider == "gcore" for h in hosts)
    if state.dry_run and st.sim_backup is not None:
        on_backup = st.sim_backup
    calendar = getattr(state, "calendar", None)
    lead = match_lead(state, cfg.priority)
    in_match = bool(calendar and cfg.policy == "preventive" and calendar.active(now, lead))
    if on_backup and st.clear_since and not in_match:
        eta = st.clear_since + return_after(state, cfg.priority)
        if eta > now:
            return {"kind": "pending", "target": "cloudflare", "when": eta,
                    "text": tr("Back to Cloudflare around {time}", time=_fmt(eta))}
    if not on_backup and cfg.policy == "preventive" and calendar:
        nxt = calendar.upcoming(now)
        if nxt and nxt.kickoff - lead - now < UPCOMING_WINDOW:
            when = max(now, nxt.kickoff - lead)
            return {"kind": "pending", "target": "gcore", "when": when,
                    "text": tr("Switches to Gcore at {time} ({match})", time=_fmt(when), match=nxt.name)}
    return None
