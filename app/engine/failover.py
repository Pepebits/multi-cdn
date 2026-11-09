"""Conmutación automática Cloudflare ⇄ Gcore.

Cada ciclo (tras leer el feed de bloqueos o comprobar el DNS) decide por dominio:

  - Pasar a Gcore si sus IPs de Cloudflare están bloqueadas en alguna operadora
    (política reactiva o preventiva) o si hay un bloqueo masivo de IPs de Cloudflare
    (solo preventiva). Antes comprueba que Gcore sirve cada hostname (HTTPS contra su
    borde con el SNI real) y que el borde no figura como bloqueado.
  - Volver a Cloudflare cuando lleva un tiempo sin ninguna de esas señales
    (45 min los críticos, 30 el resto).

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
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx

from ..providers import cloudflare as cf
from ..providers import gcore
from ..providers.cloudflare import OriginExposureError, plan_to_gcore
from ..signals.hayahora import ISPS

RETURN_AFTER = {"critical": timedelta(minutes=45), "medium": timedelta(minutes=30), "low": timedelta(minutes=30)}
MIN_GAP = timedelta(minutes=15)
FLAP_WINDOW, FLAP_MAX = timedelta(hours=6), 4
MANUAL_HOLD = timedelta(hours=1)
MASS_BLOCK = 50  # IPs de Cloudflare bloqueadas en ≥3 operadoras
# Política preventiva: antelación con la que se pasa a Gcore antes de cada partido.
MATCH_LEAD = {"critical": timedelta(minutes=45), "medium": timedelta(minutes=30), "low": timedelta(minutes=30)}

DNS_BEFORE = {
    "cloudflare": "Cloudflare proxied", "gcore": "CNAME → Gcore", "origin": "A → IP de origen (sin proxy)",
    "other": "otro destino", "unresolved": "sin resolver",
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
    last_error TEXT,                       -- último fallo avisado (para no repetirlo cada ciclo)
    hold_reason TEXT                       -- motivo de la pausa: manual | mantenimiento | demasiados cambios
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
        if "hold_reason" not in {r[1] for r in self.conn.execute("PRAGMA table_info(failover_state)")}:
            self.conn.execute("ALTER TABLE failover_state ADD COLUMN hold_reason TEXT")
        self._cache: dict[str, DomainState] = {}
        for row in self.conn.execute("SELECT domain, cf_ips, sim_backup, hold_until, paused, clear_since, switches,"
                                     " last_error, hold_reason FROM failover_state"):
            self._cache[row[0]] = DomainState(
                domain=row[0], cf_ips=json.loads(row[1]), sim_backup=None if row[2] is None else bool(row[2]), hold_until=_dt(row[3]),
                paused=bool(row[4]), clear_since=_dt(row[5]), switches=[datetime.fromisoformat(t) for t in json.loads(row[6])],
                last_error=row[7], hold_reason=row[8])

    def get(self, domain: str) -> DomainState:
        return self._cache.get(domain) or DomainState(domain)

    def save(self, st: DomainState) -> None:
        self._cache[st.domain] = st
        self.conn.execute(
            "INSERT INTO failover_state (domain, cf_ips, sim_backup, hold_until, paused, clear_since, switches, last_error,"
            " hold_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(domain) DO UPDATE SET cf_ips=excluded.cf_ips,"
            " sim_backup=excluded.sim_backup, hold_until=excluded.hold_until, paused=excluded.paused,"
            " clear_since=excluded.clear_since, switches=excluded.switches, last_error=excluded.last_error,"
            " hold_reason=excluded.hold_reason",
            (st.domain, json.dumps(st.cf_ips), None if st.sim_backup is None else int(st.sim_backup), st.hold_until and st.hold_until.isoformat(),
             int(st.paused), st.clear_since and st.clear_since.isoformat(),
             json.dumps([t.isoformat() for t in st.switches]), st.last_error, st.hold_reason))
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

    def resume(self, domain: str) -> None:
        st = self.get(domain)
        st.hold_until, st.paused, st.last_error, st.hold_reason = None, False, None, None
        self.save(st)


# ---------------------------------------------------------------- acciones DNS

class SwitchFailed(Exception):
    def __init__(self, message: str, diff: list):
        super().__init__(message)
        self.diff = diff


async def switch_to_gcore(state, name: str) -> tuple[list, bool]:
    """Pasa a Gcore los hostnames que conmutan. Devuelve (diff DNS, simulado)."""
    domain = state.inventory.domains[name]
    switchable = [h for h in domain.hostnames if h.failover]
    if not switchable:
        raise SwitchFailed("Ningún hostname está marcado para conmutar", [])
    missing = [h.name for h in switchable if not h.gcore_target]
    if missing:
        raise SwitchFailed(f"Gcore no configurado para: {', '.join(missing)}", [])
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
            diff.append([h.name, DNS_BEFORE.get(before.provider, before.provider) if before else "desconocido",
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
            diff.append([h.name, "CNAME → Gcore" if force_all else DNS_BEFORE.get(provider, provider), change.describe()])
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
            return f"no se pudo consultar el recurso en Gcore ({exc})"
        if status != "active":
            return f"el recurso de Gcore aún no está activo en todo el borde (estado «{status}»)"
    for h in (h for h in domain.hostnames if h.failover):
        if not h.gcore_target:
            return f"{h.name} no tiene destino Gcore (prepara el dominio en Gcore)"
        ips = await gcore.edge_ipv4s(h.gcore_target)
        if not ips:
            return f"no se resuelve el borde de Gcore {h.gcore_target}"
        blocked = [f"{ip} en {ISPS[isp]}" for ip in ips for isp in ISPS
                   if state.feed and (s := state.feed.state(ip, isp)) and s.blocked]
        if blocked:
            return f"el borde de Gcore también está bloqueado ({', '.join(blocked[:3])})"
        try:
            ok, detail = await gcore.probe_all_edges(h.gcore_target, h.name)
        except (OSError, asyncio.TimeoutError) as exc:
            ok, detail = False, f"{h.name}: sin respuesta del borde de Gcore ({type(exc).__name__})"
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
           match=None, feed_ok: bool = True) -> Decision:
    """Decisión pura (sin efectos) a partir del estado del dominio. Actualiza st.clear_since.

    match: partido en cuya ventana estamos (solo cuenta con política preventiva).
    feed_ok: con el feed caído o desactualizado no se sabe si hay bloqueo: se puede ir a
    Gcore por el calendario, pero nunca volver."""
    reasons = []
    if feed_ok and view.blocked_count:
        reasons.append(f"IPs de Cloudflare bloqueadas en {view.blocked_count} operadora{'s' if view.blocked_count != 1 else ''}")
    elif feed_ok and cfg.policy == "preventive" and mass >= MASS_BLOCK:
        reasons.append(f"bloqueo masivo en curso ({mass} IPs de Cloudflare bloqueadas)")
    if cfg.policy == "preventive" and match is not None:
        reasons.append(f"partido de {match.competition} ({match.name}, {_fmt(match.kickoff)})")
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
    if not reasons and feed_ok and on_backup and now - st.clear_since >= RETURN_AFTER[cfg.priority]:
        return Decision("return", [f"sin bloqueos desde las {_fmt(st.clear_since)}"])
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
    for view in build_all(state.inventory, state.resolutions, state.feed, state.engine.known_ips()):
        cfg = state.inventory.domains[view.name]
        if not eligible(cfg) or not any(h.failover for h in view.hosts):
            continue
        st = state.engine.get(view.name)
        match = calendar.active(now, MATCH_LEAD[cfg.priority]) if calendar else None
        decision = decide(view, cfg, st, dry_run=state.dry_run, mass=mass, now=now, match=match, feed_ok=feed_ok)
        if decision.action != "none" and not st.held(now):
            await _act(state, view, cfg, st, decision, now, on_switched)
        state.engine.save(st)


async def _act(state, view, cfg, st: DomainState, decision: Decision, now: datetime, on_switched) -> None:
    name = view.name
    st.switches = [t for t in st.switches if now - t < FLAP_WINDOW]
    if st.switches and now - max(st.switches) < MIN_GAP:
        return
    if len(st.switches) >= FLAP_MAX:
        st.paused = True
        st.hold_reason = "demasiados cambios"
        state.events.add(actor="auto", kind="alert", domain=name,
                         summary=f"Conmutación automática pausada: {len(st.switches)} cambios en 6 h. "
                                 "Revisa el dominio y reanúdala desde el panel")
        return
    signals = [f"{r.name}: bloqueada" for r in view.isp_rows if r.state == "blocked"]

    def fail(msg: str, diff=None) -> None:
        if msg != st.last_error:  # no repetir el mismo fallo cada ciclo
            st.last_error = msg
            state.events.add(actor="auto", kind="error", domain=name, summary=msg, dns_diff=diff or [], signals=signals)

    if decision.action == "switch":
        if not cfg.gcore_resource_id or not view.gcore_ready:
            return fail("Cambio automático a Gcore no posible: el dominio no está preparado en Gcore. Sigue en Cloudflare")
        problem = await check_backup(state, name)
        if problem:
            from ..origin_health import down_note
            return fail(f"Cambio automático a Gcore cancelado: {problem}{down_note(state, name)}. Sigue en Cloudflare")
        try:
            diff, simulated = await switch_to_gcore(state, name)
        except SwitchFailed as exc:
            return fail(f"Cambio automático a Gcore fallido: {exc}", exc.diff)
        st.sim_backup = True if simulated else None
        transition, summary = "CF → GCORE", "Cambio automático a Gcore: " + "; ".join(decision.reasons)
    else:
        try:
            diff, simulated = await return_to_cloudflare(state, name, force_all=state.dry_run and st.sim_backup is True)
        except SwitchFailed as exc:
            return fail(f"Vuelta automática a Cloudflare fallida: {exc}", exc.diff)
        st.sim_backup = False if simulated else None
        transition, summary = "GCORE → CF", "Vuelta automática a Cloudflare: " + "; ".join(decision.reasons)
    st.switches.append(now)
    st.last_error = None
    state.events.add(actor="auto", kind="switch", domain=name, transition=transition, summary=summary,
                     dns_diff=diff, signals=signals, simulated=simulated)
    if on_switched and not simulated:
        on_switched()


def describe(state, name: str, now: datetime | None = None) -> dict:
    """Texto del estado del automático para el panel."""
    now = now or datetime.now(UTC)
    cfg = state.inventory.domains[name]
    st = state.engine.get(name)
    if not auto_enabled(state):
        return {"tone": "neutral", "text": "Automático desactivado en Ajustes → Operación", "resumable": False}
    if cfg.policy == "manual":
        return {"tone": "neutral", "text": "Política manual: solo avisa, no cambia nada", "resumable": False}
    if not eligible(cfg):
        return {"tone": "warn", "text": "Sin credencial o zona de Cloudflare: no puede cambiar automáticamente", "resumable": False}
    if st.paused:
        text = "En mantenimiento hasta que lo reanudes" if st.hold_reason == "mantenimiento" \
            else "Pausado por demasiados cambios seguidos"
        return {"tone": "warn", "text": text, "resumable": True}
    if st.hold_until and now < st.hold_until:
        when = f"{st.hold_until.astimezone(UTC):%d/%m %H:%M} UTC" if st.hold_until - now > timedelta(hours=20) else f"las {_fmt(st.hold_until)}"
        why = "en mantenimiento" if st.hold_reason == "mantenimiento" else "por un cambio manual"
        return {"tone": "warn", "text": f"En pausa hasta {when} {why}", "resumable": True}
    text = "Activo: pasa a Gcore si se bloquean sus IPs de Cloudflare"
    calendar = getattr(state, "calendar", None)
    if cfg.policy == "preventive":
        text += f", hay un bloqueo masivo o empieza un partido ({int(MATCH_LEAD[cfg.priority].total_seconds() // 60)} min antes)"
        nxt = calendar.upcoming(now) if calendar else None
        if nxt:
            text += f". Próximo partido: {nxt.name}, {nxt.kickoff.astimezone(UTC):%d/%m %H:%M} UTC"
    on_backup = any((r := state.resolutions.get(h.name)) and r.provider == "gcore" for h in cfg.hostnames if h.failover)
    if state.dry_run and st.sim_backup is not None:
        on_backup = st.sim_backup
    match = calendar.active(now, MATCH_LEAD[cfg.priority]) if calendar and cfg.policy == "preventive" else None
    if on_backup and match:
        text = f"En Gcore durante el partido {match.name}; después espera {int(RETURN_AFTER[cfg.priority].total_seconds() // 60)} min sin bloqueos"
    elif on_backup and st.clear_since:
        text = f"En Gcore. Sin bloqueos desde las {_fmt(st.clear_since)}: vuelta a Cloudflare hacia las " \
               f"{_fmt(st.clear_since + RETURN_AFTER[cfg.priority])}"
    elif on_backup:
        text = f"En Gcore mientras dure el bloqueo; vuelve a Cloudflare tras {int(RETURN_AFTER[cfg.priority].total_seconds() // 60)} min sin bloqueos"
    if st.last_error:
        return {"tone": "error", "text": f"{text}. Último fallo: {st.last_error}", "resumable": True}
    return {"tone": "ok", "text": text, "resumable": False}


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
                    "text": f"Cambiando a {CDN_NAME[target]}… propagando DNS"}
    if not auto_enabled(state) or not eligible(cfg):
        return None
    st = state.engine.get(name)
    if st.held(now):
        return None
    on_backup = any((r := state.resolutions.get(h.name)) and r.provider == "gcore" for h in hosts)
    if state.dry_run and st.sim_backup is not None:
        on_backup = st.sim_backup
    calendar = getattr(state, "calendar", None)
    in_match = bool(calendar and cfg.policy == "preventive" and calendar.active(now, MATCH_LEAD[cfg.priority]))
    if on_backup and st.clear_since and not in_match:
        eta = st.clear_since + RETURN_AFTER[cfg.priority]
        if eta > now:
            return {"kind": "pending", "target": "cloudflare", "text": f"Vuelta a Cloudflare hacia las {_fmt(eta)}"}
    if not on_backup and cfg.policy == "preventive" and calendar:
        nxt = calendar.upcoming(now)
        if nxt and nxt.kickoff - MATCH_LEAD[cfg.priority] - now < UPCOMING_WINDOW:
            when = max(now, nxt.kickoff - MATCH_LEAD[cfg.priority])
            return {"kind": "pending", "target": "gcore", "text": f"Pasa a Gcore a las {_fmt(when)} ({nxt.name})"}
    return None
