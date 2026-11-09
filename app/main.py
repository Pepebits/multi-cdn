"""Controlador Multi-CDN: panel web + tareas periódicas de observación."""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
from contextlib import asynccontextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup

from . import heartbeat, notify, origin_health
from .auth import AuthStore, totp_uri
from .gcore_setup import RENEW_BEFORE, Job, prepare_domain, renew_and_check
from .gcore_usage import refresh_usage
from .gcore_usage import human as human_bytes
from .notifier import Notifier
from .config import Domain, Inventory, load_dotenv, load_inventory
from .credentials import PROVIDERS, CredentialStore
from .db import EventStore
from .engine import failover
from .engine.failover import DNS_BEFORE, EngineStore, SwitchFailed
from .inventory_store import InventoryStore, origin_key
from .providers import cloudflare as cf
from .providers import gcore
from .providers.cloudflare import CloudflareDNS, OriginExposureError, plan_to_gcore
from .secrets_store import CREDENTIALS, SecretStore
from .signals import calendar as match_calendar
from .signals import dnscheck, hayahora
from .views import build_all, build_domain

log = logging.getLogger("multicdn")
WEB = Path(__file__).parent / "web"
FEED_INTERVAL = 90
DNS_INTERVAL = 60
CF_SYNC_INTERVAL = 300
PRUNE_INTERVAL = 6 * 3600
RENEW_INTERVAL = 24 * 3600
CALENDAR_INTERVAL = 3 * 3600
USAGE_INTERVAL = 3600
BACKUP_INTERVAL = 24 * 3600
FIREWALL_CHECK_INTERVAL = 600
HEARTBEAT_INTERVAL = 300
ORIGIN_HEALTH_INTERVAL = 120


@dataclass
class State:
    store: InventoryStore
    secrets: SecretStore
    creds: CredentialStore
    auth: AuthStore
    events: EventStore
    dry_run_env: bool
    inventory: Inventory = field(init=False)
    feed: hayahora.FeedSnapshot | None = None
    feed_error: str | None = None
    resolutions: dict = field(default_factory=dict)
    dns_checked_at: datetime | None = None
    cf_ranges: list = field(default_factory=list)
    exposure_alerted: set = field(default_factory=set)
    client: httpx.AsyncClient | None = None
    cf_sync_at: datetime | None = None
    cf_sync_errors: dict = field(default_factory=dict)  # dominio -> error
    jobs: dict = field(default_factory=dict)  # dominio -> Job de preparación en Gcore
    blocked_domains: set = field(default_factory=set)  # dominios con sus IPs de Cloudflare bloqueadas
    cf_live: dict = field(default_factory=dict)  # hostname -> registro actual en Cloudflare (to_backup, target)
    calendar: match_calendar.Calendar | None = None
    calendar_error: str | None = None
    gcore_usage: dict = field(default_factory=dict)  # credencial -> Usage
    stats_cache: dict = field(default_factory=dict)  # clave -> (momento, valor)
    last_beat: object | None = None  # último aviso externo enviado (heartbeat.Beat)
    origin_health: dict = field(default_factory=dict)  # servidor -> origin_health.OriginHealth
    engine: EngineStore = field(init=False)
    engine_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self) -> None:
        self.engine = EngineStore(self.store.conn)
        self.reload()

    def views(self):
        return build_all(self.inventory, self.resolutions, self.feed, self.engine.known_ips())

    def reload(self) -> None:
        self.inventory = self.store.load()

    @property
    def dry_run(self) -> bool:
        return self.dry_run_env

    def cloudflare_for(self, domain: Domain) -> CloudflareDNS:
        token = self.creds.secret(domain.cloudflare_credential)
        return CloudflareDNS(token, self.inventory.origin_ips, self.dry_run_env)


async def refresh_feed(state: State) -> None:
    was_down = state.feed_error is not None
    try:
        state.feed = await hayahora.fetch_feed(state.client)
        state.feed_error = None
    except Exception as exc:  # el feed no es oficial: nunca debe tumbar el controlador
        state.feed_error = f"{type(exc).__name__}: {exc}"
        log.warning("feed hayahora no disponible: %s", state.feed_error)
        if not was_down:
            state.events.add(actor="auto", kind="alert", summary=f"Feed de bloqueos no disponible ({type(exc).__name__})")
        return
    check_block_transitions(state)
    await run_engine(state)


async def refresh_calendar(state: State) -> None:
    was_down = state.calendar_error is not None
    try:
        previous = state.calendar.sources if state.calendar else {}
        state.calendar = await match_calendar.fetch_calendar(
            state.client, football_data_token=state.secrets.get("football_data_token"))
        state.calendar_error = None
        for source, result in state.calendar.sources.items():
            if result != "ok" and previous.get(source, "ok") == "ok":
                state.events.add(actor="auto", kind="alert", summary=f"Calendario: {source} no responde ({result[:120]}); se usa la otra fuente")
    except Exception as exc:  # fuente no oficial: si cae se sigue con el feed de bloqueos
        state.calendar_error = f"{type(exc).__name__}: {exc}"
        log.warning("calendario de partidos no disponible: %s", state.calendar_error)
        if not was_down:
            state.events.add(actor="auto", kind="alert",
                             summary=f"Calendario de partidos no disponible ({type(exc).__name__}): la política preventiva solo usa el feed")


async def run_engine(state: State) -> None:
    """Un ciclo de la conmutación automática (no se solapan dos ciclos)."""
    if state.engine_lock.locked():
        return
    async with state.engine_lock:
        def recheck():
            if os.environ.get("MULTICDN_OFFLINE") != "1":
                asyncio.create_task(recheck_dns_soon(state))
        await failover.evaluate(state, on_switched=recheck)


BLOCK_START, BLOCK_END = "IPs de Cloudflare bloqueadas", "Fin del bloqueo"


def restore_block_state(state: State) -> None:
    """Tras un reinicio, recupera del historial qué dominios ya tienen el aviso de bloqueo enviado."""
    for name in state.inventory.domains:
        last = next((e for e in state.events.list(domain=name, limit=200)
                     if e.kind == "alert" and e.summary.startswith((BLOCK_START, BLOCK_END))), None)
        if last and last.summary.startswith(BLOCK_START):
            state.blocked_domains.add(name)


def check_block_transitions(state: State) -> None:
    """Avisa cuando las IPs de Cloudflare de un dominio empiezan o dejan de estar bloqueadas."""
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
        if blocked and d.name not in state.blocked_domains:
            state.blocked_domains.add(d.name)
            on_cf = "sigue en Cloudflare: el cambio automático lo pasa a Gcore" if is_auto else "sigue en Cloudflare: considera pasar a Gcore"
            where = {"cloudflare": on_cf, "gcore": "ya se sirve por Gcore"}.get(d.status, f"estado actual: {d.status_label.lower()}")
            state.events.add(actor="auto", kind="alert", domain=d.name,
                             summary=f"{BLOCK_START} en {d.blocked_count} operadora{'s' if d.blocked_count != 1 else ''}; {where}",
                             signals=[f"{r.name}: bloqueada" for r in d.isp_rows if r.state == "blocked"])
        elif not blocked and d.name in state.blocked_domains:
            state.blocked_domains.discard(d.name)
            extra = ""
            if d.status not in ("cloudflare", "unknown"):
                mins = int(failover.RETURN_AFTER[cfg.priority].total_seconds() // 60)
                extra = f"; vuelta automática a Cloudflare tras {mins} min sin bloqueos" if is_auto else "; ya se puede volver a Cloudflare"
            state.events.add(actor="auto", kind="alert", domain=d.name, summary=f"{BLOCK_END} de sus IPs de Cloudflare{extra}")


async def refresh_dns(state: State) -> None:
    if not state.cf_ranges:
        with suppress(Exception):
            state.cf_ranges = await dnscheck.fetch_cloudflare_ranges(state.client)
    hostnames = [h.name for d in state.inventory.domains.values() for h in d.hostnames]
    state.resolutions = await dnscheck.resolve_all(hostnames, state.cf_ranges, state.inventory.origin_ips)
    apply_cf_live(state)
    state.dns_checked_at = datetime.now(UTC)
    for name, domain in state.inventory.domains.items():
        ips = {ip for h in domain.hostnames if (r := state.resolutions.get(h.name)) and r.provider == "cloudflare" for ip in r.ips}
        state.engine.remember_ips(name, sorted(ips))
    check_block_transitions(state)
    await run_engine(state)
    for res in state.resolutions.values():
        exposed = res.provider == "origin"
        if exposed and res.hostname not in state.exposure_alerted:
            state.exposure_alerted.add(res.hostname)
            domain = next((n for n, d in state.inventory.domains.items() if any(h.name == res.hostname for h in d.hostnames)), None)
            state.events.add(
                actor="auto", kind="alert", domain=domain,
                summary=f"{res.hostname} resuelve a la IP de origen (proxy de Cloudflare desactivado)",
                signals=["DNS público: registro A sin proxy"],
            )
        elif not exposed:
            state.exposure_alerted.discard(res.hostname)


async def refresh_cloudflare(state: State) -> None:
    """Lee los registros reales en Cloudflare (tipo, proxy, túnel) de los dominios con credencial."""
    changed = False
    for name, domain in state.inventory.domains.items():
        token = state.creds.secret(domain.cloudflare_credential)
        if not token or not domain.zone_id:
            continue
        try:
            records = {r["name"]: r for r in await cf.list_web_records(token, domain.zone_id)}
            state.cf_sync_errors.pop(name, None)
        except (RuntimeError, httpx.HTTPError) as exc:
            state.cf_sync_errors[name] = str(exc) or type(exc).__name__
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


async def daily_backup(state: State) -> None:
    from .backup import backup
    path = await asyncio.to_thread(backup)
    log.info("copia de seguridad: %s", path)


async def prune_events(state: State) -> None:
    deleted = state.events.prune()
    if deleted:
        log.info("retención: %s eventos antiguos eliminados", deleted)


async def _delayed_loop(delay: int, interval: int, fn, *args) -> None:
    await asyncio.sleep(delay)  # no competir con el arranque
    await _loop(interval, fn, *args)


async def _loop(interval: int, fn, *args) -> None:
    while True:
        with suppress(Exception):
            await fn(*args)
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_dotenv()
    db_path = os.environ.get("MULTICDN_DB", "data/multicdn.db")
    secrets = SecretStore(db_path)
    store = InventoryStore(secrets)
    creds = CredentialStore(secrets)
    for provider, env in (("cloudflare", "CLOUDFLARE_API_TOKEN"), ("gcore", "GCORE_API_TOKEN")):
        if os.environ.get(env) and not creds.list(provider):
            creds.add(provider, "Importada del entorno", os.environ[env])
    if store.is_empty():
        # Primer arranque: importar inventory.yaml (o el ejemplo) si existe.
        with suppress(FileNotFoundError):
            store.import_inventory(load_inventory())
    events = EventStore(db_path)
    events.listeners.append(Notifier(secrets))
    state = State(
        store=store, secrets=secrets, creds=creds, auth=AuthStore(secrets), events=events,
        dry_run_env=os.environ.get("MULTICDN_DRY_RUN", "true").lower() != "false",
    )
    state.client = httpx.AsyncClient(headers={"User-Agent": "multicdn-controller"})
    app.state.mc = state
    restore_block_state(state)
    state.auth.purge_expired()
    await prune_events(state)
    tasks = []
    if os.environ.get("MULTICDN_OFFLINE") != "1":
        tasks = [
            asyncio.create_task(_loop(CALENDAR_INTERVAL, refresh_calendar, state)),
            asyncio.create_task(_loop(FEED_INTERVAL, refresh_feed, state)),
            asyncio.create_task(_loop(DNS_INTERVAL, refresh_dns, state)),
            asyncio.create_task(_loop(CF_SYNC_INTERVAL, refresh_cloudflare, state)),
            asyncio.create_task(_loop(PRUNE_INTERVAL, prune_events, state)),
            asyncio.create_task(_delayed_loop(300, RENEW_INTERVAL, renew_and_check, state)),
            asyncio.create_task(_delayed_loop(20, USAGE_INTERVAL, refresh_usage, state)),
            asyncio.create_task(_delayed_loop(600, BACKUP_INTERVAL, daily_backup, state)),
            asyncio.create_task(_loop(FIREWALL_CHECK_INTERVAL, check_firewall, state)),
            asyncio.create_task(_delayed_loop(120, HEARTBEAT_INTERVAL, heartbeat.beat, state)),
            asyncio.create_task(_delayed_loop(15, ORIGIN_HEALTH_INTERVAL, origin_health.check, state)),
        ]
    yield
    for t in tasks:
        t.cancel()
    await state.client.aclose()


SESSION_COOKIE = "mcdn_session"
PUBLIC_PREFIXES = ("/login", "/static/", "/healthz")
current_csrf: ContextVar[str] = ContextVar("current_csrf", default="")
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'")


async def csrf_protect(request: Request) -> None:
    """Todos los POST autenticados llevan el token CSRF de la sesión."""
    if request.method != "POST" or request.url.path.startswith("/login"):
        return
    form = await request.form()  # Starlette lo cachea: las rutas lo reutilizan
    session = getattr(request.state, "session", None)
    token = str(form.get("csrf", ""))
    if session is None or not token or not hmac.compare_digest(token, session.csrf):
        raise HTTPException(403, "Token CSRF no válido: recarga la página e inténtalo de nuevo")


app = FastAPI(title="Multi-CDN", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None,
              dependencies=[Depends(csrf_protect)])
app.mount("/static", StaticFiles(directory=WEB / "static"), name="static")
templates = Jinja2Templates(directory=WEB / "templates")


def _safe_next(value: str | None) -> str:
    return value if value and value.startswith("/") and not value.startswith("//") and "\\" not in value else "/"


@app.middleware("http")
async def security(request: Request, call_next):
    """Origen de los POST, sesión obligatoria fuera de /login y cabeceras de seguridad."""
    if request.method == "POST":
        source = request.headers.get("origin") or request.headers.get("referer")
        if source and urlparse(source).netloc != request.url.netloc:
            return PlainTextResponse("Origen no permitido", status_code=403)
        if not source and os.environ.get("MULTICDN_OFFLINE") != "1":
            return PlainTextResponse("Falta la cabecera Origin", status_code=403)
    state: State = request.app.state.mc
    # El sondeo automático (/api/) no renueva la sesión: la inactividad sigue contando.
    session = state.auth.get_session(request.cookies.get(SESSION_COOKIE), touch=not request.url.path.startswith("/api/"))
    request.state.session = session if session and session.stage == "full" else None
    request.state.pending = session if session and session.stage != "full" else None
    path = request.url.path
    if request.state.session is None and not path.startswith(PUBLIC_PREFIXES):
        if path.startswith("/api/"):
            return JSONResponse({"error": "sesión caducada"}, status_code=401)
        if request.method == "GET":
            target = path + (f"?{request.url.query}" if request.url.query else "")
            return RedirectResponse(f"/login?{urlencode({'next': target})}", status_code=303)
        return PlainTextResponse("Sesión no válida o caducada", status_code=401)
    if request.state.session:
        current_csrf.set(request.state.session.csrf)
    response: Response = await call_next(request)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Content-Security-Policy", CSP)
    if not path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def _back(url, anchor: str = "", **params) -> RedirectResponse:
    """Vuelve a `url` con el mensaje en la query; el ancla va después (si no, se pierde la query)."""
    query = urlencode({k: v for k, v in params.items() if v})
    target = f"{url}?{query}" if query else str(url)
    return RedirectResponse(target + (f"#{anchor}" if anchor else ""), status_code=303)


def _actor(request: Request) -> str:
    session = getattr(request.state, "session", None)
    return session.user.username if session else "panel"


def _fmt_time(value: datetime | None) -> str:
    return value.astimezone(UTC).strftime("%H:%M UTC") if value else "—"


def _fmt_datetime(value: datetime | None) -> str:
    return value.astimezone(UTC).strftime("%d/%m %H:%M UTC") if value else "—"


templates.env.filters["hhmm"] = _fmt_time
templates.env.filters["dt"] = _fmt_datetime
templates.env.filters["bytes"] = human_bytes


def _asset(path: str) -> str:
    """URL de un fichero estático con su versión (hash del contenido): un cambio en el CSS o el JS
    llega al navegador aunque tenga la versión anterior en caché."""
    file = WEB / "static" / path
    try:
        stat = file.stat()
        key = (path, stat.st_mtime_ns, stat.st_size)
        if key not in _ASSET_CACHE:
            import hashlib
            _ASSET_CACHE[key] = hashlib.sha256(file.read_bytes()).hexdigest()[:10]
        return f"/static/{path}?v={_ASSET_CACHE[key]}"
    except OSError:
        return f"/static/{path}"


_ASSET_CACHE: dict = {}
templates.env.globals["asset"] = _asset
templates.env.globals["current_year"] = lambda: datetime.now(UTC).year
templates.env.globals["csrf_field"] = lambda: Markup('<input type="hidden" name="csrf" value="{}">').format(current_csrf.get())


def _state(request: Request) -> State:
    return request.app.state.mc


def access_channel(request: Request) -> dict:
    """Por dónde ha llegado esta petición, deducido de la dirección usada (no se puede ver si el
    canal está cifrado, pero sí si el panel se ha publicado con un nombre que no debería)."""
    host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]").lower()
    if request.headers.get("tailscale-user-login") or host.endswith(".ts.net"):
        return {"tone": "ok", "label": "Acceso por Tailscale",
                "help": "La petición llega por tailscale serve (nombre *.ts.net o identidad de Tailscale)."}
    if host in ("localhost", "127.0.0.1", "::1"):
        return {"tone": "ok", "label": "Acceso por túnel SSH o local",
                "help": "Se ha entrado por localhost: un túnel SSH o el propio servidor."}
    return {"tone": "warn", "label": f"Acceso por {host or 'dirección desconocida'}: comprueba que no está expuesto",
            "help": "El panel debería escuchar solo en 127.0.0.1 y usarse por túnel SSH o red privada."}


def _common(request: Request, active: str, **extra) -> dict:
    s = _state(request)
    blocked = s.feed.blocked_ips() if s.feed else None
    return {
        "request": request,
        "active": active,
        "feed": s.feed,
        "feed_error": s.feed_error,
        "feed_stale": s.feed.is_stale() if s.feed else True,
        "blocked_cf_ips": blocked,
        "mass_block": blocked is not None and blocked >= 50,
        "dry_run": s.dry_run,
        "dns_checked_at": s.dns_checked_at,
        "isp_keys": {display: key for key, display in hayahora.ISPS.items()},
        "user": request.state.session.user if getattr(request.state, "session", None) else None,
        "access": access_channel(request),
        "state_version": state_version(s),
        "flash_ok": request.query_params.get("ok"),
        "flash_error": request.query_params.get("error"),
    } | extra


def state_version(s: State) -> str:
    """Huella de lo que muestra el panel: cambia cuando hay algo nuevo que ver."""
    import hashlib
    domains = s.views()
    parts = [f"{d.name}:{d.status}:{','.join(h.provider for h in d.hosts)}:{','.join(r.state for r in d.isp_rows)}"
             f":{(failover.change_indicator(s, d.name) or {}).get('text', '')}" for d in domains]
    last = s.events.list(limit=1)
    parts += [str(s.feed.last_update if s.feed else ""), str(last[0].id if last else 0),
              str({k: (j.done, len(j.lines)) for k, j in s.jobs.items()})]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


async def recheck_dns_soon(state: State) -> None:
    """Tras un cambio de CDN, comprobar el DNS público enseguida y unas cuantas veces más."""
    for delay in (10, 20, 30, 60):
        await asyncio.sleep(delay)
        with suppress(Exception):
            await refresh_cloudflare(state)
            await refresh_dns(state)


async def _after_inventory_change(state: State) -> None:
    state.reload()
    if os.environ.get("MULTICDN_OFFLINE") != "1":
        asyncio.create_task(refresh_dns(state))
        asyncio.create_task(refresh_cloudflare(state))


# ---------------------------------------------------------------- Resumen

@app.get("/", response_class=HTMLResponse)
async def resumen(request: Request):
    s = _state(request)
    domains = s.views()
    return templates.TemplateResponse(request, "resumen.html", _common(
        request, "resumen",
        domains=domains,
        exposed=[d for d in domains if d.status == "origin"],
        changes={d.name: failover.change_indicator(s, d.name) for d in domains},
        events=s.events.list(limit=5),
        origin_configured=bool(s.inventory.origin_ips),
        origin_health=list(s.origin_health.values()),
        gcore_configured=any(d.gcore_ready for d in domains),
        usage=list(s.gcore_usage.values()),
        match_now=s.calendar.active(datetime.now(UTC), failover.MATCH_LEAD["critical"]) if s.calendar else None,
        match_next=s.calendar.upcoming(datetime.now(UTC)) if s.calendar else None,
        calendar_error=s.calendar_error,
    ))


# ---------------------------------------------------------------- Dominios

@app.get("/dominios", response_class=HTMLResponse)
async def dominios(request: Request):
    s = _state(request)
    return templates.TemplateResponse(request, "dominios.html", _common(
        request, "dominios",
        domains=s.views(),
        changes={n: failover.change_indicator(s, n) for n in s.inventory.domains},
        servers=list(s.inventory.servers),
        cf_creds=s.creds.list("cloudflare"),
    ))


@app.post("/dominios")
async def crear_dominio(
    request: Request, name: str = Form(...), priority: str = Form("medium"), policy: str = Form("reactive"),
    server: str = Form(...), hostnames: str = Form(""),
):
    s = _state(request)
    url = request.url_for("dominios")
    try:
        domain = s.store.upsert_domain(name, policy=policy, priority=priority)
        hosts = [h for h in hostnames.split() if h] or [domain, f"www.{domain}"]
        for h in hosts:
            s.store.upsert_hostname(domain, h, server=server)
    except ValueError as exc:
        return _back(url, error=str(exc))
    s.events.add(actor=_actor(request), kind="config", domain=domain, summary=f"Dominio añadido con {len(hosts)} hostnames")
    await _after_inventory_change(s)
    return _back(request.url_for("dominio", name=domain), ok="Dominio añadido")


@app.get("/dominios/importar", response_class=HTMLResponse)
async def importar(request: Request, cuenta: int | None = None, zone: str | None = None):
    s = _state(request)
    cf_creds = s.creds.list("cloudflare")
    if not cf_creds:
        return _back(request.url_for("ajustes_cuentas"), error="Añade primero una credencial de Cloudflare")
    if cuenta is None or cuenta not in {c.id for c in cf_creds}:
        cuenta = cf_creds[0].id
    token = s.creds.secret(cuenta)
    ctx = {"zones": [], "records": [], "zone": None, "servers": list(s.inventory.servers), "load_error": None,
           "cf_creds": cf_creds, "cuenta": cuenta}
    try:
        ctx["zones"] = await cf.list_zones(token)
        if zone:
            ctx["zone"] = next((z for z in ctx["zones"] if z["id"] == zone), None)
            if ctx["zone"]:
                ctx["records"] = await cf.list_web_records(token, zone)
    except (RuntimeError, httpx.HTTPError) as exc:
        ctx["load_error"] = str(exc)
    existing = {h.name for d in s.inventory.domains.values() for h in d.hostnames}
    return templates.TemplateResponse(request, "importar.html", _common(request, "dominios", existing=existing, **ctx))


@app.post("/dominios/importar")
async def importar_guardar(request: Request):
    s = _state(request)
    form = await request.form()
    try:
        cuenta = int(str(form.get("cuenta", "")))
        s.creds.get(cuenta)
    except ValueError:
        return _back(request.url_for("dominios"), error="Credencial de Cloudflare no válida")
    token = s.creds.secret(cuenta)
    zone_id = str(form.get("zone_id", ""))
    if not token or not zone_id:
        return _back(request.url_for("dominios"), error="Falta la credencial o la zona")
    zones = {z["id"]: z for z in await cf.list_zones(token)}
    if zone_id not in zones:
        return _back(request.url_for("importar"), error="Zona no encontrada en la cuenta")
    records = {r["id"]: r for r in await cf.list_web_records(token, zone_id)}
    chosen = [records[rid] for rid in form.getlist("record") if rid in records]
    if not chosen:
        return _back(request.url_for("importar"), cuenta=cuenta, zone=zone_id, error="Selecciona al menos un registro")
    domain = zones[zone_id]["name"]
    try:
        s.store.upsert_domain(domain, policy=str(form.get("policy", "reactive")),
                              priority=str(form.get("priority", "medium")), zone_id=zone_id)
        current = s.inventory.domains.get(domain)
        s.store.set_credentials(domain, cuenta, current.gcore_credential if current else None)
        for r in chosen:
            s.store.upsert_hostname(domain, r["name"], server=str(form.get("server", "")), cloudflare_record_id=r["id"])
            s.store.set_cloudflare_record(r["name"], r["id"], r["origin_kind"], r["tunnel_target"], r["cname_target"])
    except ValueError as exc:
        return _back(request.url_for("importar"), cuenta=cuenta, zone=zone_id, error=str(exc))
    s.events.add(actor=_actor(request), kind="config", domain=domain,
                 summary=f"Importados {len(chosen)} hostnames desde Cloudflare")
    await _after_inventory_change(s)
    return _back(request.url_for("dominio", name=domain), ok=f"Importados {len(chosen)} hostnames desde Cloudflare")


@app.get("/dominios/{name}", response_class=HTMLResponse)
async def dominio(request: Request, name: str):
    s = _state(request)
    if name not in s.inventory.domains:
        raise HTTPException(404, "Dominio no inventariado")
    view = build_domain(name, s.inventory.domains[name], s.resolutions, s.feed, s.engine.get(name).cf_ips)
    if name in s.cf_sync_errors:
        view.alerts.append(f"No se pudieron leer sus registros en Cloudflare: {s.cf_sync_errors[name]}")
    return templates.TemplateResponse(request, "dominio.html", _common(
        request, "dominios", d=view, cfg=s.inventory.domains[name],
        servers=list(s.inventory.servers), events=s.events.list(domain=name, limit=10),
        cf_creds=s.creds.list("cloudflare"), gc_creds=s.creds.list("gcore"), job=s.jobs.get(name),
        auto=failover.describe(s, name), maintenance_options=MAINTENANCE_OPTIONS,
        origin_header=origin_header_view(s, name),
        inventory_servers={sid: bool(srv.origin_ipv4) for sid, srv in s.inventory.servers.items()},
        renew_from=(datetime.fromisoformat(s.inventory.domains[name].cert_not_after) - RENEW_BEFORE
                    if s.inventory.domains[name].cert_not_after else None),
    ))


@app.post("/dominios/{name}/hostnames/{host}/quitar")
async def hostname_quitar(request: Request, name: str, host: str):
    s = _state(request)
    url = request.url_for("dominio", name=name)
    domain = s.inventory.domains.get(name)
    if domain is None or host not in {h.name for h in domain.hostnames}:
        raise HTTPException(404)
    if len(domain.hostnames) == 1:
        return _back(url, error="Es el último hostname: elimina el dominio completo si ya no quieres vigilarlo")
    s.store.delete_hostname(host)
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=f"{host} quitado del inventario (DNS sin cambios)")
    await _after_inventory_change(s)
    return _back(url, ok=f"{host} quitado del inventario. Su DNS no se ha modificado.")


@app.post("/dominios/{name}/configuracion")
async def dominio_config(
    request: Request, name: str, priority: str = Form(...), policy: str = Form(...), zone_id: str = Form(""),
    cloudflare_credential: str = Form(""), gcore_credential: str = Form(""),
):
    s = _state(request)
    url = request.url_for("dominio", name=name)
    if name not in s.inventory.domains:
        raise HTTPException(404)
    try:
        ids = {}
        for provider, raw in (("cloudflare", cloudflare_credential), ("gcore", gcore_credential)):
            ids[provider] = int(raw) if raw else None
            if ids[provider] is not None and s.creds.get(ids[provider]).provider != provider:
                raise ValueError("credencial de proveedor incorrecto")
        s.store.upsert_domain(name, policy=policy, priority=priority, zone_id=zone_id.strip() or None)
        s.store.set_credentials(name, ids["cloudflare"], ids["gcore"])
    except ValueError as exc:
        return _back(url, error=str(exc))
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=f"Prioridad {priority}, política {policy}")
    await _after_inventory_change(s)
    return _back(url, ok="Configuración guardada")


@app.post("/dominios/{name}/hostnames")
async def hostnames_guardar(request: Request, name: str):
    """Guarda la tabla de hostnames (servidor y destino Gcore) y añade los nuevos."""
    s = _state(request)
    url = request.url_for("dominio", name=name)
    if name not in s.inventory.domains:
        raise HTTPException(404)
    form = await request.form()
    try:
        for h in s.inventory.domains[name].hostnames:
            s.store.upsert_hostname(name, h.name, server=str(form.get(f"server:{h.name}", h.server)),
                                    gcore_target=str(form.get(f"gcore:{h.name}", "")).strip() or None)
            s.store.set_failover(h.name, bool(form.get(f"failover:{h.name}")))
        for new in str(form.get("new_hostnames", "")).split():
            s.store.upsert_hostname(name, new, server=str(form.get("new_server")))
    except ValueError as exc:
        return _back(url, error=str(exc))
    s.events.add(actor=_actor(request), kind="config", domain=name, summary="Hostnames actualizados")
    await _after_inventory_change(s)
    return _back(url, ok="Hostnames guardados")


def origin_header_view(s: State, name: str) -> dict:
    """Si cada CDN tiene aplicado el secreto actual (por huella), para la ficha del dominio."""
    from .gcore_setup import fingerprint, origin_secret
    domain = s.inventory.domains[name]
    out = {}
    for cdn in ("cloudflare", "gcore"):
        applied = s.events.get_value(f"origin_header_{cdn}:{name}")
        current = fingerprint(origin_secret(s.secrets, cdn))
        if cdn == "gcore" and not domain.gcore_resource_id:
            out[cdn] = ("nodata", "Sin preparar")
        elif not applied:
            out[cdn] = ("blocked", "Sin aplicar")
        elif applied != current:
            out[cdn] = ("blocked", "Secreto antiguo")
        else:
            out[cdn] = ("free", "Al día")
    return out


@app.post("/dominios/{name}/origen/cloudflare")
async def origen_cloudflare(request: Request, name: str):
    from .gcore_setup import fingerprint, origin_secret
    s = _state(request)
    domain = s.inventory.domains.get(name)
    if domain is None:
        raise HTTPException(404)
    url = request.url_for("dominio", name=name)
    token = s.creds.secret(domain.cloudflare_credential)
    if not token or not domain.zone_id:
        return _back(url, "cabecera", error="Asigna una credencial y la zona de Cloudflare al dominio")
    secret = origin_secret(s.secrets, "cloudflare")
    try:
        outcome = await cf.ensure_origin_header(token, domain.zone_id, secret)
    except (RuntimeError, httpx.HTTPError) as exc:
        s.events.add(actor=_actor(request), kind="error", domain=name, summary=f"Cabecera secreta en Cloudflare: {exc}")
        return _back(url, "cabecera", error=f"No se pudo aplicar en Cloudflare: {exc}")
    s.events.set_value(f"origin_header_cloudflare:{name}", fingerprint(secret))
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=f"Cabecera secreta en Cloudflare: regla {outcome}")
    return _back(url, "cabecera", ok=f"Regla de Cloudflare {outcome}: las peticiones hacia el origen llevan la cabecera secreta")


@app.post("/dominios/{name}/gcore/preparar")
async def gcore_preparar(request: Request, name: str):
    s = _state(request)
    if name not in s.inventory.domains:
        raise HTTPException(404)
    job = s.jobs.get(name)
    if job and not job.done:
        return _back(request.url_for("dominio", name=name), error="Ya hay una preparación en curso")
    job = s.jobs[name] = Job(domain=name)
    s.events.add(actor=_actor(request), kind="config", domain=name, summary="Preparación en Gcore iniciada")
    asyncio.create_task(prepare_domain(s, name, job))
    return RedirectResponse(str(request.url_for("dominio", name=name)) + "#gcore", status_code=303)


@app.post("/dominios/{name}/eliminar")
async def dominio_eliminar(request: Request, name: str, confirm: str = Form(""), dns_action: str = Form("cloudflare"),
                           delete_gcore: str = Form("")):
    """Antes de dejar de vigilar el dominio, decide dónde queda servido. Si algo falla, no se elimina."""
    s = _state(request)
    domain = s.inventory.domains.get(name)
    if domain is None:
        raise HTTPException(404)
    back = request.url_for("dominio", name=name)
    if confirm.strip() != name:
        return _back(back, error="Escribe el nombre del dominio para eliminarlo")
    if dns_action not in ("cloudflare", "gcore", "none"):
        return _back(back, error="Opción no válida")
    if dns_action == "gcore" and delete_gcore:
        return _back(back, error="No puedes dejarlo en Gcore y borrar a la vez su recurso de Gcore")

    client = s.cloudflare_for(domain)
    diff, changes = [], []
    try:
        for h in domain.hostnames:
            current = s.resolutions.get(h.name)
            provider = current.provider if current else "unresolved"
            if dns_action == "cloudflare" and provider not in ("cloudflare",):
                origin = s.inventory.servers[h.server].origin_ipv4 if h.server in s.inventory.servers else None
                changes.append((h, cf.plan_restore(h, str(origin) if origin else None), provider))
            elif dns_action == "gcore" and provider != "gcore" and h.failover:
                if not h.gcore_target:
                    raise ValueError(f"{h.name} no tiene destino Gcore")
                changes.append((h, plan_to_gcore(h.name, h.gcore_target), provider))
        for h, change, provider in changes:
            await client.apply(domain.zone_id, h.cloudflare_record_id, change)
            diff.append([h.name, DNS_BEFORE.get(provider, provider), change.describe()])
        if delete_gcore and domain.gcore_resource_id:
            token = s.creds.secret(domain.gcore_credential)
            if not token:
                raise ValueError("No hay credencial de Gcore para borrar el recurso")
            await gcore.delete_resource(token, domain.gcore_resource_id)
    except (OriginExposureError, ValueError, RuntimeError, httpx.HTTPError) as exc:
        s.events.add(actor=_actor(request), kind="error", domain=name, summary=f"No se eliminó: {exc}")
        return _back(back, error=f"No se ha eliminado: {exc}")

    s.store.delete_domain(name)
    s.engine.forget(name)
    where = {"cloudflare": "en Cloudflare", "gcore": "en Gcore", "none": "con el DNS sin cambios"}[dns_action]
    extra = " · recurso de Gcore borrado" if delete_gcore and domain.gcore_resource_id else ""
    s.events.add(actor=_actor(request), kind="config", domain=name, transition=None,
                 summary=f"Eliminado del inventario; queda {where}{extra}", dns_diff=diff, simulated=client.dry_run and bool(diff))
    await _after_inventory_change(s)
    note = " (cambios DNS simulados)" if client.dry_run and diff else ""
    return _back(request.url_for("dominios"), ok=f"{name} eliminado del inventario; queda {where}{extra}{note}")


@app.post("/dominios/{name}/volver")
async def volver_cloudflare(request: Request, name: str, confirm: str = Form("")):
    """Restaura en Cloudflare (con proxy) los hostnames que no estén ya en Cloudflare."""
    s = _state(request)
    if name not in s.inventory.domains:
        raise HTTPException(404, "Dominio no inventariado")
    url = request.url_for("dominio", name=name)
    if confirm.strip() != name:
        return _back(url, error="Escribe el nombre del dominio para confirmar")
    try:
        diff, simulated = await failover.return_to_cloudflare(s, name, force_all=s.dry_run and s.engine.get(name).sim_backup is True)
    except SwitchFailed as exc:
        s.events.add(actor=_actor(request), kind="error", domain=name, summary=f"Vuelta a Cloudflare fallida: {exc}", dns_diff=exc.diff)
        return _back(url, error=f"No se pudo volver a Cloudflare: {exc}")
    if not diff:
        return _back(url, ok="Todos los hostnames ya estaban en Cloudflare")
    s.engine.manual_change(name, to_backup=False, simulated=simulated)
    s.events.add(actor=_actor(request), kind="switch", domain=name, transition="GCORE → CF",
                 summary="Vuelta manual a Cloudflare desde el panel", dns_diff=diff, simulated=simulated)
    await _after_inventory_change(s)
    if not simulated and os.environ.get("MULTICDN_OFFLINE") != "1":
        asyncio.create_task(recheck_dns_soon(s))
    msg = "Vuelta simulada (modo dry-run): no se ha tocado el DNS" if simulated else "Vuelta a Cloudflare aplicada; puede tardar unos minutos en propagarse"
    return _back(url, ok=msg + ". El cambio automático de este dominio queda en pausa 1 h")


@app.post("/dominios/{name}/cambiar")
async def cambiar(request: Request, name: str, target: str = Form(...), confirm: str = Form("")):
    s = _state(request)
    if name not in s.inventory.domains:
        raise HTTPException(404, "Dominio no inventariado")
    url = request.url_for("dominio", name=name)
    if confirm.strip() != name:
        return _back(url, error="Escribe el nombre del dominio para confirmar")
    if target != "gcore":
        return _back(url, error="Destino no disponible todavía")
    try:
        diff, simulated = await failover.switch_to_gcore(s, name)
    except SwitchFailed as exc:
        if exc.diff:
            s.events.add(actor=_actor(request), kind="error", domain=name, summary=str(exc), dns_diff=exc.diff)
        return _back(url, error=str(exc))
    s.engine.manual_change(name, to_backup=True, simulated=simulated)
    s.events.add(actor=_actor(request), kind="switch", domain=name, transition="CF → GCORE",
                 summary="Cambio manual a Gcore desde el panel", dns_diff=diff, simulated=simulated)
    await _after_inventory_change(s)
    if not simulated and os.environ.get("MULTICDN_OFFLINE") != "1":
        asyncio.create_task(recheck_dns_soon(s))
    msg = "Cambio simulado (modo dry-run): no se ha tocado el DNS" if simulated else "Cambio a Gcore aplicado; puede tardar unos minutos en propagarse"
    return _back(url, ok=msg + ". El cambio automático de este dominio queda en pausa 1 h")


MAINTENANCE_OPTIONS = {1: "1 h", 6: "6 h", 24: "24 h", 168: "7 días", 0: "hasta reanudarlo"}


@app.post("/dominios/{name}/automatico/mantenimiento")
async def automatico_mantenimiento(request: Request, name: str, horas: int = Form(...)):
    s = _state(request)
    if name not in s.inventory.domains:
        raise HTTPException(404)
    url = request.url_for("dominio", name=name)
    if horas not in MAINTENANCE_OPTIONS:
        return _back(url, error="Duración no válida")
    until = datetime.now(UTC) + timedelta(hours=horas) if horas else None
    s.engine.maintenance(name, until)
    s.events.add(actor=_actor(request), kind="config", domain=name,
                 summary=f"Mantenimiento: cambio automático en pausa {MAINTENANCE_OPTIONS[horas]}")
    return _back(url, ok=f"Cambio automático en pausa {MAINTENANCE_OPTIONS[horas]}. Los avisos siguen llegando.")


@app.post("/dominios/{name}/automatico/reanudar")
async def automatico_reanudar(request: Request, name: str):
    s = _state(request)
    if name not in s.inventory.domains:
        raise HTTPException(404)
    s.engine.resume(name)
    s.events.add(actor=_actor(request), kind="config", domain=name, summary="Cambio automático reanudado")
    asyncio.create_task(run_engine(s))
    return _back(request.url_for("dominio", name=name), ok="Cambio automático reanudado")


# ---------------------------------------------------------------- Historial

@app.get("/historial", response_class=HTMLResponse)
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
CDN_LABEL = {"cloudflare": "Cloudflare", "gcore": "Gcore", "mixed": "Mixto", "unknown": "Sin datos"}


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
            past = await _cached(s, ("fd", start.date()), lambda: match_calendar.fetch_past_laliga(s.client, token, start, end))
            matches = match_calendar.merge(matches, past)
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            note = f"sin partidos pasados ({type(exc).__name__})"
    elif not token:
        note = "partidos pasados no disponibles: añade la clave de football-data.org"
    return [m for m in matches if m.kickoff + match_calendar.MATCH_LENGTH > start and m.kickoff < end], note


async def _stats_traffic(s: State, start: datetime, end: datetime) -> tuple[dict, str | None]:
    """Tráfico diario por dominio (suma de todas las cuentas de Gcore)."""
    if os.environ.get("MULTICDN_OFFLINE") == "1":
        return {}, None
    by_resource: dict[int, list] = {}
    errors = []
    for cred in s.creds.list("gcore"):
        token = s.creds.secret(cred.id)
        try:
            by_resource |= await _cached(s, ("gc", cred.id, start.date()), lambda: gcore.traffic_series(token, start, end))
        except (RuntimeError, httpx.HTTPError) as exc:
            errors.append(f"{cred.label}: {exc}")
    names = {d.gcore_resource_id: n for n, d in s.inventory.domains.items() if d.gcore_resource_id}
    out: dict[str, dict] = {}
    for rid, rows in by_resource.items():
        name = names.get(rid, "otros recursos")
        for day, value in rows:
            out.setdefault(name, {})
            out[name][day.date()] = out[name].get(day.date(), 0) + value
    return out, "; ".join(errors) or None


@app.get("/estadisticas", response_class=HTMLResponse)
async def estadisticas(request: Request, dias: int = 7):
    from . import charts, stats
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
    for name, cfg in s.inventory.ordered_domains():
        hosts = [h.name for h in cfg.hostnames if h.failover] or [h.name for h in cfg.hostnames]
        current = {h: r.provider for h in hosts if (r := s.resolutions.get(h))}
        events = s.events.list(domain=name, limit=5000)
        for e in events:  # solo cuentan los cambios que movieron algún hostname que conmuta
            if e.kind == "switch" and not e.simulated and start <= e.ts < end and any(d[0] in hosts for d in e.dns_diff):
                switches["auto" if e.actor == "auto" else "manual"] += 1
        segs = stats.cdn_segments(events, hosts, current, start, min(end, now))
        gcore_time += sum((g.end - g.start for g in segs if g.kind == "gcore"), timedelta(0))
        ivs = stats.block_intervals(s.feed, known.get(name, []), start, end) if s.feed else []
        for iv in ivs:
            iv_end = iv.end or now
            on_gcore = sum((stats.overlap(iv.start, iv_end, g.start, g.end) for g in segs if g.kind == "gcore"), timedelta(0))
            match = next((label for b0, b1, label in bands if b0 < iv_end and b1 > iv.start), None)
            episodes.append({"domain": name, "start": iv.start, "end": iv.end, "duration": stats.fmt_duration(iv.duration(now)),
                             "isps": iv.max_isps, "isp_names": ", ".join(sorted(hayahora.ISPS.get(i, i) for i in iv.isps)),
                             "gcore_pct": round(100 * on_gcore / iv.duration(now)) if iv.duration(now) else 0,
                             "match": match})
        rows.append({
            "name": name,
            "segments": [(g.start, g.end, g.kind, f"{CDN_LABEL[g.kind]}: {g.start:%d/%m %H:%M}–{g.end:%d/%m %H:%M} UTC "
                                                  f"({stats.fmt_duration(g.end - g.start)})") for g in segs],
            "blocks": [(max(iv.start, start), iv.end or now, f"IPs bloqueadas: {iv.start:%d/%m %H:%M}–"
                        f"{(iv.end or now):%d/%m %H:%M} UTC · hasta {iv.max_isps} operadoras") for iv in ivs],
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
             "switches": switches, "traffic": human_bytes(traffic_total)},
        mass=charts.line_chart(series, start, end, step, bands) if series else None,
        daily_mass=_daily_max(series),
        timeline=charts.timeline(rows, start, end) if rows else None, rows=rows,
        traffic=charts.columns(day_list, tseries, start, end, fmt=human_bytes) if tseries else None,
        tseries=tseries, day_list=day_list, traffic_error=traffic_error,
        episodes=episodes, matches=matches, match_note=match_note, feed_note=None if s.feed else "feed de bloqueos aún sin leer",
    ))


def _daily_max(series):
    out: dict = {}
    for t, v in series:
        out[t.date()] = max(out.get(t.date(), 0), v)
    return sorted(out.items())


# ---------------------------------------------------------------- Ajustes

@app.get("/ajustes")
async def ajustes(request: Request):
    return RedirectResponse(request.url_for("ajustes_cuentas"), status_code=303)


# ---- Cuentas de proveedor

async def _check_credential(s: State, cred_id: int) -> tuple[bool, str]:
    cred, secret = s.creds.get(cred_id), s.creds.secret(cred_id)
    if not secret:
        ok, msg, scope = False, "No se puede descifrar: ¿ha cambiado la clave maestra?", None
    elif cred.provider == "cloudflare":
        ok, msg = await cf.verify_token(secret)
        scope = None
        if ok:
            zones = await cf.list_zones(secret)
            scope = ", ".join(z["name"] for z in zones) or "ninguna zona"
            msg = f"Token activo · acceso a {len(zones)} zona(s)"
            assigned = [z["name"] for z in zones if z["name"] in s.inventory.domains and s.store.assign_zone(z["name"], z["id"], cred_id)]
            if assigned:
                msg += f" · asignada a {', '.join(assigned)}"
                s.reload()
                await refresh_cloudflare(s)
    else:
        ok, msg = await gcore.verify_token(secret)
        scope = None
        if ok and os.environ.get("MULTICDN_OFFLINE") != "1":
            asyncio.create_task(refresh_usage(s))
    s.creds.record_check(cred_id, ok, msg, scope)
    return ok, msg


@app.get("/ajustes/cuentas", response_class=HTMLResponse)
async def ajustes_cuentas(request: Request):
    s = _state(request)
    creds = [(c, s.creds.usage(c.id)) for c in s.creds.list()]
    return templates.TemplateResponse(request, "ajustes_cuentas.html", _common(
        request, "ajustes", tab="cuentas", creds=creds, providers=PROVIDERS, key_on_disk=s.secrets.key_on_disk,
        usage=s.gcore_usage))


@app.post("/ajustes/cuentas")
async def cuenta_crear(request: Request, provider: str = Form(...), label: str = Form(""), secret: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_cuentas")
    try:
        cred_id = s.creds.add(provider, label, secret)
    except ValueError as exc:
        return _back(url, error=str(exc))
    s.events.add(actor=_actor(request), kind="config", summary=f"Credencial de {PROVIDERS[provider]} añadida: {label.strip()}")
    try:
        ok, msg = await _check_credential(s, cred_id)
    except httpx.HTTPError as exc:
        ok, msg = False, f"Guardada, pero no se pudo verificar: {type(exc).__name__}"
    return _back(url, **({"ok": f"«{label.strip()}» guardada. {msg}"} if ok else {"error": f"«{label.strip()}» guardada, pero la verificación falló: {msg}"}))


@app.post("/ajustes/cuentas/{cred_id}/probar")
async def cuenta_probar(request: Request, cred_id: int):
    s = _state(request)
    try:
        ok, msg = await _check_credential(s, cred_id)
    except (ValueError, httpx.HTTPError) as exc:
        ok, msg = False, str(exc) or type(exc).__name__
    return _back(request.url_for("ajustes_cuentas"), **({"ok": msg} if ok else {"error": msg}))


@app.post("/ajustes/cuentas/{cred_id}/rotar")
async def cuenta_rotar(request: Request, cred_id: int, secret: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_cuentas")
    if not secret.strip():
        return _back(url, error="Introduce la nueva credencial")
    try:
        s.creds.rotate(cred_id, secret)
        cred = s.creds.get(cred_id)
    except ValueError as exc:
        return _back(url, error=str(exc))
    s.events.add(actor=_actor(request), kind="config", summary=f"Credencial rotada: {cred.label}")
    return await cuenta_probar(request, cred_id)


@app.post("/ajustes/cuentas/{cred_id}/eliminar")
async def cuenta_eliminar(request: Request, cred_id: int):
    s = _state(request)
    url = request.url_for("ajustes_cuentas")
    try:
        label = s.creds.get(cred_id).label
        s.creds.delete(cred_id)
    except ValueError as exc:
        return _back(url, error=str(exc))
    s.events.add(actor=_actor(request), kind="config", summary=f"Credencial eliminada: {label}")
    return _back(url, ok=f"«{label}» eliminada")


# ---- Notificaciones

@app.get("/ajustes/notificaciones", response_class=HTMLResponse)
async def ajustes_notificaciones(request: Request):
    s = _state(request)
    return templates.TemplateResponse(request, "ajustes_notificaciones.html", _common(
        request, "ajustes", tab="notificaciones", fields={f.name: f for f in s.secrets.all_status()},
        beat=s.last_beat, beat_health=heartbeat.health(s),
        key_on_disk=s.secrets.key_on_disk))


CHANNELS = {"telegram": ("telegram_token", "telegram_chat_id"), "email": ("smtp_url", "alert_email_to")}


@app.post("/ajustes/notificaciones/canal/{canal}")
async def canal_guardar(request: Request, canal: str):
    """Guarda todos los campos rellenos del canal; los vacíos conservan su valor actual."""
    s = _state(request)
    if canal not in CHANNELS:
        raise HTTPException(404)
    form = await request.form()
    saved = []
    for name in CHANNELS[canal]:
        value = str(form.get(name, "")).strip()
        if value:
            s.secrets.set(name, value)
            saved.append(CREDENTIALS[name][0])
    url = request.url_for("ajustes_notificaciones")
    if not saved:
        return _back(url, error="No has escrito ningún valor nuevo")
    s.events.add(actor=_actor(request), kind="config", summary=f"Notificaciones: {', '.join(saved)} actualizado")
    return _back(url, ok=f"Guardado: {', '.join(saved)}")


@app.post("/ajustes/notificaciones/latido")
async def latido_guardar(request: Request, heartbeat_url: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_notificaciones")
    value = heartbeat_url.strip()
    if not heartbeat.valid_url(value):
        return _back(url, error="Pega la URL de ping completa (https://hc-ping.com/…)")
    s.secrets.set("heartbeat_url", value)
    s.events.add(actor=_actor(request), kind="config", summary="Aviso externo: URL actualizada")
    return await latido_probar(request)


@app.post("/ajustes/notificaciones/latido/probar")
async def latido_probar(request: Request):
    s = _state(request)
    url = request.url_for("ajustes_notificaciones")
    b = await heartbeat.beat(s)
    if b is None:
        return _back(url, error="Falta la URL de aviso externo")
    if b.result != "ok":
        return _back(url, error=f"No se pudo avisar: {b.result}")
    return _back(url, ok="Aviso enviado: " + ("todo en orden" if b.ok else f"fallo comunicado ({b.detail})"))


@app.post("/ajustes/notificaciones/{name}")
async def notificacion_guardar(request: Request, name: str, value: str = Form("")):
    s = _state(request)
    if name not in CREDENTIALS:
        raise HTTPException(404)
    url = request.url_for("ajustes_notificaciones")
    try:
        s.secrets.set(name, value)
    except ValueError:
        return _back(url, error="Introduce un valor")
    s.events.add(actor=_actor(request), kind="config", summary=f"Notificaciones: {CREDENTIALS[name][0]} actualizado")
    return _back(url, ok=f"{CREDENTIALS[name][0]} guardado")


@app.post("/ajustes/notificaciones/{name}/eliminar")
async def notificacion_eliminar(request: Request, name: str):
    s = _state(request)
    if name not in CREDENTIALS:
        raise HTTPException(404)
    s.secrets.delete(name)
    s.events.add(actor=_actor(request), kind="config", summary=f"Notificaciones: {CREDENTIALS[name][0]} eliminado")
    return _back(request.url_for("ajustes_notificaciones"), ok=f"{CREDENTIALS[name][0]} eliminado")


@app.post("/ajustes/notificaciones/probar/{canal}")
async def notificacion_probar(request: Request, canal: str):
    s = _state(request)
    try:
        if canal == "telegram":
            token = s.secrets.get("telegram_token")
            ok, msg = await notify.verify_telegram(token, s.secrets.get("telegram_chat_id")) if token else (False, "Falta el token del bot")
        elif canal == "email":
            smtp = s.secrets.get("smtp_url")
            ok, msg = await notify.verify_smtp(smtp) if smtp else (False, "Falta el servidor SMTP")
        else:
            raise HTTPException(404)
    except httpx.HTTPError as exc:
        ok, msg = False, f"Error de red: {type(exc).__name__}"
    return _back(request.url_for("ajustes_notificaciones"), **({"ok": msg} if ok else {"error": msg}))


# ---- Servidores y operación

@app.get("/ajustes/servidores", response_class=HTMLResponse)
async def ajustes_servidores(request: Request):
    s = _state(request)
    servers = [{"id": sid, "private_address": srv.private_address, "origin_ip": s.secrets.get(origin_key(sid)),
                "hostnames": sum(h.server == sid for d in s.inventory.domains.values() for h in d.hostnames)}
               for sid, srv in s.inventory.servers.items()]
    from . import firewall_status
    fw = firewall_status.read()
    return templates.TemplateResponse(request, "ajustes_servidores.html", _common(
        request, "ajustes", tab="servidores", servers=servers, fw=fw, fw_changes=firewall_status.changes(),
        fw_problem=fw.problem(datetime.now(UTC)) if fw else None))


@app.get("/ajustes/operacion", response_class=HTMLResponse)
async def ajustes_operacion(request: Request):
    s = _state(request)
    return templates.TemplateResponse(request, "ajustes_operacion.html", _common(
        request, "ajustes", tab="operacion", dry_run_env=s.dry_run_env, key_on_disk=s.secrets.key_on_disk,
        ev_stats=s.events.stats(), ev_days=s.events.get_setting("events_max_days"),
        ev_rows=s.events.get_setting("events_max_rows"), auto_on=failover.auto_enabled(s),
        quota_gb=s.events.get_setting("gcore_quota_gb"), calendar=s.calendar, calendar_error=s.calendar_error,
        fd=s.secrets.status("football_data_token"), now=datetime.now(UTC)))


@app.post("/ajustes/operacion/automatico")
async def automatico_global(request: Request, enabled: str = Form("")):
    s = _state(request)
    on = enabled == "1"
    s.events.set_setting("auto_switch", int(on))
    s.events.add(actor=_actor(request), kind="config",
                 summary="Cambio automático de CDN " + ("activado" if on else "desactivado para todos los dominios"))
    return _back(request.url_for("ajustes_operacion"), ok="Cambio automático " + ("activado" if on else "desactivado"))


@app.post("/ajustes/operacion/cuota")
async def cuota_guardar(request: Request, gcore_quota_gb: int = Form(...)):
    s = _state(request)
    url = request.url_for("ajustes_operacion")
    try:
        s.events.set_setting("gcore_quota_gb", gcore_quota_gb)
    except ValueError as exc:
        return _back(url, error=f"Cuota: {exc}")
    s.events.add(actor=_actor(request), kind="config", summary=f"Cuota mensual de Gcore: {gcore_quota_gb} GB")
    if os.environ.get("MULTICDN_OFFLINE") != "1":
        asyncio.create_task(refresh_usage(s))
    return _back(url, ok=f"Cuota guardada: {gcore_quota_gb} GB al mes")


@app.post("/ajustes/operacion/football-data")
async def football_data_guardar(request: Request, token: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_operacion")
    if not token.strip():
        return _back(url, error="Introduce la clave")
    s.secrets.set("football_data_token", token)
    s.events.add(actor=_actor(request), kind="config", summary="Clave de football-data.org guardada")
    await refresh_calendar(s)
    result = s.calendar.sources.get("football-data.org") if s.calendar else s.calendar_error
    if result == "ok":
        return _back(url, ok=f"Clave guardada y verificada · {len(s.calendar.matches)} partidos en el calendario")
    return _back(url, error=f"Clave guardada, pero football-data.org no responde bien: {result}")


@app.post("/ajustes/operacion/football-data/eliminar")
async def football_data_eliminar(request: Request):
    s = _state(request)
    s.secrets.delete("football_data_token")
    s.events.add(actor=_actor(request), kind="config", summary="Clave de football-data.org eliminada")
    await refresh_calendar(s)
    return _back(request.url_for("ajustes_operacion"), ok="Clave de football-data.org eliminada")


@app.post("/ajustes/operacion/retencion")
async def retencion_guardar(request: Request, events_max_days: int = Form(...), events_max_rows: int = Form(...)):
    s = _state(request)
    url = request.url_for("ajustes_operacion")
    try:
        s.events.set_setting("events_max_days", events_max_days)
        s.events.set_setting("events_max_rows", events_max_rows)
    except ValueError as exc:
        return _back(url, error=f"Retención: {exc}")
    deleted = s.events.prune()
    s.events.add(actor=_actor(request), kind="config",
                 summary=f"Retención del historial: {events_max_days} días, máximo {events_max_rows} eventos")
    return _back(url, ok=f"Retención guardada · {deleted} eventos antiguos eliminados")


@app.post("/ajustes/servidores")
async def servidor_guardar(request: Request, server_id: str = Form(...), origin_ipv4: str = Form(""),
                           private_address: str = Form("")):
    s = _state(request)
    try:
        s.store.upsert_server(server_id.strip().lower(), origin_ipv4.strip() or None, private_address.strip() or None)
    except ValueError as exc:
        return _back(request.url_for("ajustes_servidores"), error=f"Servidor: {exc}")
    s.events.add(actor=_actor(request), kind="config", summary=f"Servidor {server_id} guardado")
    await _after_inventory_change(s)
    return _back(request.url_for("ajustes_servidores"), ok=f"Servidor {server_id} guardado")


@app.post("/ajustes/servidores/{server_id}/editar")
async def servidor_editar(request: Request, server_id: str, new_id: str = Form(...), origin_ipv4: str = Form(""),
                          private_address: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_servidores")
    if server_id not in s.inventory.servers:
        raise HTTPException(404)
    try:
        s.store.rename_server(server_id, new_id)
        target = new_id.strip().lower()
        if origin_ipv4.strip():
            s.store.upsert_server(target, origin_ipv4.strip(), private_address.strip() or None)
        else:
            s.secrets.delete(origin_key(target))
            s.store.upsert_server(target, None, private_address.strip() or None)
    except ValueError as exc:
        return _back(url, error=f"Servidor: {exc}")
    s.events.add(actor=_actor(request), kind="config",
                 summary=f"Servidor {server_id} actualizado" + (f" (ahora {target})" if target != server_id else ""))
    await _after_inventory_change(s)
    return _back(url, ok=f"Servidor {target} guardado")


@app.post("/ajustes/servidores/{server_id}/eliminar")
async def servidor_eliminar(request: Request, server_id: str):
    s = _state(request)
    try:
        s.store.delete_server(server_id)
    except ValueError as exc:
        return _back(request.url_for("ajustes_servidores"), error=str(exc))
    await _after_inventory_change(s)
    return _back(request.url_for("ajustes_servidores"), ok=f"Servidor {server_id} eliminado")


@app.get("/ajustes/inventario.yaml")
async def exportar(request: Request):
    return PlainTextResponse(
        _state(request).store.export_yaml(), media_type="application/yaml",
        headers={"Content-Disposition": 'attachment; filename="inventory.yaml"'},
    )


# ---------------------------------------------------------------- Autenticación

def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def _cookie_secure(request: Request) -> bool:
    mode = os.environ.get("MULTICDN_COOKIE_SECURE", "auto")
    if mode in ("0", "1"):
        return mode == "1"
    return request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"


def _with_session(response: Response, request: Request, token: str | None) -> Response:
    if token is None:
        response.delete_cookie(SESSION_COOKIE, path="/")
    else:
        response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="strict", secure=_cookie_secure(request), path="/")
    return response


def _auth_page(request: Request, template: str, **ctx) -> HTMLResponse:
    return templates.TemplateResponse(request, template, {"request": request, "next": _safe_next(request.query_params.get("next"))} | ctx)


LOCK_MSG = "Demasiados intentos fallidos. Espera unos minutos antes de volver a intentarlo."


@app.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    s = _state(request)
    if request.state.session:
        return RedirectResponse(_safe_next(request.query_params.get("next")), status_code=303)
    return _auth_page(request, "login.html", has_users=s.auth.has_users(), error=request.query_params.get("error"))


@app.post("/login")
async def login_post(request: Request, username: str = Form(""), password: str = Form(""), next: str = Form("/")):
    s = _state(request)
    keys = (f"u:{username.strip().lower()}", f"ip:{_client_ip(request)}")
    if s.auth.locked(*keys):
        return _auth_page(request, "login.html", has_users=True, error=LOCK_MSG, username=username)
    user = s.auth.check_password(username, password)
    if user is None:
        s.auth.register_failure(*keys)
        s.events.add(actor="auto", kind="auth", summary=f"Contraseña incorrecta para «{username.strip()[:40]}» desde {_client_ip(request)}")
        if s.auth.locked(*keys):
            s.events.add(actor="auto", kind="auth",
                         summary=f"Acceso bloqueado por intentos fallidos («{username.strip()[:40]}» desde {_client_ip(request)})")
        return _auth_page(request, "login.html", has_users=True, error="Usuario o contraseña incorrectos.", username=username)
    stage = "pending" if user.totp_enabled else "enroll"
    token = s.auth.create_session(user.id, stage, _client_ip(request), request.headers.get("user-agent"))
    target = "/login/codigo" if stage == "pending" else "/login/alta"
    return _with_session(RedirectResponse(f"{target}?{urlencode({'next': _safe_next(next)})}", status_code=303), request, token)


def _finish_login(request: Request, user_id: int, username: str, next_url: str) -> Response:
    s = _state(request)
    pending = request.state.pending
    if pending:
        s.auth.delete_session(pending.id_hash)  # nuevo identificador tras autenticar
    token = s.auth.create_session(user_id, "full", _client_ip(request), request.headers.get("user-agent"))
    s.auth.register_success(f"u:{username}", f"ip:{_client_ip(request)}")
    s.events.add(actor=username, kind="auth", summary=f"Inicio de sesión desde {_client_ip(request)}")
    return _with_session(RedirectResponse(_safe_next(next_url), status_code=303), request, token)


@app.get("/login/codigo", response_class=HTMLResponse)
async def login_codigo(request: Request):
    pending = request.state.pending
    if not pending or pending.stage != "pending":
        return RedirectResponse("/login", status_code=303)
    return _auth_page(request, "login_codigo.html", username=pending.user.username)


@app.post("/login/codigo")
async def login_codigo_post(request: Request, code: str = Form(""), next: str = Form("/")):
    s = _state(request)
    pending = request.state.pending
    if not pending or pending.stage != "pending":
        return RedirectResponse("/login?error=La+sesión+ha+caducado", status_code=303)
    user = pending.user
    keys = (f"u:{user.username}", f"ip:{_client_ip(request)}")
    if s.auth.locked(*keys):
        s.auth.delete_session(pending.id_hash)
        return _with_session(RedirectResponse(f"/login?{urlencode({'error': LOCK_MSG})}", status_code=303), request, None)
    code = code.strip()
    used_recovery = False
    ok = s.auth.check_totp(user.id, code)
    if not ok and "-" in code:
        ok = used_recovery = s.auth.use_recovery_code(user.id, code)
    if not ok:
        s.auth.register_failure(*keys)
        s.events.add(actor="auto", kind="auth", summary=f"Código incorrecto para {user.username} desde {_client_ip(request)}")
        if s.auth.locked(*keys):
            s.events.add(actor="auto", kind="auth",
                         summary=f"Acceso bloqueado por intentos fallidos ({user.username} desde {_client_ip(request)})")
        return _auth_page(request, "login_codigo.html", username=user.username, error="Código incorrecto o ya usado.")
    if used_recovery:
        s.events.add(actor=user.username, kind="auth",
                     summary=f"Acceso con código de recuperación (quedan {s.auth.recovery_left(user.id)})")
    return _finish_login(request, user.id, user.username, next)


@app.get("/login/alta", response_class=HTMLResponse)
async def login_alta(request: Request):
    import segno
    s = _state(request)
    pending = request.state.pending
    if not pending or pending.stage != "enroll":
        return RedirectResponse("/login", status_code=303)
    secret = s.auth.totp_secret(pending.user.id) or s.auth.start_totp_enrollment(pending.user.id)
    uri = totp_uri(secret, pending.user.username)
    qr = segno.make(uri, error="m").svg_inline(scale=5, dark="#1c1b1b", light="#ffffff")
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return _auth_page(request, "login_alta.html", qr=Markup(qr), secret=grouped, username=pending.user.username,
                      error=request.query_params.get("error"))


@app.post("/login/alta")
async def login_alta_post(request: Request, code: str = Form(""), next: str = Form("/")):
    s = _state(request)
    pending = request.state.pending
    if not pending or pending.stage != "enroll":
        return RedirectResponse("/login", status_code=303)
    user = pending.user
    if not s.auth.check_totp(user.id, code):
        return RedirectResponse(f"/login/alta?{urlencode({'error': 'Código incorrecto: revisa la hora del móvil', 'next': _safe_next(next)})}",
                                status_code=303)
    s.auth.enable_totp(user.id)
    codes = s.auth.new_recovery_codes(user.id)
    s.events.add(actor=user.username, kind="auth", summary="TOTP activado")
    s.auth.delete_session(pending.id_hash)
    token = s.auth.create_session(user.id, "full", _client_ip(request), request.headers.get("user-agent"))
    s.events.add(actor=user.username, kind="auth", summary=f"Inicio de sesión desde {_client_ip(request)}")
    response = _auth_page(request, "login_recuperacion.html", codes=codes, next=_safe_next(next))
    return _with_session(response, request, token)


@app.post("/logout")
async def logout(request: Request):
    s = _state(request)
    if request.state.session:
        s.auth.delete_session(request.state.session.id_hash)
        s.events.add(actor=request.state.session.user.username, kind="auth", summary="Cierre de sesión")
    return _with_session(RedirectResponse("/login", status_code=303), request, None)


@app.get("/ajustes/cuenta", response_class=HTMLResponse)
async def ajustes_cuenta(request: Request):
    s = _state(request)
    me = request.state.session
    return templates.TemplateResponse(request, "ajustes_cuenta.html", _common(
        request, "ajustes", tab="cuenta", sessions=s.auth.list_sessions(me.user.id), current_hash=me.id_hash,
        recovery_left=s.auth.recovery_left(me.user.id)))


@app.post("/ajustes/cuenta/password")
async def cuenta_password(request: Request, current: str = Form(""), code: str = Form(""), new: str = Form(""),
                          new2: str = Form("")):
    s = _state(request)
    me = request.state.session
    url = request.url_for("ajustes_cuenta")
    if s.auth.check_password(me.user.username, current) is None or not s.auth.check_totp(me.user.id, code):
        s.events.add(actor=me.user.username, kind="auth", summary="Cambio de contraseña rechazado: credenciales incorrectas")
        return _back(url, error="La contraseña actual o el código no son correctos")
    if new != new2:
        return _back(url, error="Las contraseñas nuevas no coinciden")
    try:
        s.auth.set_password(me.user.id, new)
    except ValueError as exc:
        return _back(url, error=str(exc))
    closed = s.auth.close_sessions(me.user.id, except_hash=me.id_hash)
    s.events.add(actor=me.user.username, kind="auth", summary=f"Contraseña cambiada; {closed} sesiones cerradas")
    detail = {0: "No tenías otras sesiones abiertas.", 1: "Se ha cerrado tu otra sesión."}.get(closed, f"Se han cerrado tus otras {closed} sesiones.")
    return _back(url, ok=f"Contraseña cambiada. {detail}")


@app.post("/ajustes/cuenta/recuperacion")
async def cuenta_recuperacion(request: Request, code: str = Form("")):
    s = _state(request)
    me = request.state.session
    if not s.auth.check_totp(me.user.id, code):
        return _back(request.url_for("ajustes_cuenta"), error="Código TOTP incorrecto")
    codes = s.auth.new_recovery_codes(me.user.id)
    s.events.add(actor=me.user.username, kind="auth", summary="Códigos de recuperación regenerados")
    return _auth_page(request, "login_recuperacion.html", codes=codes, next="/ajustes/cuenta")


@app.post("/ajustes/cuenta/sesiones/{id_hash}/cerrar")
async def cuenta_cerrar_sesion(request: Request, id_hash: str):
    s = _state(request)
    me = request.state.session
    if any(x.id_hash == id_hash for x in s.auth.list_sessions(me.user.id)):
        s.auth.delete_session(id_hash)
        s.events.add(actor=me.user.username, kind="auth", summary="Sesión cerrada desde Mi cuenta")
    if id_hash == me.id_hash:
        return _with_session(RedirectResponse("/login", status_code=303), request, None)
    return _back(request.url_for("ajustes_cuenta"), ok="Sesión cerrada")


@app.get("/api/estado")
async def api_estado(request: Request):
    s = _state(request)
    return {"version": state_version(s), "dns_checked_at": s.dns_checked_at,
            "feed": s.feed.last_update if s.feed else None}


@app.get("/healthz")
async def healthz(request: Request):
    s = _state(request)
    return {"ok": True, "feed": s.feed is not None, "dns_checked_at": s.dns_checked_at}
