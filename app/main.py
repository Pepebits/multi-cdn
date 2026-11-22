"""Controlador Multi-CDN: panel web + tareas periódicas de observación."""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
from contextlib import asynccontextmanager, suppress
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup

from . import alerts, env_sync, event_codes, envfile, envparse, error_reporting, heartbeat, i18n, notify, origin_health, proxy
from .auth import AuthStore, totp_uri
from .gcore_setup import RENEW_BEFORE, Job, prepare_domain, renew_and_check
from .gcore_usage import refresh_usage
from .gcore_usage import human as human_bytes
from .i18n import N_, tn, tr, trn
from .notifier import Notifier
from .config import load_dotenv, load_inventory
from .credentials import ENV_TOKENS, PROVIDERS, CredentialStore
from .db import EventStore
from .engine import failover
from .engine.failover import SwitchFailed
from .inventory_store import InventoryStore, origin_key
from .providers import cloudflare as cf
from .providers import gcore
from .providers.cloudflare import OriginExposureError, plan_to_gcore
from .secrets_store import CREDENTIALS, SecretStore
from .signals import calendar as match_calendar
from .signals import hayahora
from .problems import open_problems
from .views import build_domain
from .state import State
from .tasks import (
    BACKUP_INTERVAL, CALENDAR_INTERVAL, CF_SYNC_INTERVAL, DNS_INTERVAL, FEED_INTERVAL_OPTIONS,
    HEARTBEAT_INTERVAL, ORIGIN_HEALTH_INTERVAL, PRUNE_INTERVAL, RENEW_INTERVAL, USAGE_INTERVAL,
    check_firewall, daily_backup, _delayed_loop, feed_interval, feed_mode, _loop, prune_events,
    recheck_dns_soon, refresh_calendar, refresh_cloudflare, refresh_dns, refresh_feed, restore_block_state, run_engine,
)

log = logging.getLogger("multicdn")
WEB = Path(__file__).parent / "web"


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_dotenv()
    error_reporting.watch_background_tasks()
    db_path = os.environ.get("MULTICDN_DB", "data/multicdn.db")
    secrets = SecretStore(db_path)
    store = InventoryStore(secrets)
    creds = CredentialStore(secrets)
    if store.is_empty():
        # Primer arranque: importar inventory.yaml (o el ejemplo) si existe.
        with suppress(FileNotFoundError):
            store.import_inventory(load_inventory())
    events = EventStore(db_path)
    load_notify_lang(events)
    env_sync.sync(secrets, events, creds)  # config/secrets.env has priority at startup
    events.listeners.append(Notifier(secrets))
    state = State(
        store=store, secrets=secrets, creds=creds, auth=AuthStore(secrets), events=events,
        dry_run_env=os.environ.get("MULTICDN_DRY_RUN", "true").lower() != "false",
    )
    state.client = httpx.AsyncClient(headers={"User-Agent": "multicdn-controller"})
    app.state.mc = state
    if scrubbed := events.scrub_history():  # origin IPs stored before 0.3.0 (ADR-003)
        log.info("history: origin IP removed from %s entries", scrubbed)
    restore_block_state(state)
    state.auth.purge_expired()
    await prune_events(state)
    tasks = []
    from . import firewall_status
    if os.environ.get("MULTICDN_OFFLINE") != "1":
        tasks = [
            asyncio.create_task(_loop(CALENDAR_INTERVAL, refresh_calendar, state)),
            asyncio.create_task(_loop(lambda: feed_interval(state), refresh_feed, state)),
            asyncio.create_task(_loop(DNS_INTERVAL, refresh_dns, state)),
            asyncio.create_task(_loop(CF_SYNC_INTERVAL, refresh_cloudflare, state)),
            asyncio.create_task(_loop(PRUNE_INTERVAL, prune_events, state)),
            asyncio.create_task(_delayed_loop(300, RENEW_INTERVAL, renew_and_check, state)),
            asyncio.create_task(_delayed_loop(20, USAGE_INTERVAL, refresh_usage, state)),
            asyncio.create_task(_delayed_loop(600, BACKUP_INTERVAL, daily_backup, state)),
            asyncio.create_task(_loop(int(firewall_status.CHECK_INTERVAL.total_seconds()), check_firewall, state)),
            asyncio.create_task(_delayed_loop(120, HEARTBEAT_INTERVAL, heartbeat.beat, state)),
            asyncio.create_task(_delayed_loop(15, ORIGIN_HEALTH_INTERVAL, origin_health.check, state)),
        ]
    yield
    for t in tasks:
        t.cancel()
    await state.client.aclose()


SESSION_COOKIE = "mcdn_session"
PUBLIC_PREFIXES = ("/login", "/static/", "/healthz", "/lang/")
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
        raise HTTPException(403, tr("Invalid CSRF token: reload the page and try again"))


# Optional Sentry/GlitchTip: before the app exists, so its middleware is instrumented.
load_dotenv()
error_reporting.setup_logging()
error_reporting.init("panel")

app = FastAPI(title="Multi-CDN", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None,
              dependencies=[Depends(csrf_protect)])
app.mount("/static", StaticFiles(directory=WEB / "static"), name="static")
templates = Jinja2Templates(directory=WEB / "templates")
i18n.install(templates.env)


@app.get("/lang/{lang}")
def set_language(request: Request, lang: str, next: str = "/"):
    """Footer language selector: remembered in this browser for a year."""
    response = RedirectResponse(_safe_next(next), status_code=303)
    if code := i18n.normalize(lang):
        response.set_cookie(i18n.COOKIE, code, max_age=365 * 86400, httponly=True, samesite="lax",
                            secure=_cookie_secure(request))
    return response


load_notify_lang = env_sync.load_notify_lang  # the CLI and the runbook import it from here


def _safe_next(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    # Browsers drop tabs and newlines from URLs: "/\t/evil.example" would become "//evil.example".
    return "/" if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value) else value


@app.middleware("http")
async def security(request: Request, call_next):
    """Origen de los POST, sesión obligatoria fuera de /login y cabeceras de seguridad."""
    i18n.set_ui(i18n.pick(request.cookies.get(i18n.COOKIE), request.headers.get("accept-language")))
    if request.method == "POST":
        source = request.headers.get("origin") or request.headers.get("referer")
        if source and urlparse(source).netloc != request.url.netloc:
            return PlainTextResponse(tr("Origin not allowed"), status_code=403)
        if not source and os.environ.get("MULTICDN_OFFLINE") != "1":
            return PlainTextResponse(tr("Missing Origin header"), status_code=403)
    state: State = request.app.state.mc
    # El sondeo automático (/api/) no renueva la sesión: la inactividad sigue contando.
    session = state.auth.get_session(request.cookies.get(SESSION_COOKIE), touch=not request.url.path.startswith("/api/"))
    request.state.session = session if session and session.stage == "full" else None
    request.state.pending = session if session and session.stage != "full" else None
    path = request.url.path
    if request.state.session is None and not path.startswith(PUBLIC_PREFIXES):
        if path.startswith("/api/"):
            return JSONResponse({"error": tr("session expired")}, status_code=401)
        if request.method == "GET":
            target = path + (f"?{request.url.query}" if request.url.query else "")
            return RedirectResponse(f"/login?{urlencode({'next': target})}", status_code=303)
        return PlainTextResponse(tr("Invalid or expired session"), status_code=401)
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


# Outside the security middleware: the scheme is already the one the browser used (ADR-004).
app.add_middleware(proxy.ForwardedScheme)


def _back(url, anchor: str = "", **params) -> RedirectResponse:
    """Vuelve a `url` con el mensaje en la query; el ancla va después (si no, se pierde la query)."""
    # Provider errors end up here: the origin IP never goes into a URL (ADR-003).
    query = urlencode({k: error_reporting.scrub_origin(str(v)) for k, v in params.items() if v})
    target = f"{url}?{query}" if query else str(url)
    return RedirectResponse(target + (f"#{anchor}" if anchor else ""), status_code=303)


def _actor(request: Request) -> str:
    session = getattr(request.state, "session", None)
    return session.user.username if session else "panel"


# One date format in the whole panel (i18n.format_when): "14 Nov, 22:50 UTC" inside <time>.
# `when` is the full date; `hhmm` drops the day when it is today (status lines that refresh
# often); `day` is the date alone. All return markup: inside a translated string use _m().
templates.env.filters["when"] = i18n.when_markup
templates.env.filters["hhmm"] = lambda value: i18n.when_markup(value, compact=True)
templates.env.filters["when_text"] = i18n.format_when
templates.env.filters["day"] = lambda value: i18n.when_markup(value, time=False)
templates.env.filters["bytes"] = human_bytes
templates.env.globals["ENV_REASONS"] = envfile.REASONS
templates.env.globals["DEPLOY_GUIDE"] = "https://github.com/Pepebits/multi-cdn/blob/main/deploy/README.md"


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


def _require_domain(s: State, name: str) -> None:
    """404 if the domain is not in the inventory (every /dominios/{name}/… route checks it)."""
    if name not in s.inventory.domains:
        raise HTTPException(404, tr("Domain not in the inventory"))


def _state(request: Request) -> State:
    return request.app.state.mc


def access_channel(request: Request) -> dict:
    """Por dónde ha llegado esta petición, deducido de la dirección usada (no se puede ver si el
    canal está cifrado, pero sí si el panel se ha publicado con un nombre que no debería)."""
    host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]").lower()
    if request.headers.get("tailscale-user-login") or host.endswith(".ts.net"):
        return {"tone": "ok", "label": tr("Access through Tailscale"),
                "help": tr("The request comes through tailscale serve (*.ts.net name or Tailscale identity).")}
    if host in ("localhost", "127.0.0.1", "::1"):
        return {"tone": "ok", "label": tr("Access through an SSH tunnel or locally"),
                "help": tr("Accessed through localhost: an SSH tunnel or the server itself.")}
    return {"tone": "warn", "label": tr("Access through {host}: check that it is not exposed", host=host or tr("unknown address")),
            "help": tr("The panel should listen only on 127.0.0.1 and be used through an SSH tunnel or a private network.")}


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
        "flash": {"card": request.query_params.get("card"), "ok": request.query_params.get("ok"),
                  "error": request.query_params.get("error")},
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


async def _after_inventory_change(state: State) -> None:
    state.reload()
    if os.environ.get("MULTICDN_OFFLINE") != "1":
        asyncio.create_task(refresh_dns(state))
        asyncio.create_task(refresh_cloudflare(state))


# ---------------------------------------------------------------- Resumen

def getting_started(s: State, domains) -> list[dict]:
    """Setup checklist on the overview, in the order of deploy/README.md. The template holds
    the texts; this only says which steps are done."""
    sec = s.secrets
    return [
        {"key": "cloudflare", "done": bool(s.creds.list("cloudflare")), "href": "/ajustes/cuentas"},
        {"key": "gcore", "done": bool(s.creds.list("gcore")), "href": "/ajustes/cuentas"},
        {"key": "origin", "done": bool(s.inventory.origin_ips), "href": "/ajustes/servidores"},
        {"key": "domains", "done": any(d.cloudflare_credential for d in s.inventory.domains.values()),
         "href": "/dominios/importar"},
        {"key": "prepare", "done": any(d.gcore_ready for d in domains), "href": "/dominios"},
        {"key": "alerts", "done": bool((sec.get("telegram_token") and sec.get("telegram_chat_id"))
                                       or (sec.get("smtp_url") and sec.get("alert_email_to"))),
         "href": "/ajustes/notificaciones"},
        {"key": "live", "done": not s.dry_run, "href": "/ajustes/cambio#modo"},
    ]


@app.get("/", response_class=HTMLResponse)
async def resumen(request: Request):
    s = _state(request)
    domains = s.views()
    steps = getting_started(s, domains)
    return templates.TemplateResponse(request, "resumen.html", _common(
        request, "resumen",
        domains=domains,
        exposed=[d for d in domains if d.status == "origin"],
        changes={d.name: failover.change_indicator(s, d.name) for d in domains},
        autos={d.name: failover.describe(s, d.name) for d in domains},
        events=s.events.list(limit=5),
        origin_configured=bool(s.inventory.origin_ips),
        origin_health=list(s.origin_health.values()),
        gcore_configured=any(d.gcore_ready for d in domains),
        usage=list(s.gcore_usage.values()),
        match_now=s.calendar.active(datetime.now(UTC), failover.match_lead(s, "critical")) if s.calendar else None,
        match_next=s.calendar.upcoming(datetime.now(UTC)) if s.calendar else None,
        calendar_error=s.calendar_error,
        steps=steps if not all(st["done"] for st in steps) else None,
        calendar_loaded=s.calendar is not None,
        problems=open_problems(s),
    ))


# ---------------------------------------------------------------- Dominios

@app.get("/dominios", response_class=HTMLResponse)
async def dominios(request: Request):
    s = _state(request)
    return templates.TemplateResponse(request, "dominios.html", _common(
        request, "dominios",
        domains=s.views(),
        changes={n: failover.change_indicator(s, n) for n in s.inventory.domains},
        autos={n: failover.describe(s, n) for n in s.inventory.domains},
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
    s.events.add(actor=_actor(request), kind="config", domain=domain, summary=tn("Domain added with {n} hostnames", n=len(hosts)))
    await _after_inventory_change(s)
    return _back(request.url_for("dominio", name=domain), ok=tr("Domain added"))


@app.get("/dominios/importar", response_class=HTMLResponse)
async def importar(request: Request, cuenta: int | None = None, zone: str | None = None):
    s = _state(request)
    cf_creds = s.creds.list("cloudflare")
    if not cf_creds:
        return _back(request.url_for("ajustes_cuentas"), error=tr("Add a Cloudflare credential first"))
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
        return _back(request.url_for("dominios"), error=tr("Invalid Cloudflare credential"))
    token = s.creds.secret(cuenta)
    zone_id = str(form.get("zone_id", ""))
    if not token or not zone_id:
        return _back(request.url_for("dominios"), error=tr("The credential or the zone is missing"))
    zones = {z["id"]: z for z in await cf.list_zones(token)}
    if zone_id not in zones:
        return _back(request.url_for("importar"), error=tr("Zone not found in the account"))
    records = {r["id"]: r for r in await cf.list_web_records(token, zone_id)}
    chosen = [records[rid] for rid in form.getlist("record") if rid in records]
    if not chosen:
        return _back(request.url_for("importar"), cuenta=cuenta, zone=zone_id, error=tr("Select at least one record"))
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
                 summary=tn("Imported {n} hostnames from Cloudflare", n=len(chosen)))
    await _after_inventory_change(s)
    return _back(request.url_for("dominio", name=domain), ok=tr("Imported {n} hostnames from Cloudflare", n=len(chosen)))


@app.get("/dominios/{name}", response_class=HTMLResponse)
async def dominio(request: Request, name: str):
    s = _state(request)
    _require_domain(s, name)
    view = build_domain(name, s.inventory.domains[name], s.resolutions, s.feed, s.engine.get(name).cf_ips)
    if name in s.cf_sync_errors:
        view.alerts.append(tr("Could not read its records on Cloudflare: {error}", error=s.cf_sync_errors[name]))
    if multi := s.cf_multi_records.get(name):
        view.alerts.append(tr("{hosts}: more than one A/AAAA record on Cloudflare. The switch to Gcore turns the record into a "
                              "CNAME, which Cloudflare rejects while the others exist: keep a single record per hostname",
                              hosts=", ".join(multi)))
    cert_not_after = s.inventory.domains[name].cert_not_after
    cert_until = datetime.fromisoformat(cert_not_after) if cert_not_after else None
    return templates.TemplateResponse(request, "dominio.html", _common(
        request, "dominios", d=view, cfg=s.inventory.domains[name],
        servers=list(s.inventory.servers), events=s.events.list(domain=name, limit=10),
        cf_creds=s.creds.list("cloudflare"), gc_creds=s.creds.list("gcore"), job=s.jobs.get(name),
        auto=failover.describe(s, name), maintenance_options={k: tr(v) for k, v in MAINTENANCE_OPTIONS.items()},
        origin_header=origin_header_view(s, name),
        inventory_servers={sid: bool(srv.origin_ipv4) for sid, srv in s.inventory.servers.items()},
        cert_until=cert_until,
        renew_from=cert_until - RENEW_BEFORE if cert_until else None,
        tl=domain_timeline_view(s, name),
    ))


TIMELINE_DAYS = 7


def domain_timeline_view(s: State, name: str, days: int = TIMELINE_DAYS, now: datetime | None = None) -> dict:
    """Domain page: the last `days` UTC days on Gcore, blocked and with matches (stats + charts)."""
    from . import charts, stats
    now = now or datetime.now(UTC)
    cfg = s.inventory.domains[name]
    start, end = stats.timeline_window(days, now)
    hosts = [h.name for h in cfg.hostnames if h.failover] or [h.name for h in cfg.hostnames]
    current = {h: r.provider for h in hosts if (r := s.resolutions.get(h))}
    tl = stats.domain_timeline(s.events.list(domain=name, limit=5000), hosts, current, start, end, now,
                               feed=s.feed, ips=s.engine.get(name).cf_ips,
                               matches=s.calendar.matches if s.calendar else (),
                               match_length=match_calendar.MATCH_LENGTH)
    gcore = [p for p in tl["periods"] if p.kind == "gcore"]
    return tl | {"days": days, "lanes": charts.domain_lanes(tl), "fmt_duration": stats.fmt_duration,
                 "gcore_count": len(gcore), "blocked_count": sum(p.kind == "blocked" for p in tl["periods"]),
                 "match_count": sum(p.kind == "match" for p in tl["periods"]),
                 "gcore_total": stats.fmt_duration(sum((p.duration(now) for p in gcore), timedelta(0))),
                 "has_feed": s.feed is not None, "has_ips": bool(s.engine.get(name).cf_ips)}


@app.post("/dominios/{name}/hostnames/{host}/quitar")
async def hostname_quitar(request: Request, name: str, host: str):
    s = _state(request)
    url = request.url_for("dominio", name=name)
    domain = s.inventory.domains.get(name)
    if domain is None or host not in {h.name for h in domain.hostnames}:
        raise HTTPException(404)
    if len(domain.hostnames) == 1:
        return _back(url, error=tr("It is the last hostname: delete the whole domain if you no longer want to monitor it"))
    s.store.delete_hostname(host)
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=tn("{host} removed from the inventory (DNS unchanged)", host=host))
    await _after_inventory_change(s)
    return _back(url, ok=tr("{host} removed from the inventory. Its DNS has not been changed.", host=host))


@app.post("/dominios/{name}/configuracion")
async def dominio_config(
    request: Request, name: str, priority: str = Form(...), policy: str = Form(...), zone_id: str = Form(""),
    cloudflare_credential: str = Form(""), gcore_credential: str = Form(""),
):
    s = _state(request)
    url = request.url_for("dominio", name=name)
    _require_domain(s, name)
    try:
        ids = {}
        for provider, raw in (("cloudflare", cloudflare_credential), ("gcore", gcore_credential)):
            ids[provider] = int(raw) if raw else None
            if ids[provider] is not None and s.creds.get(ids[provider]).provider != provider:
                raise ValueError(tr("credential of the wrong provider"))
        s.store.upsert_domain(name, policy=policy, priority=priority, zone_id=zone_id.strip() or None)
        s.store.set_credentials(name, ids["cloudflare"], ids["gcore"])
    except ValueError as exc:
        return _back(url, error=str(exc))
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=tn("Priority {priority}, policy {policy}", priority=priority, policy=policy))
    await _after_inventory_change(s)
    return _back(url, ok=tr("Settings saved"))


@app.post("/dominios/{name}/hostnames")
async def hostnames_guardar(request: Request, name: str):
    """Guarda la tabla de hostnames (servidor y destino Gcore) y añade los nuevos."""
    s = _state(request)
    url = request.url_for("dominio", name=name)
    _require_domain(s, name)
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
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=tn("Hostnames updated"))
    await _after_inventory_change(s)
    return _back(url, ok=tr("Hostnames saved"))


def origin_header_view(s: State, name: str) -> dict:
    """Si cada CDN tiene aplicado el secreto actual (por huella), para la ficha del dominio."""
    from .gcore_setup import fingerprint, origin_secret
    domain = s.inventory.domains[name]
    out = {}
    for cdn in ("cloudflare", "gcore"):
        applied = s.events.get_value(f"origin_header_{cdn}:{name}")
        current = fingerprint(origin_secret(s.secrets, cdn))
        if cdn == "gcore" and not domain.gcore_resource_id:
            out[cdn] = ("nodata", tr("Not prepared"))
        elif not applied:
            out[cdn] = ("blocked", tr("Not applied"))
        elif applied != current:
            out[cdn] = ("blocked", tr("Old secret"))
        else:
            out[cdn] = ("free", tr("Up to date"))
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
        return _back(url, "cabecera", error=tr("Assign a Cloudflare credential and zone to the domain"))
    secret = origin_secret(s.secrets, "cloudflare")
    try:
        outcome = await cf.ensure_origin_header(token, domain.zone_id, secret)
    except (RuntimeError, httpx.HTTPError) as exc:
        s.events.add(actor=_actor(request), kind="error", domain=name, summary=tn("Secret header on Cloudflare: {error}", error=exc))
        return _back(url, "cabecera", error=tr("Could not apply it on Cloudflare: {error}", error=exc))
    s.events.set_value(f"origin_header_cloudflare:{name}", fingerprint(secret))
    if outcome in ORIGIN_RULE_EVENT:  # cloudflare.py returns Spanish codes
        summary, msg = tn(ORIGIN_RULE_EVENT[outcome]), tr(ORIGIN_RULE_FLASH[outcome])
    else:
        summary = tn("Secret header on Cloudflare: rule {outcome}", outcome=outcome)
        msg = tr("Cloudflare rule {outcome}: requests to the origin carry the secret header", outcome=outcome)
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=summary)
    return _back(url, "cabecera", ok=msg)


ORIGIN_RULE_EVENT = {
    "creada": N_("Secret header on Cloudflare: rule created"),
    "actualizada": N_("Secret header on Cloudflare: rule updated"),
    "sin cambios": N_("Secret header on Cloudflare: rule unchanged"),
}
ORIGIN_RULE_FLASH = {
    "creada": N_("Cloudflare rule created: requests to the origin carry the secret header"),
    "actualizada": N_("Cloudflare rule updated: requests to the origin carry the secret header"),
    "sin cambios": N_("Cloudflare rule unchanged: requests to the origin carry the secret header"),
}


@app.post("/dominios/{name}/gcore/preparar")
async def gcore_preparar(request: Request, name: str):
    s = _state(request)
    _require_domain(s, name)
    job = s.jobs.get(name)
    if job and not job.done:
        return _back(request.url_for("dominio", name=name), error=tr("A preparation is already in progress"))
    job = s.jobs[name] = Job(domain=name)
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=tn("Gcore preparation started"))
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
    if confirm.strip().lower() != name.lower():
        return _back(back, error=tr("Type the domain name to delete it"))
    if dns_action not in ("cloudflare", "gcore", "none"):
        return _back(back, error=tr("Invalid option"))
    if dns_action == "gcore" and delete_gcore:
        return _back(back, error=tr("You cannot leave it on Gcore and delete its Gcore resource at the same time"))
    if delete_gcore and domain.gcore_resource_id and any(
            (r := s.resolutions.get(h.name)) is None or r.provider not in ("cloudflare",) for h in domain.hostnames if h.failover):
        # El DNS tarda en propagar (y en simulación ni siquiera cambia): borrar ahora el recurso
        # dejaría la web apuntando a nada.
        return _back(back, error=tr("Its DNS is not on Cloudflare yet. Return it to Cloudflare first, wait until the "
                                    "public DNS shows it there, then delete the domain and its Gcore resource"))
    async with s.engine_lock:
        return await _delete_domain(request, s, name, domain, back, dns_action, delete_gcore)


async def _delete_domain(request, s, name, domain, back, dns_action, delete_gcore):
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
                    raise ValueError(tn("{hostname} has no Gcore target", hostname=h.name))
                changes.append((h, plan_to_gcore(h.name, h.gcore_target), provider))
        for h, change, provider in changes:
            await client.apply(domain.zone_id, h.cloudflare_record_id, change)
            diff.append([h.name, failover.dns_before(provider), change.describe()])
        if delete_gcore and domain.gcore_resource_id:
            token = s.creds.secret(domain.gcore_credential)
            if not token:
                raise ValueError(tn("There is no Gcore credential to delete the resource"))
            await gcore.delete_resource(token, domain.gcore_resource_id)
    except (OriginExposureError, ValueError, RuntimeError, httpx.HTTPError) as exc:
        s.events.add(actor=_actor(request), kind="error", domain=name, summary=tn("Not deleted: {error}", error=exc))
        return _back(back, error=tr("It has not been deleted: {error}", error=exc))

    s.store.delete_domain(name)
    s.engine.forget(name)
    alerts.forget(s, f"auto_not_ready:{name}")
    where = DELETE_WHERE[dns_action]
    gcore_deleted = bool(delete_gcore and domain.gcore_resource_id)

    def outcome(t):
        return t(where) + (" · " + t(GCORE_DELETED) if gcore_deleted else "")

    s.events.add(actor=_actor(request), kind="config", domain=name, transition=None,
                 summary=tn("Domain deleted; {outcome}", outcome=outcome(tn)),
                 dns_diff=diff, simulated=client.dry_run and bool(diff))
    await _after_inventory_change(s)
    if client.dry_run and diff:
        msg = tr("{domain} deleted; {outcome} (simulated DNS changes)", domain=name, outcome=outcome(tr))
    else:
        msg = tr("{domain} deleted; {outcome}", domain=name, outcome=outcome(tr))
    return _back(request.url_for("dominios"), ok=msg)


GCORE_DELETED = N_("Gcore resource deleted")
DELETE_WHERE = {"cloudflare": N_("it stays on Cloudflare"), "gcore": N_("it stays on Gcore"), "none": N_("its DNS stays unchanged")}


@app.post("/dominios/{name}/volver")
async def volver_cloudflare(request: Request, name: str, confirm: str = Form("")):
    """Restaura en Cloudflare (con proxy) los hostnames que no estén ya en Cloudflare."""
    s = _state(request)
    _require_domain(s, name)
    url = request.url_for("dominio", name=name)
    if confirm.strip().lower() != name.lower():
        return _back(url, error=tr("Type the domain name to confirm"))
    async with s.engine_lock:  # no cruzarse con un ciclo del motor
        try:
            diff, simulated = await failover.return_to_cloudflare(s, name, force_all=s.dry_run and s.engine.get(name).sim_backup is True)
        except SwitchFailed as exc:
            s.events.add(actor=_actor(request), kind="error", domain=name, summary=tn("Return to Cloudflare failed: {error}", error=exc), dns_diff=exc.diff)
            return _back(url, error=tr("Could not return to Cloudflare: {error}", error=exc))
        if not diff:
            return _back(url, ok=tr("All hostnames were already on Cloudflare"))
        s.engine.manual_change(name, to_backup=False, simulated=simulated)
    s.events.add(actor=_actor(request), kind="switch", domain=name, transition="GCORE → CF",
                 summary=tn("Manual return to Cloudflare from the panel"), dns_diff=diff, simulated=simulated)
    await _after_inventory_change(s)
    if not simulated and os.environ.get("MULTICDN_OFFLINE") != "1":
        asyncio.create_task(recheck_dns_soon(s))
    if simulated:
        msg = tr("Simulated return (dry run): DNS was not touched. Automatic switching for this domain is paused for 1 h")
    else:
        msg = tr("Return to Cloudflare applied; it may take a few minutes to propagate. "
                 "Automatic switching for this domain is paused for 1 h")
    return _back(url, ok=msg)


@app.post("/dominios/{name}/cambiar")
async def cambiar(request: Request, name: str, target: str = Form(...), confirm: str = Form("")):
    s = _state(request)
    _require_domain(s, name)
    url = request.url_for("dominio", name=name)
    if confirm.strip().lower() != name.lower():
        return _back(url, error=tr("Type the domain name to confirm"))
    if target != "gcore":
        return _back(url, error=tr("Target not available yet"))
    async with s.engine_lock:  # no cruzarse con un ciclo del motor
        try:
            diff, simulated = await failover.switch_to_gcore(s, name)
        except SwitchFailed as exc:
            if exc.diff:
                s.events.add(actor=_actor(request), kind="error", domain=name, summary=str(exc), dns_diff=exc.diff)
            return _back(url, error=str(exc))
        s.engine.manual_change(name, to_backup=True, simulated=simulated)
    s.events.add(actor=_actor(request), kind="switch", domain=name, transition="CF → GCORE",
                 summary=tn("Manual switch to Gcore from the panel"), dns_diff=diff, simulated=simulated)
    await _after_inventory_change(s)
    if not simulated and os.environ.get("MULTICDN_OFFLINE") != "1":
        asyncio.create_task(recheck_dns_soon(s))
    if simulated:
        msg = tr("Simulated switch (dry run): DNS was not touched. Automatic switching for this domain is paused for 1 h")
    else:
        msg = tr("Switch to Gcore applied; it may take a few minutes to propagate. "
                 "Automatic switching for this domain is paused for 1 h")
    return _back(url, ok=msg)


MAINTENANCE_OPTIONS = {1: "1 h", 6: "6 h", 24: "24 h", 168: N_("7 days"), 0: N_("until resumed")}


@app.post("/dominios/{name}/automatico/mantenimiento")
async def automatico_mantenimiento(request: Request, name: str, horas: int = Form(...)):
    s = _state(request)
    _require_domain(s, name)
    url = request.url_for("dominio", name=name)
    if horas not in MAINTENANCE_OPTIONS:
        return _back(url, error=tr("Invalid duration"))
    until = datetime.now(UTC) + timedelta(hours=horas) if horas else None
    # Sin esperar al ciclo en curso: _act vuelve a mirar la pausa en la base de datos justo antes
    # de tocar el DNS, así que la pausa también frena un cambio que ya estaba comprobando Gcore.
    s.engine.maintenance(name, until)
    s.events.add(actor=_actor(request), kind="config", domain=name,
                 summary=tn("Maintenance: automatic switching paused ({duration})", duration=tn(MAINTENANCE_OPTIONS[horas])))
    return _back(url, ok=tr("Automatic switching paused ({duration}). Alerts keep coming.", duration=tr(MAINTENANCE_OPTIONS[horas])))


@app.post("/dominios/{name}/automatico/reanudar")
async def automatico_reanudar(request: Request, name: str):
    s = _state(request)
    _require_domain(s, name)
    s.engine.resume(name)
    s.events.add(actor=_actor(request), kind="config", domain=name, summary=tn("Automatic switching resumed"))
    asyncio.create_task(run_engine(s))
    return _back(request.url_for("dominio", name=name), ok=tr("Automatic switching resumed"))


@app.post("/dominios/{name}/automatico/descartar")
async def automatico_descartar(request: Request, name: str):
    s = _state(request)
    _require_domain(s, name)
    s.engine.clear_error(name)
    return _back(request.url_for("dominio", name=name), ok=tr("Last failure dismissed"))


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
            past = await _cached(s, ("fd", start.date()), lambda: match_calendar.fetch_past_laliga(s.client, token, start, end))
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
        try:
            by_resource |= await _cached(s, ("gc", cred.id, start.date()), lambda: gcore.traffic_series(token, start, end))
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
            if e.is_real_switch and start <= e.ts < end and any(d[0] in hosts for d in e.dns_diff):
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


# ---------------------------------------------------------------- Ajustes
# Six tabs in setup order (_macros.settings_tabs): cuentas, servidores, notificaciones, cambio
# (automatic switching), sistema, cuenta. Every save returns to its card (?card=<id>#<id>) and
# the card shows the message (_macros.card_flash).

SETTINGS_TABS = {"cuentas": N_("Provider accounts"), "servidores": N_("Servers"), "notificaciones": N_("Notifications"),
                 "cambio": N_("Automatic switching"), "sistema": N_("System"), "cuenta": N_("My account")}


@app.get("/ajustes")
async def ajustes(request: Request):
    return RedirectResponse(request.url_for("ajustes_cuentas"), status_code=303)


@app.get("/ajustes/operacion")
async def ajustes_operacion(request: Request):
    """Before 0.3.1: Settings → Operation, now Automatic switching (and System)."""
    return RedirectResponse(request.url_for("ajustes_cambio"), status_code=301)


def _card(url, card: str, **params) -> RedirectResponse:
    """Back to the settings card that was saved, with its message inside the card."""
    return _back(url, card, card=card, **params)


def _settings_page(request: Request, tab: str, template: str, **extra) -> HTMLResponse:
    return templates.TemplateResponse(request, template, _common(
        request, "ajustes", tab=tab, tab_label=tr(SETTINGS_TABS[tab]), settings_cards=True, **extra))


def _env_warning(reason: str | None, keys: str) -> str:
    """Why a value saved in the panel is not in config/secrets.env, and what to do ("" if it is)."""
    if not reason:
        return ""
    return tr("Could not update config/secrets.env ({reason}): set {keys} there yourself, or the file's value "
              "comes back on the next restart.", reason=tr(envfile.REASONS.get(reason, envfile.REASONS["error"])), keys=keys)


def _with_env_warning(message: str, reason: str | None, key: str) -> str:
    """A save in the panel whose write-back to the secrets file failed: say it in the same message."""
    if not reason:
        return message
    return f"{message.rstrip('.')}. {_env_warning(reason, key)}"


def _secret_save(s: State, name: str, value: str | None) -> str | None:
    return envfile.save(s.secrets, name, value)


def _env_view(source: str | None, at, env: str | None, state: str | None, error: str | None) -> dict:
    return {"source": source, "updated_at": at, "env": env, "env_state": state, "env_error": error}


def env_mismatches(s: State) -> list[dict]:
    """Secrets whose value in config/secrets.env differs from the panel's (the panel could not
    write the file): on the next start the file replaces them. For Settings → System and open problems."""
    out = []
    for st in s.secrets.all_status():
        if st.env_state in ("differs", "env_only"):
            out.append({"label": st.label, "env": st.env, "state": st.env_state, "error": st.env_error})
    for c in s.creds.list():
        info = s.creds.env_status(c)
        if info["state"] == "differs":
            out.append({"label": tr("{provider} token", provider=c.provider_label), "env": info["env"],
                        "state": "differs", "error": info["error"]})
    for env in s.creds.env_removed():
        out.append({"label": env, "env": env, "state": "env_only", "error": s.secrets.env_error(env)})
    return out


# ---- 1. Cuentas de proveedor

async def _check_credential(s: State, cred_id: int) -> tuple[bool, str]:
    cred, secret = s.creds.get(cred_id), s.creds.secret(cred_id)
    if not secret:
        ok, msg, scope = False, tn("Cannot decrypt it: has the master key changed?"), None
    elif cred.provider == "cloudflare":
        ok, msg = await cf.verify_token(secret)
        scope = None
        if ok:
            zones = await cf.list_zones(secret)
            scope = ", ".join(z["name"] for z in zones) or tn("no zone")
            msg = tn("Token active · access to {n} zone(s)", n=len(zones))
            assigned = [z["name"] for z in zones if z["name"] in s.inventory.domains and s.store.assign_zone(z["name"], z["id"], cred_id)]
            if assigned:
                msg = tn("Token active · access to {n} zone(s) · assigned to {domains}", n=len(zones), domains=", ".join(assigned))
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
    creds = []
    for c in s.creds.list():
        info = s.creds.env_status(c)
        creds.append((c, s.creds.usage(c.id),
                      _env_view(info["source"], info["at"], info["env"], info["state"], info["error"])))
    return _settings_page(request, "cuentas", "ajustes_cuentas.html", creds=creds, providers=PROVIDERS,
                          key_on_disk=s.secrets.key_on_disk, usage=s.gcore_usage, env_removed=s.creds.env_removed())


@app.post("/ajustes/cuentas")
async def cuenta_crear(request: Request, provider: str = Form(...), label: str = Form(""), secret: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_cuentas")
    try:
        cred_id = s.creds.add(provider, label, secret)
    except ValueError as exc:
        return _card(url, "nueva-cuenta", error=str(exc))
    s.events.add(actor=_actor(request), kind="config", summary=tn("{provider} credential added: {label}", provider=PROVIDERS[provider], label=label.strip()))
    try:
        ok, msg = await _check_credential(s, cred_id)
    except httpx.HTTPError as exc:
        ok, msg = False, tr("Saved, but it could not be verified: {error}", error=type(exc).__name__)
    card = f"cuenta-{cred_id}"
    if ok:
        return _card(url, card, ok=tr('"{label}" saved. {msg}', label=label.strip(), msg=msg))
    return _card(url, card, error=tr('"{label}" saved, but the verification failed: {msg}', label=label.strip(), msg=msg))


@app.post("/ajustes/cuentas/{cred_id}/probar")
async def cuenta_probar(request: Request, cred_id: int):
    return await _probe_credential(request, cred_id)


async def _probe_credential(request: Request, cred_id: int, extra: str = "") -> RedirectResponse:
    s = _state(request)
    try:
        ok, msg = await _check_credential(s, cred_id)
    except (ValueError, httpx.HTTPError) as exc:
        ok, msg = False, str(exc) or type(exc).__name__
    if extra:
        msg = f"{extra} · {msg}"
    return _card(request.url_for("ajustes_cuentas"), f"cuenta-{cred_id}", **({"ok": msg} if ok else {"error": msg}))


@app.post("/ajustes/cuentas/{cred_id}/rotar")
async def cuenta_rotar(request: Request, cred_id: int, secret: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_cuentas")
    if not secret.strip():
        return _card(url, f"cuenta-{cred_id}", error=tr("Enter the new credential"))
    try:
        s.creds.rotate(cred_id, secret)
        cred = s.creds.get(cred_id)
    except ValueError as exc:
        return _card(url, f"cuenta-{cred_id}", error=str(exc))
    s.events.add(actor=_actor(request), kind="config", summary=tn("Credential rotated: {label}", label=cred.label))
    extra = ""
    if (linked := s.creds.env_credential(cred.provider)) and linked.id == cred_id:
        env = ENV_TOKENS[cred.provider]
        extra = _env_warning(envfile.write_back(s.secrets, env, secret), env)
    return await _probe_credential(request, cred_id, extra)


@app.post("/ajustes/cuentas/{cred_id}/eliminar")
async def cuenta_eliminar(request: Request, cred_id: int):
    s = _state(request)
    url = request.url_for("ajustes_cuentas")
    try:
        cred = s.creds.get(cred_id)
        linked = s.creds.env_credential(cred.provider)
        s.creds.delete(cred_id)
    except ValueError as exc:
        return _card(url, f"cuenta-{cred_id}", error=str(exc))
    s.events.add(actor=_actor(request), kind="config", summary=tn("Credential deleted: {label}", label=cred.label))
    msg = tr('"{label}" deleted', label=cred.label)
    if linked and linked.id == cred_id:
        env = ENV_TOKENS[cred.provider]
        msg = _with_env_warning(msg, envfile.write_back(s.secrets, env, None), env)
    return _card(url, "lista-cuentas", ok=msg)


# ---- 2. Servidores

def _ip_hint(ip: str | None) -> str | None:
    """Only the last part of the origin IP, like any other secret: "···.10"."""
    if not ip:
        return None
    return "···." + ip.rsplit(".", 1)[-1] if "." in ip else "···:" + ip.rsplit(":", 1)[-1]


@app.get("/ajustes/servidores", response_class=HTMLResponse)
async def ajustes_servidores(request: Request):
    s = _state(request)
    servers = [{"id": sid, "private_address": srv.private_address, "ip_hint": _ip_hint(s.secrets.get(origin_key(sid))),
                "hostnames": sum(h.server == sid for d in s.inventory.domains.values() for h in d.hostnames)}
               for sid, srv in s.inventory.servers.items()]
    from . import firewall_status
    fw = firewall_status.read()
    return _settings_page(request, "servidores", "ajustes_servidores.html", servers=servers, fw=fw,
                          fw_changes=firewall_status.changes(), fw_problem=fw.problem(datetime.now(UTC)) if fw else None)


@app.post("/ajustes/servidores")
async def servidor_guardar(request: Request, server_id: str = Form(...), origin_ipv4: str = Form(""),
                           private_address: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_servidores")
    sid = server_id.strip().lower()
    try:
        s.store.upsert_server(sid, origin_ipv4.strip() or None, private_address.strip() or None)
    except ValueError as exc:
        return _card(url, "nuevo-servidor", error=tr("Server: {error}", error=exc))
    s.events.add(actor=_actor(request), kind="config", summary=tn("Server {server} saved", server=server_id))
    await _after_inventory_change(s)
    return _card(url, f"servidor-{sid}", ok=tr("Server {server} saved", server=sid))


@app.post("/ajustes/servidores/{server_id}/editar")
async def servidor_editar(request: Request, server_id: str, new_id: str = Form(...), origin_ipv4: str = Form(""),
                          private_address: str = Form("")):
    """An empty IP field keeps the current IP (it is never shown); "Remove IP" removes it."""
    s = _state(request)
    url = request.url_for("ajustes_servidores")
    if server_id not in s.inventory.servers:
        raise HTTPException(404)
    try:
        s.store.validate_server(origin_ipv4.strip() or None, private_address.strip() or None)  # before renaming
        s.store.rename_server(server_id, new_id)
        target = new_id.strip().lower()
        s.store.upsert_server(target, origin_ipv4.strip() or None, private_address.strip() or None)
    except ValueError as exc:
        return _card(url, f"servidor-{server_id}", error=tr("Server: {error}", error=exc))
    s.events.add(actor=_actor(request), kind="config",
                 summary=(tn("Server {server} updated (now {new})", server=server_id, new=target) if target != server_id
                          else tn("Server {server} updated", server=server_id)))
    await _after_inventory_change(s)
    return _card(url, f"servidor-{target}", ok=tr("Server {server} saved", server=target))


def hostnames_on_backup(s: State, server_id: str) -> list[str]:
    """Hostnames of this server that are on Gcore now (public DNS or the live Cloudflare record):
    returning them to Cloudflare needs the origin IP."""
    return sorted(h.name for d in s.inventory.domains.values() for h in d.hostnames
                  if h.server == server_id and (((r := s.resolutions.get(h.name)) and r.provider == "gcore")
                                                or (s.cf_live.get(h.name) or {}).get("to_backup")))


@app.post("/ajustes/servidores/{server_id}/quitar-ip")
async def servidor_quitar_ip(request: Request, server_id: str):
    s = _state(request)
    if server_id not in s.inventory.servers:
        raise HTTPException(404)
    if on_backup := hostnames_on_backup(s, server_id):
        return _card(request.url_for("ajustes_servidores"), f"servidor-{server_id}", error=trn(
            "{hostnames} is served by Gcore now and needs this IP to go back to Cloudflare: switch it back first",
            "{hostnames} are served by Gcore now and need this IP to go back to Cloudflare: switch them back first",
            len(on_backup), hostnames=", ".join(on_backup)))
    s.secrets.delete(origin_key(server_id))
    s.events.add(actor=_actor(request), kind="config", summary=tn("Server {server}: origin IP removed", server=server_id))
    await _after_inventory_change(s)
    return _card(request.url_for("ajustes_servidores"), f"servidor-{server_id}",
                 ok=tr("Origin IP of {server} removed", server=server_id))


@app.post("/ajustes/servidores/{server_id}/eliminar")
async def servidor_eliminar(request: Request, server_id: str):
    s = _state(request)
    url = request.url_for("ajustes_servidores")
    try:
        s.store.delete_server(server_id)
    except ValueError as exc:
        return _card(url, f"servidor-{server_id}", error=str(exc))
    s.events.add(actor=_actor(request), kind="config", summary=tn("Server {server} deleted", server=server_id))
    await _after_inventory_change(s)
    return _card(url, "servidores-titulo", ok=tr("Server {server} deleted", server=server_id))


# ---- 3. Notificaciones

@app.get("/ajustes/notificaciones", response_class=HTMLResponse)
async def ajustes_notificaciones(request: Request):
    s = _state(request)
    failures, notes = heartbeat.checks(s)
    return _settings_page(request, "notificaciones", "ajustes_notificaciones.html",
                          fields={f.name: f for f in s.secrets.all_status()}, beat=s.last_beat,
                          beat_failures=[tr(x) for x in failures], beat_notes=[tr(x) for x in notes],
                          notify_lang=i18n.notify_lang(), quota_gb=s.events.get_setting("gcore_quota_gb"))


CHANNELS = {"telegram": ("telegram_token", "telegram_chat_id"), "email": ("smtp_url", "alert_email_to")}
NOTIFY_FIELDS = {name for names in CHANNELS.values() for name in names}


@app.post("/ajustes/notificaciones/canal/{canal}")
async def canal_guardar(request: Request, canal: str):
    """Guarda todos los campos rellenos del canal; los vacíos conservan su valor actual."""
    s = _state(request)
    if canal not in CHANNELS:
        raise HTTPException(404)
    form = await request.form()
    saved, failed, failed_keys = [], None, []
    values = {name: str(form.get(name, "")).strip() for name in CHANNELS[canal]}
    if any(envparse.bad_chars(v) for v in values.values()):
        return _card(request.url_for("ajustes_notificaciones"), f"canal-{canal}", error=tr("Enter a value"))
    for name, value in values.items():
        if value:
            if reason := _secret_save(s, name, value):
                failed, failed_keys = reason, [*failed_keys, CREDENTIALS[name][1]]
            saved.append(CREDENTIALS[name][0])  # translated at use: tr()/tn() below
    url = request.url_for("ajustes_notificaciones")
    if not saved:
        return _card(url, f"canal-{canal}", error=tr("You have not entered any new value"))
    s.events.add(actor=_actor(request), kind="config",
                 summary=tn("Notifications: {fields} updated", fields=", ".join(tn(x) for x in saved)))
    msg = tr("Saved: {fields}", fields=", ".join(tr(x) for x in saved))
    return _card(url, f"canal-{canal}", ok=_with_env_warning(msg, failed, ", ".join(failed_keys)))


@app.post("/ajustes/notificaciones/latido")
async def latido_guardar(request: Request, heartbeat_url: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_notificaciones")
    value = heartbeat_url.strip()
    if not heartbeat.valid_url(value):
        return _card(url, "latido", error=tr("Paste the full ping URL (https://hc-ping.com/…)"))
    host = urlparse(value).hostname or ""
    if os.environ.get("MULTICDN_OFFLINE") != "1" and not await heartbeat.host_is_public(host, s.inventory.origin_ips):
        return _card(url, "latido", error=tr("The ping URL must point to a public server: {host} does not resolve to a public address",
                                             host=host))
    reason = _secret_save(s, "heartbeat_url", value)
    s.events.add(actor=_actor(request), kind="config", summary=tn("External heartbeat: URL updated"))
    return await _beat_now(request, _env_warning(reason, "MULTICDN_HEARTBEAT_URL"))


@app.post("/ajustes/notificaciones/latido/probar")
async def latido_probar(request: Request):
    return await _beat_now(request)


async def _beat_now(request: Request, warning: str = "") -> RedirectResponse:
    """Sends a heartbeat now and says how it went (plus `warning`, when saving left one)."""
    s = _state(request)
    url = request.url_for("ajustes_notificaciones")
    b = await heartbeat.beat(s)
    if b is None:
        msg, ok = tr("The external heartbeat URL is missing"), False
    elif b.result != "ok":
        msg, ok = tr("Could not send the heartbeat: {result}", result=b.result), False
    elif b.ok:
        msg, ok = tr("Heartbeat sent: all good"), True
    else:
        msg, ok = tr("Heartbeat sent: failure reported ({detail})", detail=b.detail), True
    if warning:
        msg = f"{msg.rstrip('.')}. {warning}"
    return _card(url, "latido", **({"ok": msg} if ok else {"error": msg}))


# Fixed paths before /ajustes/notificaciones/{name}: the first matching route wins.
@app.post("/ajustes/notificaciones/idioma")
@app.post("/ajustes/operacion/idioma")  # before 0.3.1
async def idioma_guardar(request: Request, lang: str = Form("")):
    """Language of history, alerts and terminal output (what is stored or sent)."""
    s = _state(request)
    url = request.url_for("ajustes_notificaciones")
    code = i18n.normalize(lang)
    if code is None:
        return _card(url, "idioma", error=tr("Language not available"))
    s.events.set_value("notify_lang", code)
    i18n.set_notify(code)
    s.events.add(actor=_actor(request), kind="config",
                 summary=tn("Language of history and alerts: {language}", language=i18n.LANGS[code]))
    return _card(url, "idioma", ok=tr("Language of history and alerts saved: {language}", language=i18n.LANGS[code]))


@app.post("/ajustes/notificaciones/cuota")
@app.post("/ajustes/operacion/cuota")  # before 0.3.1
async def cuota_guardar(request: Request, gcore_quota_gb: int = Form(...)):
    s = _state(request)
    url = request.url_for("ajustes_notificaciones")
    try:
        s.events.set_setting("gcore_quota_gb", gcore_quota_gb)
    except ValueError as exc:
        return _card(url, "cuota", error=tr("Quota: {error}", error=exc))
    s.events.add(actor=_actor(request), kind="config", summary=tn("Gcore monthly quota: {gb} GB", gb=gcore_quota_gb))
    if os.environ.get("MULTICDN_OFFLINE") != "1":
        asyncio.create_task(refresh_usage(s))
    return _card(url, "cuota", ok=tr("Quota saved: {gb} GB per month", gb=gcore_quota_gb))


def _field_card(name: str) -> str:
    return "latido" if name == "heartbeat_url" else ("canal-telegram" if name.startswith("telegram") else "canal-email")


@app.post("/ajustes/notificaciones/{name}")
async def notificacion_guardar(request: Request, name: str, value: str = Form("")):
    s = _state(request)
    if name not in NOTIFY_FIELDS:
        raise HTTPException(404)
    url = request.url_for("ajustes_notificaciones")
    if not value.strip() or envparse.bad_chars(value.strip()):
        return _card(url, _field_card(name), error=tr("Enter a value"))
    reason = _secret_save(s, name, value)
    s.events.add(actor=_actor(request), kind="config", summary=tn("Notifications: {fields} updated", fields=tn(CREDENTIALS[name][0])))
    return _card(url, _field_card(name), ok=_with_env_warning(tr("{field} saved", field=tr(CREDENTIALS[name][0])),
                                                              reason, CREDENTIALS[name][1]))


@app.post("/ajustes/notificaciones/{name}/eliminar")
async def notificacion_eliminar(request: Request, name: str):
    s = _state(request)
    if name not in NOTIFY_FIELDS | {"heartbeat_url"}:
        raise HTTPException(404)
    reason = _secret_save(s, name, None)
    s.events.add(actor=_actor(request), kind="config", summary=tn("Notifications: {field} removed", field=tn(CREDENTIALS[name][0])))
    return _card(request.url_for("ajustes_notificaciones"), _field_card(name),
                 ok=_with_env_warning(tr("{field} removed", field=tr(CREDENTIALS[name][0])), reason, CREDENTIALS[name][1]))


@app.post("/ajustes/notificaciones/probar/{canal}")
async def notificacion_probar(request: Request, canal: str):
    s = _state(request)
    try:
        if canal == "telegram":
            token = s.secrets.get("telegram_token")
            ok, msg = await notify.verify_telegram(token, s.secrets.get("telegram_chat_id")) if token else (False, tr("The bot token is missing"))
        elif canal == "email":
            smtp = s.secrets.get("smtp_url")
            ok, msg = await notify.verify_smtp(smtp) if smtp else (False, tr("The SMTP server is missing"))
        else:
            raise HTTPException(404)
    except httpx.HTTPError as exc:
        ok, msg = False, tr("Network error: {error}", error=type(exc).__name__)
    return _card(request.url_for("ajustes_notificaciones"), f"canal-{canal}", **({"ok": msg} if ok else {"error": msg}))


# ---- 4. Cambio automático

FEED_REASONS = {
    "feed": N_("feed failing"),
    "calendar": N_("no match calendar"),
    "gcore": N_("domain on Gcore"),
    "blocks": N_("blocks underway"),
}


def feed_reason_text(s: State, now: datetime | None = None) -> str:
    """Why the feed is read at its current pace, for the pill on Settings → Automatic switching."""
    now = now or datetime.now(UTC)
    _seconds, reason = feed_mode(s, now)
    if reason is None:
        return tr("nothing going on")
    if reason == "match":
        match = s.calendar.active(now, max(failover.match_lead(s, p) for p in failover.PRIORITIES)) if s.calendar else None
        if match is None or match.kickoff <= now:
            return tr("match in progress")
        minutes = int((match.kickoff - now).total_seconds() // 60)
        return tr("match in {time}", time=f"{minutes // 60} h" if minutes >= 120 else f"{minutes} min")
    return tr(FEED_REASONS[reason])


def feed_option_label(seconds: int) -> str:
    if seconds == FEED_INTERVAL_OPTIONS[-1]:
        return tr("{minutes} min (default)", minutes=seconds // 60)
    return tr("{minutes} min", minutes=seconds // 60) if seconds % 60 == 0 else tr("{seconds} s", seconds=seconds)


@app.get("/ajustes/cambio", response_class=HTMLResponse)
async def ajustes_cambio(request: Request):
    s = _state(request)
    eligible = [n for n, d in s.inventory.domains.items() if failover.eligible(d)]
    on_gcore = {n for n, d in s.inventory.domains.items()
                if any((r := s.resolutions.get(h.name)) and r.provider == "gcore" for h in d.hostnames)}
    return _settings_page(
        request, "cambio", "ajustes_cambio.html", dry_run_env=s.dry_run_env, auto_on=failover.auto_enabled(s),
        auto_count=len(eligible), auto_on_gcore=len(on_gcore & set(eligible)),
        calendar=s.calendar, calendar_error=s.calendar_error, fd=s.secrets.status("football_data_token"),
        now=datetime.now(UTC),
        timings={p: {"match_lead": int(failover.match_lead(s, p).total_seconds() // 60),
                     "return_after": int(failover.return_after(s, p).total_seconds() // 60),
                     "default_lead": failover.DEFAULT_MATCH_LEAD[p], "default_wait": failover.DEFAULT_RETURN_AFTER[p]}
                 for p in failover.PRIORITIES},
        limits=failover.TIMING_LIMITS, feed_options=[(v, feed_option_label(v)) for v in FEED_INTERVAL_OPTIONS],
        feed_idle=s.events.get_setting("feed_interval"), feed_now=feed_interval(s, quiet=True),
        feed_why=feed_reason_text(s))


@app.post("/ajustes/cambio/tiempos")
@app.post("/ajustes/operacion/tiempos")  # before 0.3.1
async def tiempos_guardar(request: Request):
    """Antelación antes de un partido y espera sin bloqueos para volver, por prioridad."""
    s = _state(request)
    url = request.url_for("ajustes_cambio")
    form = await request.form()
    values = {}
    for kind, (lo, hi) in failover.TIMING_LIMITS.items():
        for p in failover.PRIORITIES:
            if form.get("reset"):
                values[(kind, p)] = failover.TIMING_DEFAULTS[kind][p]
                continue
            try:
                minutes = int(str(form.get(failover.timing_key(kind, p), "")))
            except ValueError:
                return _card(url, "tiempos", error=tr("Enter whole minutes"))
            if not lo <= minutes <= hi:
                return _card(url, "tiempos", error=tr("Times must be between {lo} and {hi} min", lo=lo, hi=hi))
            values[(kind, p)] = minutes
    for (kind, p), minutes in values.items():
        s.events.set_value(failover.timing_key(kind, p), str(minutes))
    summary = "; ".join(tn("{priority}: {lead} min before a match, back after {wait} min without blocks",
                           priority=tn(PRIORITY_NAME[p]), lead=values[("match_lead", p)], wait=values[("return_after", p)])
                        for p in failover.PRIORITIES)
    s.events.add(actor=_actor(request), kind="config", summary=tn("Switching times: {summary}", summary=summary))
    return _card(url, "tiempos", ok=tr("Default switching times restored") if form.get("reset") else tr("Switching times saved"))


PRIORITY_NAME = {"critical": N_("Critical"), "medium": N_("Medium"), "low": N_("Low")}


@app.post("/ajustes/cambio/feed")
@app.post("/ajustes/operacion/feed")  # before 0.3.1
async def feed_guardar(request: Request, seconds: str = Form("")):
    """Idle interval between block feed reads (ADR-001); the fast one (90 s) is fixed."""
    s = _state(request)
    url = request.url_for("ajustes_cambio")
    try:
        value = int(seconds)
    except ValueError:
        value = 0
    if value not in FEED_INTERVAL_OPTIONS:
        return _card(url, "feed", error=tr("Choose one of the listed intervals"))
    s.events.set_setting("feed_interval", value)
    s.events.add(actor=_actor(request), kind="config",
                 summary=tn("Block feed read every {seconds} s when nothing is going on", seconds=value))
    return _card(url, "feed", ok=tr("Feed interval saved"))


@app.post("/ajustes/cambio/automatico")
@app.post("/ajustes/operacion/automatico")  # before 0.3.1
async def automatico_global(request: Request, enabled: str = Form("")):
    s = _state(request)
    on = enabled == "1"
    s.events.set_setting("auto_switch", int(on))
    s.events.add(actor=_actor(request), kind="config",
                 summary=tn("Automatic CDN switching enabled") if on else tn("Automatic CDN switching disabled for all domains"))
    return _card(request.url_for("ajustes_cambio"), "automatico",
                 ok=tr("Automatic switching enabled") if on else tr("Automatic switching disabled"))


@app.post("/ajustes/cambio/football-data")
@app.post("/ajustes/operacion/football-data")  # before 0.3.1
async def football_data_guardar(request: Request, token: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_cambio")
    if not token.strip() or envparse.bad_chars(token.strip()):
        return _card(url, "calendario", error=tr("Enter the key"))
    reason = _secret_save(s, "football_data_token", token)
    s.events.add(actor=_actor(request), kind="config", summary=tn("football-data.org key saved"))
    await refresh_calendar(s)
    result = s.calendar.sources.get("football-data.org") if s.calendar else s.calendar_error
    if result == "ok":
        msg = tr("Key saved and verified · {n} matches in the calendar", n=len(s.calendar.matches))
        return _card(url, "calendario", ok=_with_env_warning(msg, reason, "FOOTBALL_DATA_TOKEN"))
    msg = tr("Key saved, but football-data.org is not responding properly: {result}", result=result)
    return _card(url, "calendario", error=_with_env_warning(msg, reason, "FOOTBALL_DATA_TOKEN"))


@app.post("/ajustes/cambio/football-data/quitar")
@app.post("/ajustes/operacion/football-data/eliminar")  # before 0.3.1
async def football_data_eliminar(request: Request):
    s = _state(request)
    reason = _secret_save(s, "football_data_token", None)
    s.events.add(actor=_actor(request), kind="config", summary=tn("football-data.org key removed"))
    await refresh_calendar(s)
    return _card(request.url_for("ajustes_cambio"), "calendario",
                 ok=_with_env_warning(tr("football-data.org key removed"), reason, "FOOTBALL_DATA_TOKEN"))


# ---- 5. Sistema

@app.get("/ajustes/sistema", response_class=HTMLResponse)
async def ajustes_sistema(request: Request):
    s = _state(request)
    return _settings_page(
        request, "sistema", "ajustes_sistema.html", key_on_disk=s.secrets.key_on_disk,
        ev_stats=s.events.stats(), ev_days=s.events.get_setting("events_max_days"),
        ev_rows=s.events.get_setting("events_max_rows"), error_reporting=error_reporting.status(),
        dsn=s.secrets.status("sentry_dsn"), env_file=envfile.status(s.secrets), env_mismatches=env_mismatches(s),
        env_managed=sorted(envfile.MANAGED), secrets_display=envfile.DISPLAY)


DSN_PROBLEMS = {
    "shape": N_("That is not a DSN: copy it from the project's settings (https://key@host/project)"),
    "https": N_("The DSN must use https"),
    "host": N_("The DSN must point to a public server name, not an IP address or a local name"),
}


@app.post("/ajustes/sistema/errores")
async def errores_guardar(request: Request, dsn: str = Form("")):
    s = _state(request)
    url = request.url_for("ajustes_sistema")
    value = dsn.strip()
    if not value:
        return _card(url, "errores", error=tr("Paste the DSN"))
    if problem := error_reporting.dsn_problem(value):
        return _card(url, "errores", error=tr(DSN_PROBLEMS[problem]))
    host = urlparse(value).hostname or ""
    if os.environ.get("MULTICDN_OFFLINE") != "1" and not await heartbeat.host_is_public(host, s.inventory.origin_ips):
        return _card(url, "errores", error=tr("The DSN must point to a public server: {host} does not resolve to a public address",
                                              host=host))
    reason = _secret_save(s, "sentry_dsn", value)
    await asyncio.to_thread(error_reporting.reconfigure, value)  # closes the previous client: may wait
    s.events.add(actor=_actor(request), kind="config", summary=tn("Error reporting DSN updated"))
    return _card(url, "errores", ok=_with_env_warning(tr("Error reporting DSN saved"), reason, "MULTICDN_SENTRY_DSN"))


@app.post("/ajustes/sistema/errores/quitar")
async def errores_quitar(request: Request):
    s = _state(request)
    reason = _secret_save(s, "sentry_dsn", None)
    await asyncio.to_thread(error_reporting.reconfigure, None)
    s.events.add(actor=_actor(request), kind="config", summary=tn("Error reporting DSN removed"))
    return _card(request.url_for("ajustes_sistema"), "errores",
                 ok=_with_env_warning(tr("Error reporting is off: nothing is sent"), reason, "MULTICDN_SENTRY_DSN"))


@app.post("/ajustes/sistema/errores/probar")
async def errores_probar(request: Request):
    url = request.url_for("ajustes_sistema")
    event_id = await asyncio.to_thread(error_reporting.send_test)  # waits up to 5 s for it to leave
    if not event_id:
        return _card(url, "errores", error=tr("Error reporting is off: save a DSN first"))
    return _card(url, "errores", ok=tr("Test error sent · event {id}", id=event_id))


@app.post("/ajustes/sistema/retencion")
@app.post("/ajustes/operacion/retencion")  # before 0.3.1
async def retencion_guardar(request: Request, events_max_days: int = Form(...), events_max_rows: int = Form(...)):
    s = _state(request)
    url = request.url_for("ajustes_sistema")
    try:
        s.events.set_setting("events_max_days", events_max_days)
        s.events.set_setting("events_max_rows", events_max_rows)
    except ValueError as exc:
        return _card(url, "mantenimiento", error=tr("Retention: {error}", error=exc))
    deleted = s.events.prune()
    s.events.add(actor=_actor(request), kind="config",
                 summary=tn("History retention: {days} days, at most {rows} events", days=events_max_days, rows=events_max_rows))
    return _card(url, "mantenimiento", ok=trn("Retention saved · {n} old event deleted",
                                              "Retention saved · {n} old events deleted", deleted))


@app.get("/ajustes/inventario.yaml")
async def exportar(request: Request):
    return PlainTextResponse(
        _state(request).store.export_yaml(), media_type="application/yaml",
        headers={"Content-Disposition": 'attachment; filename="inventory.yaml"'},
    )


# ---------------------------------------------------------------- Autenticación

def _client_ip(request: Request) -> str:
    return proxy.client_ip(request)


def _cookie_secure(request: Request) -> bool:
    mode = os.environ.get("MULTICDN_COOKIE_SECURE", "auto").strip().lower()
    if mode in ("0", "1", "false", "true"):
        return mode in ("1", "true")
    return request.url.scheme == "https"  # behind tailscale serve: from X-Forwarded-Proto (proxy.ForwardedScheme)


def _with_session(response: Response, request: Request, token: str | None) -> Response:
    if token is None:
        response.delete_cookie(SESSION_COOKIE, path="/")
    else:
        response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="strict", secure=_cookie_secure(request), path="/")
    return response


def _auth_page(request: Request, template: str, **ctx) -> HTMLResponse:
    return templates.TemplateResponse(request, template, {"request": request, "next": _safe_next(request.query_params.get("next"))} | ctx)


LOCK_MSG = N_("Too many failed attempts. Wait a few minutes before trying again.")


def _locked_out(request: Request, session) -> Response:
    """Lockout inside a session: the session is closed and the browser goes back to /login."""
    _state(request).auth.delete_session(session.id_hash)
    return _with_session(RedirectResponse(f"/login?{urlencode({'error': tr(LOCK_MSG)})}", status_code=303), request, None)


def _totp_attempt(request: Request, session, passed, failure: str | None = None, actor: str = "auto") -> bool | Response:
    """A code check inside a session (TOTP enrolment, password change, new recovery codes).
    It counts towards the same lockout as the login, so a stolen session cookie cannot be used
    to try codes without limit. True if `passed()`; False if not (the caller shows its error);
    a response that closes the session when the user or the IP is (or becomes) locked."""
    s = _state(request)
    user, ip = session.user, _client_ip(request)
    keys = (f"u:{user.username}", f"ip:{ip}")
    if s.auth.locked(*keys):
        return _locked_out(request, session)
    if passed():
        s.auth.register_success(*keys)
        return True
    s.auth.register_failure(*keys)
    s.events.add(actor=actor, kind="auth", summary=failure or tn("Wrong code for {user} from {ip}", user=user.username, ip=ip))
    if s.auth.locked(*keys):
        s.events.add(actor="auto", kind="auth", code=event_codes.LOGIN_LOCKED,
                     summary=tn("Access blocked after failed attempts ({user} from {ip})", user=user.username, ip=ip))
        return _locked_out(request, session)
    return False


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
        return _auth_page(request, "login.html", has_users=True, error=tr(LOCK_MSG), username=username)
    user = s.auth.check_password(username, password)
    if user is None:
        s.auth.register_failure(*keys)
        s.events.add(actor="auto", kind="auth", summary=tn('Wrong password for "{user}" from {ip}', user=username.strip()[:40], ip=_client_ip(request)))
        if s.auth.locked(*keys):
            s.events.add(actor="auto", kind="auth",
                         code=event_codes.LOGIN_LOCKED,
                         summary=tn('Access blocked after failed attempts ("{user}" from {ip})',
                                    user=username.strip()[:40], ip=_client_ip(request)))
        return _auth_page(request, "login.html", has_users=True, error=tr("Incorrect username or password."), username=username)
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
    s.events.add(actor=username, kind="auth", summary=tn("Signed in from {ip}", ip=_client_ip(request)))
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
        return RedirectResponse(f"/login?{urlencode({'error': tr('The session has expired')})}", status_code=303)
    user = pending.user
    keys = (f"u:{user.username}", f"ip:{_client_ip(request)}")
    if s.auth.locked(*keys):
        s.auth.delete_session(pending.id_hash)
        return _with_session(RedirectResponse(f"/login?{urlencode({'error': tr(LOCK_MSG)})}", status_code=303), request, None)
    code = code.strip()
    used_recovery = False
    ok = s.auth.check_totp(user.id, code)
    if not ok and "-" in code:
        ok = used_recovery = s.auth.use_recovery_code(user.id, code)
    if not ok:
        s.auth.register_failure(*keys)
        s.events.add(actor="auto", kind="auth", summary=tn("Wrong code for {user} from {ip}", user=user.username, ip=_client_ip(request)))
        if s.auth.locked(*keys):
            s.events.add(actor="auto", kind="auth",
                         code=event_codes.LOGIN_LOCKED,
                         summary=tn("Access blocked after failed attempts ({user} from {ip})",
                                    user=user.username, ip=_client_ip(request)))
        return _auth_page(request, "login_codigo.html", username=user.username, error=tr("Wrong or already used code."))
    if used_recovery:
        s.events.add(actor=user.username, kind="auth",
                     summary=tn("Signed in with a recovery code ({n} left)", n=s.auth.recovery_left(user.id)))
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
    passed = _totp_attempt(request, pending, lambda: s.auth.check_totp(user.id, code))
    if isinstance(passed, Response):
        return passed
    if not passed:
        return RedirectResponse(f"/login/alta?{urlencode({'error': tr('Wrong code: check the clock of your phone'), 'next': _safe_next(next)})}",
                                status_code=303)
    s.auth.enable_totp(user.id)
    codes = s.auth.new_recovery_codes(user.id)
    s.events.add(actor=user.username, kind="auth", summary=tn("TOTP enabled"))
    s.auth.delete_session(pending.id_hash)
    token = s.auth.create_session(user.id, "full", _client_ip(request), request.headers.get("user-agent"))
    s.events.add(actor=user.username, kind="auth", summary=tn("Signed in from {ip}", ip=_client_ip(request)))
    response = _auth_page(request, "login_recuperacion.html", codes=codes, next=_safe_next(next))
    return _with_session(response, request, token)


@app.post("/logout")
async def logout(request: Request):
    s = _state(request)
    if request.state.session:
        s.auth.delete_session(request.state.session.id_hash)
        s.events.add(actor=request.state.session.user.username, kind="auth", summary=tn("Signed out"))
    return _with_session(RedirectResponse("/login", status_code=303), request, None)


@app.get("/ajustes/cuenta", response_class=HTMLResponse)
async def ajustes_cuenta(request: Request):
    s = _state(request)
    me = request.state.session
    return _settings_page(request, "cuenta", "ajustes_cuenta.html", sessions=s.auth.list_sessions(me.user.id),
                          current_hash=me.id_hash, recovery_left=s.auth.recovery_left(me.user.id),
                          recovery_low=RECOVERY_LOW)


RECOVERY_LOW = 2  # recovery codes left that already deserve a warning (and an open problem)


def ua_summary(user_agent: str | None) -> str:
    """"Chrome · macOS" from a User-Agent header (the full text goes in a tooltip)."""
    ua = user_agent or ""
    browsers = (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"), ("FxiOS/", "Firefox"),
                ("CriOS/", "Chrome"), ("Chrome/", "Chrome"), ("Safari/", "Safari"), ("curl/", "curl"))
    systems = (("iPhone", "iOS"), ("iPad", "iPadOS"), ("Android", "Android"), ("CrOS", "ChromeOS"),
               ("Mac OS X", "macOS"), ("Macintosh", "macOS"), ("Windows", "Windows"), ("Linux", "Linux"))
    browser = next((name for mark, name in browsers if mark in ua), None)
    system = next((name for mark, name in systems if mark in ua), None)
    parts = [p for p in (browser, system) if p]
    return " · ".join(parts) if parts else (ua[:40] or "—")


templates.env.filters["ua"] = ua_summary


@app.post("/ajustes/cuenta/password")
async def cuenta_password(request: Request, current: str = Form(""), code: str = Form(""), new: str = Form(""),
                          new2: str = Form("")):
    s = _state(request)
    me = request.state.session
    url = request.url_for("ajustes_cuenta")
    passed = _totp_attempt(
        request, me,
        lambda: s.auth.check_password(me.user.username, current) is not None and s.auth.check_totp(me.user.id, code),
        failure=tn("Password change rejected: wrong credentials"), actor=me.user.username)
    if isinstance(passed, Response):
        return passed
    if not passed:
        return _card(url, "password", error=tr("The current password or the code is not correct"))
    if new != new2:
        return _card(url, "password", error=tr("The new passwords do not match"))
    try:
        s.auth.set_password(me.user.id, new)
    except ValueError as exc:
        return _card(url, "password", error=str(exc))
    closed = s.auth.close_sessions(me.user.id, except_hash=me.id_hash)
    s.events.add(actor=me.user.username, kind="auth", summary=tn("Password changed; {n} sessions closed", n=closed))
    if closed == 0:
        msg = tr("Password changed. You had no other sessions open.")
    elif closed == 1:
        msg = tr("Password changed. Your other session has been closed.")
    else:
        msg = tr("Password changed. Your other {n} sessions have been closed.", n=closed)
    return _card(url, "password", ok=msg)


@app.post("/ajustes/cuenta/recuperacion")
async def cuenta_recuperacion(request: Request, code: str = Form("")):
    s = _state(request)
    me = request.state.session
    passed = _totp_attempt(request, me, lambda: s.auth.check_totp(me.user.id, code))
    if isinstance(passed, Response):
        return passed
    if not passed:
        return _card(request.url_for("ajustes_cuenta"), "recuperacion", error=tr("Wrong TOTP code"))
    codes = s.auth.new_recovery_codes(me.user.id)
    s.events.add(actor=me.user.username, kind="auth", summary=tn("Recovery codes regenerated"))
    return _auth_page(request, "login_recuperacion.html", codes=codes, next="/ajustes/cuenta")


@app.post("/ajustes/cuenta/sesiones/{id_hash}/cerrar")
async def cuenta_cerrar_sesion(request: Request, id_hash: str):
    s = _state(request)
    me = request.state.session
    if any(x.id_hash == id_hash for x in s.auth.list_sessions(me.user.id)):
        s.auth.delete_session(id_hash)
        s.events.add(actor=me.user.username, kind="auth", summary=tn("Session closed from My account"))
    if id_hash == me.id_hash:
        return _with_session(RedirectResponse("/login", status_code=303), request, None)
    return _card(request.url_for("ajustes_cuenta"), "sesiones", ok=tr("Session closed"))


@app.get("/api/estado")
async def api_estado(request: Request):
    s = _state(request)
    return {"version": state_version(s), "dns_checked_at": s.dns_checked_at,
            "feed": s.feed.last_update if s.feed else None}


@app.get("/healthz")
async def healthz(request: Request, response: Response):
    """Are the panel's own loops alive? (ADR-002). Third-party failures (feed, calendar, tokens)
    do not count. No free text in the body: it is public."""
    s = _state(request)
    now = datetime.now(UTC)
    grace = os.environ.get("MULTICDN_OFFLINE") == "1" or now - s.started_at < heartbeat.STARTUP_GRACE
    stale = [] if grace else heartbeat.liveness(s, now)
    if stale:
        response.status_code = 503
    return {"ok": not stale, "stale": stale, "feed": s.feed is not None, "dns_checked_at": s.dns_checked_at}
