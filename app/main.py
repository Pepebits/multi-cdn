"""Controlador Multi-CDN: crea la app web, arranca las tareas periódicas y aplica la seguridad.

Las páginas están en app/routes (una sección por módulo), el estado compartido en app/state.py
y las tareas de fondo en app/tasks.py."""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import Depends, FastAPI, Request
from fastapi.responses import (
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles

from . import env_sync, error_reporting, heartbeat, i18n, origin_health, proxy
from .auth import AuthStore
from .config import load_dotenv, load_inventory
from .credentials import CredentialStore
from .db import EventStore
from .gcore_setup import renew_and_check
from .gcore_usage import refresh_usage
from .i18n import tr
from .inventory_store import InventoryStore
from .notifier import Notifier
from .routes import auth, domains, history, overview, settings, status
from .routes.common import (
    CSP,
    PUBLIC_PREFIXES,
    SESSION_COOKIE,
    _cookie_secure,
    _safe_next,
    csrf_protect,
    current_csrf,
)
from .secrets_store import SecretStore
from .state import State
from .tasks import (
    BACKUP_INTERVAL,
    CALENDAR_INTERVAL,
    CF_SYNC_INTERVAL,
    DNS_INTERVAL,
    GCORE_WATCH_INTERVAL,
    check_gcore_readiness,
    gcore_ready_interval,
    HEARTBEAT_INTERVAL,
    ORIGIN_HEALTH_INTERVAL,
    PRUNE_INTERVAL,
    RENEW_INTERVAL,
    USAGE_INTERVAL,
    _delayed_loop,
    _loop,
    check_firewall,
    daily_backup,
    feed_interval,
    prune_events,
    refresh_calendar,
    refresh_cloudflare,
    refresh_dns,
    refresh_feed,
    restore_block_state,
    watch_gcore,
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
    events.listeners.append(Notifier(secrets, events=events))
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
            asyncio.create_task(_delayed_loop(60, GCORE_WATCH_INTERVAL, watch_gcore, state)),
            asyncio.create_task(_delayed_loop(180, lambda: gcore_ready_interval(state), check_gcore_readiness, state)),
        ]
    yield
    for t in tasks:
        t.cancel()
    await state.close_http()


# Optional Sentry/GlitchTip: before the app exists, so its middleware is instrumented.
load_dotenv()
error_reporting.setup_logging()
error_reporting.init("panel")

app = FastAPI(title="Multi-CDN", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None,
              dependencies=[Depends(csrf_protect)])
app.mount("/static", StaticFiles(directory=WEB / "static"), name="static")


@app.get("/lang/{lang}")
def set_language(request: Request, lang: str, next: str = "/"):
    """Footer language selector: remembered in this browser for a year."""
    response = RedirectResponse(_safe_next(next), status_code=303)
    if code := i18n.normalize(lang):
        response.set_cookie(i18n.COOKIE, code, max_age=365 * 86400, httponly=True, samesite="lax",
                            secure=_cookie_secure(request))
    return response


load_notify_lang = env_sync.load_notify_lang  # the CLI and the runbook import it from here


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


# Sections in the order their routes were registered before the split (path matching is in order).
for section in (overview, domains, history, settings, auth, status):
    app.include_router(section.router)
