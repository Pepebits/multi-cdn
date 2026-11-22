"""Shared pieces of the panel's routes: templates and their filters, CSRF and session helpers,
redirects with messages and the settings/auth helpers used by more than one section."""

from __future__ import annotations

import asyncio
import hmac
import os
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from markupsafe import Markup

from .. import envfile, error_reporting, event_codes, i18n, proxy
from ..engine import failover
from ..gcore_usage import human as human_bytes
from ..i18n import N_, tn, tr
from ..signals import hayahora
from ..state import State
from ..tasks import (
    refresh_cloudflare,
    refresh_dns,
)

WEB = Path(__file__).resolve().parent.parent / "web"


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


templates = Jinja2Templates(directory=WEB / "templates")
i18n.install(templates.env)


def _safe_next(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value:
        return "/"
    # Browsers drop tabs and newlines from URLs: "/\t/evil.example" would become "//evil.example".
    return "/" if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value) else value


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


# Settings tabs, in setup order (_macros.settings_tabs); _settings_page needs them.
SETTINGS_TABS = {"cuentas": N_("Provider accounts"), "servidores": N_("Servers"), "notificaciones": N_("Notifications"),
                 "cambio": N_("Automatic switching"), "sistema": N_("System"), "cuenta": N_("My account")}
