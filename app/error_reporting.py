"""Optional error reporting to Sentry or GlitchTip (any Sentry-compatible server).

Off by default: without MULTICDN_SENTRY_DSN nothing is imported, initialised or sent.

When it is on, only errors are sent: unhandled exceptions in the panel and the CLI, and
anything logged with log.exception() / log.error(). No performance traces unless
MULTICDN_SENTRY_TRACES_SAMPLE_RATE is set, no sessions, no request bodies, no cookies or
headers, no local variables. Every string in an event is scrubbed of IP addresses (the
origin IP must never leave the server), emails and token-looking values before it is sent.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import tomllib
from pathlib import Path
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger("multicdn")

# A trailing full stop ends the sentence, not the address ("refused by 192.0.2.10.").
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?:%\w+)?(?![\w:])")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b")
_SECRETS = [
    # Telegram bot token (also inside https://api.telegram.org/bot<token>/…)
    (re.compile(r"(?<!\d)\d{6,}:[\w-]{30,}"), "[token]"),
    # Authorization schemes used by the providers
    (re.compile(r"\b(Bearer|APIKey|Basic|token)\s+[\w.~+/=-]{8,}", re.I), r"\1 [token]"),
    # credentials in URLs: scheme://user:password@host
    (re.compile(r"(\w+://)[^/\s:@]+:[^/\s@]+@"), r"\1[credentials]@"),
    # query parameters that carry secrets
    (re.compile(r"([?&](?:token|key|apikey|api_key|secret|password|code)=)[^&\s#]+", re.I), r"\1[redacted]"),
]
_DROP_REQUEST_KEYS = ("cookies", "headers", "data", "env", "query_string")


def _scrub_ip(match: re.Match[str]) -> str:
    try:
        ipaddress.ip_address(match.group(0).split("%")[0])
    except ValueError:
        return match.group(0)
    return "[ip]"


_origin_ips: Callable[[], Iterable[str]] = lambda: ()
_TELEGRAM, _URL_CREDENTIALS = _SECRETS[0], _SECRETS[2]


def set_origin_ips(source: Callable[[], Iterable[str]]) -> None:
    """Where scrub_origin() gets the current origin IPs from (the panel registers its inventory)."""
    global _origin_ips
    _origin_ips = source


def _origins() -> set:
    out = set()
    try:
        for ip in _origin_ips() or ():
            try:
                out.add(ipaddress.ip_address(str(ip)))
            except ValueError:
                pass
    except Exception:
        pass
    return out


def scrub_origin(text: str | None) -> str | None:
    """Narrow scrub for texts kept in the history, sent as alerts or shown in the panel: only
    the origin IPs (any notation) become "[origin IP]", plus Telegram tokens and credentials in
    URLs. Other IPs (Gcore edges, clients) and words such as "token" stay as they are."""
    if not text:
        return text
    origins = _origins()
    if origins:
        def repl(m: re.Match[str]) -> str:
            try:
                return "[origin IP]" if ipaddress.ip_address(m.group(0).split("%")[0]) in origins else m.group(0)
            except ValueError:
                return m.group(0)
        text = _IPV6.sub(repl, _IPV4.sub(repl, text))
    for pattern, replacement in (_TELEGRAM, _URL_CREDENTIALS):
        text = pattern.sub(replacement, text)
    return text


def scrub_text(text: str) -> str:
    text = _IPV4.sub(_scrub_ip, text)
    text = _IPV6.sub(_scrub_ip, text)
    for pattern, repl in _SECRETS:
        text = pattern.sub(repl, text)
    return _EMAIL.sub("[email]", text)


def scrub(value: Any) -> Any:
    """Scrubs every string inside an event (dicts, lists, tuples), keys included."""
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, dict):
        return {scrub(k): scrub(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(scrub(v) for v in value)
    return value


def before_send(event: dict[str, Any], hint: dict[str, Any] | None = None) -> dict[str, Any]:
    request = event.get("request")
    if isinstance(request, dict):
        for key in _DROP_REQUEST_KEYS:
            request.pop(key, None)
    event.pop("user", None)
    for frame_holder in (event.get("exception") or {}).get("values") or []:
        for frame in (frame_holder.get("stacktrace") or {}).get("frames") or []:
            frame.pop("vars", None)
    return scrub(event)


def before_breadcrumb(crumb: dict[str, Any], hint: dict[str, Any] | None = None) -> dict[str, Any]:
    return scrub(crumb)


def setup_logging() -> None:
    """The panel's own log lines (multicdn.*) on stdout with date and level; uvicorn keeps
    its own. MULTICDN_LOG_LEVEL changes the level (default INFO)."""
    logger = logging.getLogger("multicdn")
    if logger.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    level = os.environ.get("MULTICDN_LOG_LEVEL", "INFO").strip().upper()
    logger.setLevel(level if level in ("DEBUG", "INFO", "WARNING", "ERROR") else "INFO")


def _release() -> str:
    """multi-cdn@<version>, from the pyproject.toml shipped next to the app (also in the image)."""
    try:
        data = tomllib.loads((Path(__file__).resolve().parent.parent / "pyproject.toml").read_text())
        return f"multi-cdn@{data['project']['version']}"
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        return "multi-cdn@unknown"


def _rate(name: str) -> float:
    raw = os.environ.get(name, "").strip()
    try:
        return min(max(float(raw), 0.0), 1.0) if raw else 0.0
    except ValueError:
        log.warning("%s is not a number between 0 and 1: ignored", name)
        return 0.0


def init(component: str) -> bool:
    """Starts error reporting if MULTICDN_SENTRY_DSN is set. Returns whether it is on."""
    dsn = os.environ.get("MULTICDN_SENTRY_DSN", "").strip()
    if not dsn:
        return False
    try:
        import sentry_sdk
        from sentry_sdk.integrations.logging import LoggingIntegration
    except ImportError:
        log.warning("MULTICDN_SENTRY_DSN is set but sentry-sdk is not installed: error reporting is off")
        return False
    traces = _rate("MULTICDN_SENTRY_TRACES_SAMPLE_RATE")
    sentry_sdk.init(
        dsn=dsn,
        environment=os.environ.get("MULTICDN_SENTRY_ENVIRONMENT", "").strip() or "production",
        release=_release(),
        server_name="multi-cdn",          # not the machine's hostname
        # Nothing about the person or the request; locals can hold tokens or the origin IP.
        data_collection={
            "user_info": False,
            "cookies": {"mode": "off"},
            "http_headers": {"request": {"mode": "off"}},
            "http_bodies": [],
            "url_query_params": {"mode": "off"},
            "stack_frame_variables": False,
        },
        include_local_variables=False,
        max_request_body_size="never",
        auto_session_tracking=False,      # GlitchTip ignores sessions; avoid the noise
        traces_sample_rate=traces or None,
        # log.error()/log.exception() become events; INFO lines become breadcrumbs.
        integrations=[LoggingIntegration(level=logging.INFO, event_level=logging.ERROR)],
        before_send=before_send,
        before_send_transaction=before_send,
        before_breadcrumb=before_breadcrumb,
    )
    sentry_sdk.set_tag("component", component)
    log.info("error reporting on (%s)", component)
    return True


def status() -> dict[str, Any]:
    """What Settings → Operation shows: whether reporting is on and where to. Only the scheme and
    host of the DSN, never its key, path or project id."""
    dsn = os.environ.get("MULTICDN_SENTRY_DSN", "").strip()
    if not dsn:
        return {"enabled": False, "configured": False, "installed": None, "server": None, "environment": None}
    try:
        import importlib.util
        installed = importlib.util.find_spec("sentry_sdk") is not None
    except (ImportError, ValueError):
        installed = False
    server = None
    try:
        parts = urlsplit(dsn)
        host = parts.hostname
        if parts.scheme in ("http", "https") and host:
            host = f"[{host}]" if ":" in host else host
            port = parts.port
            server = f"{parts.scheme}://{host}" + (f":{port}" if port and port not in (80, 443) else "")
    except ValueError:
        server = None
    return {"enabled": installed, "configured": True, "installed": installed, "server": server,
            "environment": os.environ.get("MULTICDN_SENTRY_ENVIRONMENT", "").strip() or "production"}


def watch_background_tasks() -> None:
    """Also report exceptions in asyncio tasks nobody awaits. Needs the running event loop,
    so the panel calls it at startup; does nothing when error reporting is off."""
    try:
        import sentry_sdk
        from sentry_sdk.integrations.asyncio import enable_asyncio_integration
    except ImportError:
        return
    if sentry_sdk.get_client().is_active():
        enable_asyncio_integration()
