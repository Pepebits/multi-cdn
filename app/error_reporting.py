"""Optional error reporting to Sentry or GlitchTip (any Sentry-compatible server).

Off by default: without a DSN nothing is initialised or sent. The DSN is set in Settings →
System (or MULTICDN_SENTRY_DSN in config/secrets.env, synced with the panel like every secret)
and read from the encrypted database before the app exists; a change in the panel applies at
once to logged errors (reconfigure) and fully after a restart. A DSN that is not valid, or that
sentry_sdk refuses, only turns error reporting off: it never stops the panel from starting.

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


# dsn: in use · failed: a DSN that could not be used (not valid, or refused by sentry_sdk)
_live: dict[str, Any] = {"dsn": None, "failed": None, "component": "panel", "changed": False}


def _start(dsn: str, component: str) -> bool:
    try:
        import sentry_sdk
        from sentry_sdk.integrations.logging import LoggingIntegration
    except ImportError:
        log.warning("an error reporting DSN is set but sentry-sdk is not installed: error reporting is off")
        _live.update(dsn=dsn, component=component)
        return False
    if problem := dsn_problem(dsn):
        log.warning("error reporting: the DSN is not valid (%s): error reporting is off", problem)
        _live.update(dsn=None, failed=dsn, component=component)
        return False
    traces = _rate("MULTICDN_SENTRY_TRACES_SAMPLE_RATE")
    try:
        _init(sentry_sdk, LoggingIntegration, dsn, traces, component)
    except Exception as exc:  # a DSN sentry_sdk refuses must never stop the panel
        log.warning("error reporting: could not start it (%s): error reporting is off", type(exc).__name__)
        _stop(sentry_sdk)
        _live.update(dsn=None, failed=dsn, component=component)
        return False
    _live.update(dsn=dsn, failed=None, component=component)
    log.info("error reporting on (%s)", component)
    return True


def _init(sentry_sdk, LoggingIntegration, dsn: str, traces: float, component: str) -> None:
    sentry_sdk.init(
        dsn=dsn,
        environment=environment(),
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


def _stop(sentry_sdk) -> None:
    """Closes the current client (waits up to 2 s for pending events) and goes back to the
    non-recording one: nothing else is sent. Blocking: the panel calls it in a thread."""
    try:
        client = sentry_sdk.get_client()
        if client.is_active():
            client.close(timeout=2)
        sentry_sdk.get_global_scope().set_client(None)
    except Exception as exc:
        log.warning("error reporting: could not close the client (%s)", type(exc).__name__)


def environment() -> str:
    return os.environ.get("MULTICDN_SENTRY_ENVIRONMENT", "").strip() or "production"


def stored_dsn() -> str | None:
    """The DSN before the app exists: from the encrypted database (after importing
    config/secrets.env, which has priority at startup), else from MULTICDN_SENTRY_DSN when there
    is no database yet (first start: the panel imports it right after). Anything wrong reading
    it: logged, and error reporting stays off."""
    try:
        from . import envfile
        view = envfile.load()
        env_value = None if view.configured and not view.readable else (
            os.environ.get("MULTICDN_SENTRY_DSN", "").strip() or None)
    except Exception as exc:
        log.warning("error reporting: could not read %s (%s)", "config/secrets.env", type(exc).__name__)
        env_value = None
    db = Path(os.environ.get("MULTICDN_DB", "data/multicdn.db"))
    if not db.is_file():
        return env_value
    if not os.environ.get("MULTICDN_SECRET_KEY") and not (db.parent / ".secret_key").is_file():
        return env_value  # no master key yet: nothing stored can be read
    secrets = events = None
    try:
        from .db import EventStore
        from .env_sync import load_notify_lang, sync
        from .secrets_store import SecretStore
        secrets, events = SecretStore(db), EventStore(db)
        load_notify_lang(events)
        sync(secrets, events)
        return secrets.get("sentry_dsn")
    except Exception as exc:  # never stop the panel from starting
        log.warning("error reporting: could not read the DSN from the database (%s): off", type(exc).__name__)
        return None
    finally:
        for store in (secrets, events):
            if store is not None:
                store.conn.close()


def init(component: str) -> bool:
    """Starts error reporting if a DSN is configured (Settings → System or MULTICDN_SENTRY_DSN).
    Returns whether it is on."""
    _live["component"] = component
    dsn = stored_dsn()
    if not dsn:
        return False
    return _start(dsn, component)


def reconfigure(dsn: str | None) -> bool:
    """A DSN saved (or removed, None) in the panel, live: the previous client is closed and
    sentry_sdk starts again with the same safe options (or stays off). Errors logged from now on
    are sent at once; the web integration (unhandled exceptions in requests) is set up when the
    app is created, so full capture needs a restart (status()["restart_note"]). Blocking (it
    waits for pending events): the panel calls it in a thread."""
    try:
        import sentry_sdk
    except ImportError:
        _live.update(dsn=dsn)
        return False
    _stop(sentry_sdk)
    if dsn:
        ok = _start(dsn, _live["component"])
        _live["changed"] = ok
        return ok
    _live.update(dsn=None, failed=None, changed=False)
    log.info("error reporting off")
    return False


def send_test() -> str | None:
    """Sends a test error and waits for it to leave; returns the event id (None when off).
    Blocking (up to 5 s): the panel calls it in a thread."""
    try:
        import sentry_sdk
    except ImportError:
        return None
    if not sentry_sdk.get_client().is_active():
        return None
    event_id = sentry_sdk.capture_message("multi-cdn: test error sent from Settings → System", level="error")
    sentry_sdk.flush(timeout=5)
    return event_id


_DSN_PATH = re.compile(r"(?:/[\w.~-]+)*/\d+/?")


def dsn_problem(dsn: str) -> str | None:
    """Why a DSN cannot be saved (an untranslated reason, see main), or None: https, a public
    key, a public host name and a numeric project id (https://key@host/project)."""
    if not dsn or len(dsn) > 500 or any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in dsn):
        return "shape"
    try:
        parts = urlsplit(dsn)
        parts.port
    except ValueError:
        return "shape"
    if parts.scheme != "https":
        return "https"
    if not parts.username or not parts.hostname or not _DSN_PATH.fullmatch(parts.path) or parts.query or parts.fragment:
        return "shape"
    from .heartbeat import public_hostname
    if not public_hostname(parts.hostname):
        return "host"
    return None


def status() -> dict[str, Any]:
    """What Settings → System shows: whether reporting is on and where to. Only the scheme and
    host of the DSN, never its key, path or project id."""
    from .secrets_store import dsn_server
    dsn = _live["dsn"]
    if not dsn:
        failed = _live.get("failed")
        return {"enabled": False, "configured": bool(failed), "installed": None, "failed": bool(failed),
                "server": dsn_server(failed) if failed else None, "environment": None, "restart_note": False}
    try:
        import importlib.util
        installed = importlib.util.find_spec("sentry_sdk") is not None
    except (ImportError, ValueError):
        installed = False
    return {"enabled": installed, "configured": True, "installed": installed, "failed": False, "server": dsn_server(dsn),
            "environment": environment(), "restart_note": _live["changed"]}


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
