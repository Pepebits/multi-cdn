"""Write-back of panel changes to the server's .env, so that both stay equal (0.3.1).

At startup the .env has priority (env_sync); when someone saves or removes a value in the panel
it is written here too. Only the variables the panel manages can be written: never
MULTICDN_SECRET_KEY, MULTICDN_DRY_RUN or anything else.

The file is the one Docker passes with env_file, bind-mounted read-write into the container
(MULTICDN_ENV_PATH). A bind-mounted single file cannot be replaced with rename (EBUSY), so it
is rewritten in place: read, keep a copy of the previous content in data/env-backups/ (0600,
the last 10), then write on the same descriptor, truncate and fsync. Every other line,
comment and their order stay byte for byte. Values are never logged.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path

from .credentials import ENV_TOKENS
from .i18n import N_
from .secrets_store import CREDENTIALS, SecretStore

log = logging.getLogger("multicdn")
MANAGED = frozenset({env for _label, env, _help in CREDENTIALS.values()} | set(ENV_TOKENS.values()))
MARKER = "# Managed by the multi-cdn panel"
BACKUPS_KEEP = 10

# Why the .env could not be written (stored as env_error:<VAR>; the panel shows the text).
REASONS = {
    "not_configured": N_("MULTICDN_ENV_PATH is not set"),
    "missing": N_("the file does not exist"),
    "not_writable": N_("no permission to write it"),
    "read_only": N_("read-only file system"),
    "error": N_("could not be written"),
}


class EnvFileError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def env_path() -> Path | None:
    raw = os.environ.get("MULTICDN_ENV_PATH", "").strip()
    return Path(raw) if raw else None


def backups_dir() -> Path:
    return Path(os.environ.get("MULTICDN_DB", "data/multicdn.db")).parent / "env-backups"


_PLAIN = re.compile(r"[A-Za-z0-9_@:/.+,=%~^-]*")


def quote(value: str) -> str:
    """As Docker Compose (env_file) and config.load_dotenv read it back: bare when safe,
    else in single quotes (literal), else in double quotes with \\, \" and $$ escaped."""
    if _PLAIN.fullmatch(value):
        return value
    if "'" not in value:
        return f"'{value}'"
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "$$") + '"'


def render(content: str, key: str, value: str | None) -> str:
    """`content` with KEY set to `value` (the first non-comment KEY= line, in place; else
    appended under MARKER) or removed (None). Nothing else changes."""
    line_re = re.compile(rf"^([ \t]*)(export[ \t]+)?{re.escape(key)}[ \t]*=")
    lines = content.splitlines(keepends=True)
    out, done = [], False
    for line in lines:
        m = line_re.match(line)
        if not m:
            out.append(line)
            continue
        if value is None:
            continue  # removed (every occurrence: a later one would win otherwise)
        if done:
            out.append(line)
            continue
        ending = line[len(line.rstrip("\r\n")):]
        out.append(f"{m.group(1)}{m.group(2) or ''}{key}={quote(value)}{ending}")
        done = True
    text = "".join(out)
    if value is not None and not done:
        if text and not text.endswith("\n"):
            text += "\n"
        if MARKER not in text:
            text += ("\n" if text else "") + MARKER + "\n"
        text += f"{key}={quote(value)}\n"
    return text


def _backup(content: bytes) -> None:
    folder = backups_dir()
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    target = folder / f".env-{stamp}"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    for old in sorted(folder.glob(".env-*"))[:-BACKUPS_KEEP]:
        old.unlink(missing_ok=True)


def update_env(path: str | Path, key: str, value: str | None) -> bool:
    """Sets or removes one managed variable in the .env at `path`. Returns whether the file
    changed. Raises ValueError for a key the panel does not manage or a value with a line
    break, EnvFileError when the file cannot be written."""
    if key not in MANAGED:
        raise ValueError(f"{key} is not managed by the panel")
    if value is not None:
        value = value.strip()
        if any(c in value for c in "\r\n\0"):
            raise ValueError("line breaks are not allowed in .env values")
    try:
        fd = os.open(path, os.O_RDWR)
    except FileNotFoundError:
        raise EnvFileError("missing") from None
    except PermissionError:
        raise EnvFileError("not_writable") from None
    except OSError as exc:
        raise EnvFileError("read_only" if exc.errno == 30 else "error") from None
    try:
        with os.fdopen(fd, "r+b") as f:
            old = f.read()
            new = render(old.decode("utf-8"), key, value).encode("utf-8")
            if new == old:
                return False
            _backup(old)
            f.seek(0)
            f.write(new)
            f.truncate()
            f.flush()
            os.fsync(f.fileno())
    except (UnicodeDecodeError, OSError) as exc:
        raise EnvFileError("read_only" if getattr(exc, "errno", None) == 30 else "error") from None
    return True


def refresh_environ() -> bool:
    """At startup, take the managed variables from the .env file itself, not from the
    environment the container was created with: `docker restart` keeps the old environment,
    so a value the panel wrote (or removed) would otherwise come back. Returns whether the
    file could be read."""
    path = env_path()
    if path is None:
        return False
    from .config import read_dotenv
    try:
        values = read_dotenv(path)
    except (OSError, UnicodeDecodeError):
        log.warning(".env: could not read %s; using the process environment", path)
        return False
    for key in MANAGED:
        if values.get(key, "").strip():
            os.environ[key] = values[key].strip()
        else:
            os.environ.pop(key, None)
    return True


def write_back(secrets: SecretStore, key: str, value: str | None) -> str | None:
    """After a change in the panel: write it to .env and to this process's environment.
    Returns None when .env is now equal, else the reason code (also kept for the panel)."""
    path = env_path()
    try:
        if path is None:
            raise EnvFileError("not_configured")
        update_env(path, key, value)
    except (EnvFileError, ValueError) as exc:
        code = exc.code if isinstance(exc, EnvFileError) else "error"
        secrets.set_meta(f"env_error:{key}", code)
        log.warning(".env: could not update %s (%s)", key, code)
        return code
    if value is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = value.strip()
    secrets.del_meta(f"env_error:{key}")
    secrets.set_meta("env_written_at", datetime.now(UTC).isoformat(timespec="seconds"))
    log.info(".env: %s %s", key, "removed" if value is None else "updated")
    return None


def save(secrets: SecretStore, name: str, value: str | None) -> str | None:
    """Saves (or removes, None) a secret from the panel: database first, then .env."""
    if value is None:
        secrets.delete(name)
    else:
        secrets.set(name, value)
    return write_back(secrets, CREDENTIALS[name][1], value)


def status(secrets: SecretStore) -> dict:
    """For Settings → System: where the .env is and whether the panel can write it."""
    path = env_path()
    exists = bool(path and path.is_file())
    written = secrets.meta("env_written_at")
    return {"path": str(path) if path else None, "configured": path is not None, "exists": exists,
            "writable": exists and os.access(path, os.W_OK),
            "written_at": datetime.fromisoformat(written) if written else None}
