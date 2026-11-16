"""The panel's secrets file, config/secrets.env (0.3.1): the panel-managed values, kept equal to
the encrypted database.

Only the variables in MANAGED live there (the notification and integration secrets plus the
Cloudflare and Gcore tokens). Everything else (MULTICDN_SECRET_KEY, MULTICDN_DRY_RUN, ORIGIN_*,
Compose interpolation such as MULTICDN_ENV_FILE) stays in the main .env, which the container
cannot read or write: Compose passes it with env_file only.

With Docker, compose.yaml mounts the host folder ./config at /app/config (read-write) and sets
MULTICDN_SECRETS_PATH=/app/config/secrets.env. It is NOT an env_file: only the panel reads it,
and only its own variables, so nothing written there reaches the container's environment.

Precedence at every start (panel, CLI, error reporting before the app exists), see env_sync:

1. config/secrets.env: a value that differs from the database is imported.
2. Any other route into the process environment (compose `environment:`, the main .env,
   systemd) for a variable that is not in the file: imported only when that value is new since
   the last start. A container restarted with `docker restart` keeps the environment it was
   created with, so an unchanged old value never undoes a change made in the panel.
3. Otherwise the database keeps its value: removing a line from the file does not remove the
   value from the panel.

If MULTICDN_SECRETS_PATH is set but the file cannot be read, nothing is imported (the database
wins) and the panel shows a problem. Without MULTICDN_SECRETS_PATH (development, no mount) every
managed variable of the environment is imported when it differs, as before 0.3.1.

Saving or removing a value in the panel rewrites the file atomically (a temporary file in the
same folder, fsync, rename, fsync of the folder): every other line and comment stays as it was.
A copy of the previous managed lines is kept in data/secrets-backups/ (0600, the last 10).
Values are never logged.
"""

from __future__ import annotations

import errno
import logging
import os
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from . import envparse
from .credentials import ENV_TOKENS
from .i18n import N_
from .secrets_store import CREDENTIALS, SecretStore

log = logging.getLogger("multicdn")
MANAGED = frozenset({env for _label, env, _help in CREDENTIALS.values()} | set(ENV_TOKENS.values()))
MARKER = envparse.MARKER
render = envparse.render  # set or remove one variable, every other line unchanged
BACKUPS_KEEP = 10
DISPLAY = "config/secrets.env"  # how the docs and the panel name it (host path, next to compose.yaml)

# Why the secrets file could not be written or read (stored as env_error:<VAR>; the panel shows the text).
REASONS = {
    "not_configured": N_("MULTICDN_SECRETS_PATH is not set"),
    "missing": N_("its folder does not exist"),
    "not_writable": N_("no permission to write it"),
    "read_only": N_("read-only file system"),
    "unreadable": N_("the file cannot be read"),
    "invalid": N_("the value cannot be written to the file"),
    "error": N_("could not be written"),
}

_lock = threading.Lock()


class EnvFileError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def secrets_path() -> Path | None:
    raw = os.environ.get("MULTICDN_SECRETS_PATH", "").strip()
    return Path(raw) if raw else None


def backups_dir() -> Path:
    return Path(os.environ.get("MULTICDN_DB", "data/multicdn.db")).parent / "secrets-backups"


# ---------------------------------------------------------------- what the file holds

@dataclass
class FileView:
    """The secrets file as read at startup and kept current by the panel's writes."""
    configured: bool = False
    path: Path | None = None
    readable: bool = False
    exists: bool = False
    error: str | None = None                                # why it could not be read (REASONS code)
    values: dict[str, str] = field(default_factory=dict)    # managed variables in the file
    invalid: list[str] = field(default_factory=list)        # managed variables with a rejected value
    unmanaged: list[str] = field(default_factory=list)      # other variables (ignored, a problem)


_view = FileView()
_boot: dict[str, str] | None = None  # managed variables of the environment the process started with


def reset() -> None:
    """Forget what was read (tests: each one starts like a new process)."""
    global _view, _boot
    _view, _boot = FileView(), None


def view() -> FileView:
    return _view


def current(env: str) -> str | None:
    """The value the panel compares with for `env`: the secrets file when one is configured
    (None if the file lacks it or could not be read), else the process environment."""
    if _view.configured:
        return _view.values.get(env) if _view.readable else None
    return os.environ.get(env, "").strip() or None


def load() -> FileView:
    """Reads the secrets file (startup). Its managed values replace the process environment;
    variables that are not in the file are left alone (they may come from compose `environment:`
    or systemd). A non-managed variable in the file is ignored and reported; MULTICDN_DRY_RUN
    there forces dry run, since Compose has already injected it."""
    global _view, _boot
    if _boot is None:
        _boot = {k: v.strip() for k in MANAGED if (v := os.environ.get(k, "")).strip()}
    path = secrets_path()
    if path is None:
        _view = FileView()
        return _view
    v = FileView(configured=True, path=path)
    try:
        parsed = envparse.read(path, {})
        v.readable = v.exists = True
    except FileNotFoundError:
        parsed, v.readable = envparse.Parsed(), True  # optional in compose.yaml: like an empty file
    except (OSError, UnicodeDecodeError) as exc:
        v.error = "unreadable"
        log.warning("%s: could not read it (%s): nothing is imported, the panel keeps its values",
                    DISPLAY, type(exc).__name__)
        _view = v
        return v
    v.values = {k: val.strip() for k, val in parsed.values.items() if k in MANAGED and val.strip()}
    v.invalid = sorted(k for k in parsed.invalid if k in MANAGED)
    v.unmanaged = sorted(k for k in set(parsed.values) | parsed.invalid if k not in MANAGED)
    for key, value in v.values.items():
        os.environ[key] = value
    if v.unmanaged:
        log.warning("%s: ignoring variables the panel does not manage: %s (move them to .env)",
                    DISPLAY, ", ".join(v.unmanaged))
        if "MULTICDN_DRY_RUN" in v.unmanaged:
            os.environ["MULTICDN_DRY_RUN"] = "true"
    if v.invalid:
        log.warning("%s: ignoring values with line breaks or control characters: %s", DISPLAY, ", ".join(v.invalid))
    _view = v
    return v


def import_source(secrets: SecretStore) -> dict[str, str] | None:
    """What env_sync imports at startup (call load() first): variable -> value, or None when
    the secrets file is configured but unreadable (import nothing: the database wins)."""
    if not _view.configured:
        return {k: v.strip() for k in MANAGED if (v := os.environ.get(k, "")).strip()}
    if not _view.readable:
        return None
    source = dict(_view.values)
    for key in MANAGED:
        boot = (_boot or {}).get(key)
        seen_key = f"env_seen:{key}"
        seen = _decrypt(secrets, secrets.meta(seen_key))
        if key not in source and key not in _view.invalid and boot and boot != seen:
            source[key] = boot  # new since the last start, from another route
        if boot:
            if boot != seen:
                secrets.set_meta(seen_key, secrets.fernet.encrypt(boot.encode()).decode())
        elif seen is not None:
            secrets.del_meta(seen_key)
    return source


def _decrypt(secrets: SecretStore, token: str | None) -> str | None:
    if not token:
        return None
    try:
        return secrets.fernet.decrypt(token.encode()).decode()
    except Exception:
        return None


# ---------------------------------------------------------------- writing

def _fsync_dir(folder: Path) -> None:
    try:
        fd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _new_file_mode(folder: Path) -> int:
    """0600, or 0660 when the folder has a default ACL: then the ACL decides who may read it
    (install.sh grants the deploying user and uid 10001) and the mask must not hide them."""
    try:
        os.getxattr(folder, "system.posix_acl_default")
        return 0o660
    except (AttributeError, OSError):
        return 0o600


def _write_atomic(path: Path, data: bytes) -> None:
    folder = path.parent
    # A unique name (pid is always 1 in the container): a temp file left by a crash never blocks
    # later saves.
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=folder)
    tmp = Path(name)
    try:
        os.fchmod(fd, _new_file_mode(folder))
    except BaseException:
        os.close(fd)
        tmp.unlink(missing_ok=True)
        raise
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    _fsync_dir(folder)


def _backup(content: str) -> None:
    """Only the managed lines of the previous file (never anything else that a person may have
    put there), 0600 in a 0700 folder, the last BACKUPS_KEEP."""
    parsed = envparse.parse(content, {})
    lines = content.split("\n")
    keep = [lines[i] for e in parsed.entries if e.key in MANAGED for i in range(e.first, e.last + 1)]
    if not keep:
        return
    folder = backups_dir()
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(folder, 0o700)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    target = folder / f"secrets.env-{stamp}"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(("\n".join(keep) + "\n").encode("utf-8"))
        f.flush()
        os.fsync(f.fileno())
    _fsync_dir(folder)
    for old in sorted(folder.glob("secrets.env-*"))[:-BACKUPS_KEEP]:
        old.unlink(missing_ok=True)


def _code(exc: OSError) -> str:
    if isinstance(exc, PermissionError):
        return "not_writable"
    if exc.errno == errno.EROFS:
        return "read_only"
    if isinstance(exc, FileNotFoundError):
        return "missing"
    return "error"


def update_file(path: str | Path, key: str, value: str | None) -> bool:
    """Sets or removes one managed variable in the secrets file at `path` (created if missing).
    Returns whether the file changed. Raises ValueError for a key the panel does not manage or a
    value that cannot be written, EnvFileError when the file cannot be read or written."""
    if key not in MANAGED:
        raise ValueError(f"{key} is not managed by the panel")
    if value is not None:
        value = value.strip()
        if not value or envparse.bad_chars(value):
            raise ValueError("line breaks and control characters are not allowed")
        envparse.quote(value)  # raises ValueError
    path = Path(path)
    with _lock:
        try:
            old = path.read_bytes().decode("utf-8")
        except FileNotFoundError:
            old = ""
            if not path.parent.is_dir():
                raise EnvFileError("missing") from None
        except UnicodeDecodeError:
            raise EnvFileError("unreadable") from None
        except OSError as exc:
            raise EnvFileError("unreadable" if isinstance(exc, PermissionError) else _code(exc)) from None
        new = render(old, key, value)
        if new == old and path.exists():
            return False
        try:
            if old:
                _backup(old)
            _write_atomic(path, new.encode("utf-8"))
        except OSError as exc:
            raise EnvFileError(_code(exc)) from None
    return True


def write_back(secrets: SecretStore, key: str, value: str | None) -> str | None:
    """After a change in the panel: write it to the secrets file and to this process's
    environment. Returns None when the file is now equal, else the reason code (also kept for
    the panel)."""
    path = secrets_path()
    try:
        if path is None:
            raise EnvFileError("not_configured")
        update_file(path, key, value)
    except EnvFileError as exc:
        code = exc.code
    except ValueError:
        code = "invalid"
    else:
        code = None
    if code:
        secrets.set_meta(f"env_error:{key}", code)
        log.warning("%s: could not update %s (%s)", DISPLAY, key, code)
        return code
    if value is None:
        os.environ.pop(key, None)
        _view.values.pop(key, None)
    else:
        os.environ[key] = _view.values[key] = value.strip()
    if key in _view.invalid:
        _view.invalid.remove(key)
    _view.exists = _view.readable = True
    _view.error = None
    secrets.del_meta(f"env_error:{key}")
    secrets.set_meta("env_written_at", datetime.now(UTC).isoformat(timespec="seconds"))
    log.info("%s: %s %s", DISPLAY, key, "removed" if value is None else "updated")
    return None


def save(secrets: SecretStore, name: str, value: str | None) -> str | None:
    """Saves (or removes, None) a secret from the panel: database first, then the secrets file."""
    if value is None:
        secrets.delete(name)
    else:
        secrets.set(name, value)
    return write_back(secrets, CREDENTIALS[name][1], value)


def status(secrets: SecretStore) -> dict:
    """For Settings → System: where the secrets file is and whether the panel can write it."""
    path = secrets_path()
    exists = bool(path and path.is_file())
    folder_ok = bool(path and path.parent.is_dir() and os.access(path.parent, os.W_OK | os.X_OK))
    writable = bool(path) and folder_ok and (not exists or os.access(path, os.R_OK))
    written = secrets.meta("env_written_at")
    return {"path": str(path) if path else None, "configured": path is not None, "exists": exists,
            "writable": writable, "readable": _view.readable if _view.configured else None,
            "error": _view.error, "unmanaged": list(_view.unmanaged), "invalid": list(_view.invalid),
            "written_at": datetime.fromisoformat(written) if written else None}
