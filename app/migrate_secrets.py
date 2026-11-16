"""Moves the panel-managed variables from the main .env to config/secrets.env (upgrade to 0.3.1).

Run on the server by deploy/install.sh, with the system python3 (standard library only, so it
works before the image is built):

    python3 -m app.migrate_secrets .env config/secrets.env

Also available as ``python -m app.cli migrate-secrets``. What it does:

- every line of .env that sets a panel-managed variable (MANAGED_KEYS) is removed from .env and
  its value written to the secrets file (under "# Managed by the multi-cdn panel"). A variable
  the secrets file already has keeps the file's value (Compose loads the file after .env, so
  that is the value the container saw).
- before changing .env a full copy is kept next to it as .env.bak-<UTC timestamp> (0600).
- both files are written atomically (temporary file, fsync, rename); .env keeps its permissions,
  the secrets file gets 0600 (the container runs as the same user, see compose.yaml).
- prints which variables moved (never their values), and warns about variables in the secrets
  file that the panel does not manage (they would override .env; the panel ignores them).

Exit status: 0 done or nothing to do, 1 could not read or write a file.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import envparse

# The same set as envfile.MANAGED (a test keeps them equal): here without importing the app.
MANAGED_KEYS = frozenset({
    "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "SMTP_URL", "ALERT_EMAIL_TO", "FOOTBALL_DATA_TOKEN",
    "MULTICDN_HEARTBEAT_URL", "MULTICDN_SENTRY_DSN", "CLOUDFLARE_API_TOKEN", "GCORE_API_TOKEN",
})


def _read(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8")
    except FileNotFoundError:
        return ""


def _write(path: Path, text: str, mode: int) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(text.encode("utf-8"))
            f.flush()
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def plan(env_text: str, secrets_text: str) -> tuple[str, str, list[str], list[str]]:
    """(new .env, new secrets file, variables moved, variables kept from the secrets file)."""
    parsed = envparse.parse(env_text, {**os.environ})
    in_secrets = envparse.parse(secrets_text, {})
    lines = env_text.split("\n")
    managed = [e for e in parsed.entries if e.key in MANAGED_KEYS]
    drop = {i for e in managed for i in range(e.first, e.last + 1)}
    moved, kept = [], []
    new_secrets = secrets_text
    for key in dict.fromkeys(e.key for e in managed):
        if key in in_secrets.values or key in in_secrets.invalid:
            kept.append(key)
            continue
        last = [e for e in managed if e.key == key][-1]
        value = parsed.values.get(key)
        try:
            if value is None:
                raise ValueError
            if value.strip():
                new_secrets = envparse.render(new_secrets, key, value.strip())
        except ValueError:  # not representable (or rejected): move the lines as they were
            raw = "\n".join(lines[last.first:last.last + 1]).lstrip(" \t").removeprefix("export").lstrip(" \t")
            if new_secrets and not new_secrets.endswith("\n"):
                new_secrets += "\n"
            if envparse.MARKER not in new_secrets:
                new_secrets += ("\n" if new_secrets.strip() else "") + envparse.MARKER + "\n"
            new_secrets += raw + "\n"
        moved.append(key)
    bom = "﻿" if env_text.startswith("﻿") else ""
    new_env = "\n".join(text for i, text in enumerate(env_text.removeprefix(bom).split("\n")) if i not in drop)
    return bom + new_env, new_secrets, moved, kept


def migrate(env_path: Path, secrets_path: Path, out=print, now: datetime | None = None) -> int:
    try:
        env_text = env_path.read_bytes().decode("utf-8")
        secrets_text = _read(secrets_path)
    except (OSError, UnicodeDecodeError) as exc:
        out(f"    could not read {env_path} or {secrets_path}: {exc}")
        return 1
    unmanaged = sorted(k for k in set(envparse.parse(secrets_text, {}).values) if k not in MANAGED_KEYS)
    if unmanaged:
        out(f"    WARNING: {secrets_path} has variables the panel does not manage: {', '.join(unmanaged)}.")
        out("    They would override .env (MULTICDN_DRY_RUN there keeps the panel in dry run). Move them to .env.")
    broken = sorted(k for k in envparse.parse(env_text, {**os.environ}).invalid if k in MANAGED_KEYS)
    if broken:
        out(f"    {env_path} has lines the panel cannot read for: {', '.join(broken)} (an unclosed quote?).")
        out("    Nothing was moved: fix those lines and run it again.")
        return 1
    new_env, new_secrets, moved, kept = plan(env_text, secrets_text)
    if not moved and not kept:
        return 0
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    backup = env_path.with_name(f"{env_path.name}.bak-{stamp}")
    try:
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(env_text.encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        _write(secrets_path, new_secrets, 0o600)
        _write(env_path, new_env, stat.S_IMODE(env_path.stat().st_mode))
    except OSError as exc:
        out(f"    could not move the panel's variables: {exc}")
        return 1
    if moved:
        out(f"    Moved from {env_path} to {secrets_path}: {', '.join(moved)}")
    if kept:
        out(f"    Removed from {env_path}, {secrets_path} already had them (its value stays): {', '.join(kept)}")
    out(f"    Copy of the previous {env_path.name}: {backup} (delete it once the panel works)")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print("usage: python3 -m app.migrate_secrets <.env> <config/secrets.env>")
        return 2
    return migrate(Path(args[0]), Path(args[1]))


if __name__ == "__main__":
    sys.exit(main())
