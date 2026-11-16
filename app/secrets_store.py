"""Credenciales cifradas en SQLite (Fernet): the only place the panel reads secrets from.

La clave maestra viene de MULTICDN_SECRET_KEY. Si no existe, se genera una en
data/.secret_key (permisos 600) y el panel avisa: para que las copias de la base
de datos no sirvan sin la clave, guárdala fuera del VPS o pásala por entorno.

Sync with the server's .env (0.3.1), so both stay equal: at startup (panel and CLI) the .env
has priority and every env-backed secret that differs is imported here (``import_env``, see
env_sync); saving or removing a value in the panel writes it back to .env (envfile). When the
panel cannot write .env, the status says so (``env_state``) and the next start restores the
.env value.
"""

from __future__ import annotations

import hmac
import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken

from .i18n import N_, tr

# Secretos sueltos: nombre -> (etiqueta, variable de entorno, descripción).
# Las credenciales de proveedores (Cloudflare, Gcore) van aparte: ver credentials.py.
CREDENTIALS: dict[str, tuple[str, str, str]] = {
    "telegram_token": (N_("Telegram bot token"), "TELEGRAM_BOT_TOKEN", N_("Bot created with @BotFather.")),
    "telegram_chat_id": (N_("Telegram chat ID"), "TELEGRAM_CHAT_ID", N_("Chat or group that receives the alerts.")),
    "smtp_url": (N_("SMTP server"), "SMTP_URL", N_("Format smtps://user:password@host:465")),
    "alert_email_to": (N_("Alert email"), "ALERT_EMAIL_TO", N_("Recipient of the email alerts.")),
    "football_data_token": (N_("football-data.org key"), "FOOTBALL_DATA_TOKEN", N_("Second source for the LaLiga calendar.")),
    "heartbeat_url": (N_("External heartbeat URL"), "MULTICDN_HEARTBEAT_URL",
                      N_("Ping URL from healthchecks.io (or compatible). Set its period to 5 min and grace to 10 min there.")),
    "sentry_dsn": (N_("Error reporting DSN"), "MULTICDN_SENTRY_DSN",
                   N_("DSN of a Sentry or GlitchTip project (https://key@host/project).")),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets (
    name TEXT PRIMARY KEY,
    ciphertext BLOB NOT NULL,
    hint TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS secret_meta (
    key TEXT PRIMARY KEY,     -- env_error:<VAR>, env_cred:<provider>, env_written_at
    value TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class SecretStatus:
    name: str
    label: str
    help: str
    configured: bool
    source: str | None  # panel | env | None
    hint: str | None
    updated_at: datetime | None
    env: str = ""                   # the .env variable behind it
    env_state: str | None = None    # see env_state()
    env_error: str | None = None    # why .env could not be updated (envfile reason code)


def env_state(env: str, current: str | None) -> str | None:
    """How the value in use compares with the server's .env (as this process sees it):
    "sync" equal · "panel_only" not in .env · "differs" .env has another value · "env_only"
    removed in the panel but still in .env · None neither has it. "differs" and "env_only"
    happen only when the panel could not write .env: on the next start .env wins."""
    value = os.environ.get(env, "").strip() if env else ""
    if current is None:
        return "env_only" if value else None
    if not value:
        return "panel_only"
    return "sync" if hmac.compare_digest(value.encode(), current.strip().encode()) else "differs"


def _load_key(db_path: Path) -> tuple[bytes, bool]:
    env = os.environ.get("MULTICDN_SECRET_KEY")
    if env:
        return env.encode(), False
    key_file = db_path.parent / ".secret_key"
    if not key_file.exists():
        key_file.write_bytes(Fernet.generate_key())
        key_file.chmod(0o600)
    return key_file.read_bytes().strip(), True


PLAIN_FIELDS = {"telegram_chat_id", "alert_email_to"}  # no son secretos: se muestran enteros


def _hint(value: str) -> str:
    return "····" + value[-4:] if len(value) > 8 else "····"


def dsn_server(dsn: str) -> str | None:
    """scheme://host[:port] of a URL: the DSN's key, path and project id stay out."""
    try:
        parts = urlsplit(dsn)
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not host:
        return None
    host = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{host}" + (f":{port}" if port and port not in (80, 443) else "")


def hint_for(name: str, value: str) -> str:
    if name in PLAIN_FIELDS:
        return value
    if name == "sentry_dsn":
        return dsn_server(value) or "····"
    return _hint(value)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class SecretStore:
    def __init__(self, path: str | Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        key, self.key_on_disk = _load_key(path)
        self.fernet = Fernet(key)
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        if "source" not in {r[1] for r in self.conn.execute("PRAGMA table_info(secrets)")}:
            # Before 0.3.1 everything in this table had been saved from the panel.
            self.conn.execute("ALTER TABLE secrets ADD COLUMN source TEXT NOT NULL DEFAULT 'panel'")
            self.conn.commit()

    def set(self, name: str, value: str, source: str = "panel") -> None:
        value = value.strip()
        if not value:
            raise ValueError(tr("empty value"))
        self.conn.execute(
            "INSERT INTO secrets (name, ciphertext, hint, updated_at, source) VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT(name) DO UPDATE SET ciphertext=excluded.ciphertext, hint=excluded.hint,"
            " updated_at=excluded.updated_at, source=excluded.source",
            (name, self.fernet.encrypt(value.encode()), hint_for(name, value), _now(), source),
        )
        self.conn.commit()

    def delete(self, name: str) -> None:
        self.conn.execute("DELETE FROM secrets WHERE name = ?", (name,))
        self.conn.commit()

    def get(self, name: str) -> str | None:
        row = self.conn.execute("SELECT ciphertext FROM secrets WHERE name = ?", (name,)).fetchone()
        if row:
            try:
                return self.fernet.decrypt(row[0]).decode()
            except InvalidToken:
                return None  # clave maestra cambiada: tratar como no configurado
        return None  # the .env is imported at startup (import_env): the database is the only source

    def hint(self, name: str) -> str | None:
        row = self.conn.execute("SELECT hint FROM secrets WHERE name = ?", (name,)).fetchone()
        return row[0] if row else None

    def source(self, name: str) -> tuple[str, datetime] | None:
        """(panel | env, when it was saved or imported)."""
        row = self.conn.execute("SELECT source, updated_at FROM secrets WHERE name = ?", (name,)).fetchone()
        return (row[0], datetime.fromisoformat(row[1])) if row else None

    # ---- sync with the server's .env
    def meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM secret_meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute("INSERT INTO secret_meta (key, value) VALUES (?, ?)"
                          " ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        self.conn.commit()

    def del_meta(self, key: str) -> None:
        self.conn.execute("DELETE FROM secret_meta WHERE key = ?", (key,))
        self.conn.commit()

    def import_env(self) -> list[str]:
        """At startup the server's .env has priority: every secret whose .env value differs from
        the stored one is imported; returns their names (equal values import nothing, so a
        restart does not repeat the history entry)."""
        imported = []
        for name, (_label, env, _help) in CREDENTIALS.items():
            value = os.environ.get(env, "").strip()
            if not value or self.get(name) == value:
                continue
            self.set(name, value, source="env")
            self.del_meta(f"env_error:{env}")
            imported.append(name)
        return imported

    def env_error(self, env: str) -> str | None:
        """Why the last write of this variable to .env failed (envfile reason code)."""
        return self.meta(f"env_error:{env}")

    def status(self, name: str) -> SecretStatus:
        label, env, help_ = CREDENTIALS[name]
        label, help_ = tr(label), tr(help_)
        row = self.conn.execute("SELECT hint, updated_at, source FROM secrets WHERE name = ?", (name,)).fetchone()
        state = env_state(env, self.get(name) if row else None)
        error = self.env_error(env) if state in ("differs", "env_only") else None
        if row:
            return SecretStatus(name, label, help_, True, row[2], row[0], datetime.fromisoformat(row[1]), env, state, error)
        return SecretStatus(name, label, help_, False, None, None, None, env, state, error)

    def all_status(self) -> list[SecretStatus]:
        return [self.status(n) for n in CREDENTIALS]
