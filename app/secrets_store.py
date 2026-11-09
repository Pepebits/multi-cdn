"""Credenciales cifradas en SQLite (Fernet). Solo escritura desde el panel.

La clave maestra viene de MULTICDN_SECRET_KEY. Si no existe, se genera una en
data/.secret_key (permisos 600) y el panel avisa: para que las copias de la base
de datos no sirvan sin la clave, guárdala fuera del VPS o pásala por entorno.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

# Secretos sueltos: nombre -> (etiqueta, variable de entorno de respaldo, descripción).
# Las credenciales de proveedores (Cloudflare, Gcore) van aparte: ver credentials.py.
CREDENTIALS: dict[str, tuple[str, str, str]] = {
    "telegram_token": ("Token del bot de Telegram", "TELEGRAM_BOT_TOKEN", "Bot creado con @BotFather."),
    "telegram_chat_id": ("Chat ID de Telegram", "TELEGRAM_CHAT_ID", "Chat o grupo que recibe las alertas."),
    "smtp_url": ("Servidor SMTP", "SMTP_URL", "Formato smtps://usuario:contraseña@host:465"),
    "alert_email_to": ("Email de alertas", "ALERT_EMAIL_TO", "Destinatario de los avisos por correo."),
    "football_data_token": ("Clave de football-data.org", "FOOTBALL_DATA_TOKEN", "Segunda fuente del calendario de LaLiga."),
    "heartbeat_url": ("URL de aviso externo", "MULTICDN_HEARTBEAT_URL",
                      "URL de ping de healthchecks.io (o compatible). Configura allí periodo 5 min y margen 10 min."),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets (
    name TEXT PRIMARY KEY,
    ciphertext BLOB NOT NULL,
    hint TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class SecretStatus:
    name: str
    label: str
    help: str
    configured: bool
    source: str | None  # panel | entorno | None
    hint: str | None
    updated_at: datetime | None


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


class SecretStore:
    def __init__(self, path: str | Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        key, self.key_on_disk = _load_key(path)
        self.fernet = Fernet(key)
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)

    def set(self, name: str, value: str) -> None:
        value = value.strip()
        if not value:
            raise ValueError("valor vacío")
        self.conn.execute(
            "INSERT INTO secrets (name, ciphertext, hint, updated_at) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(name) DO UPDATE SET ciphertext=excluded.ciphertext, hint=excluded.hint, updated_at=excluded.updated_at",
            (name, self.fernet.encrypt(value.encode()), value if name in PLAIN_FIELDS else _hint(value),
             datetime.now(UTC).isoformat(timespec="seconds")),
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
        env = CREDENTIALS.get(name, (None, None))[1]
        return os.environ.get(env) or None if env else None

    def hint(self, name: str) -> str | None:
        row = self.conn.execute("SELECT hint FROM secrets WHERE name = ?", (name,)).fetchone()
        return row[0] if row else None

    def status(self, name: str) -> SecretStatus:
        label, env, help_ = CREDENTIALS[name]
        row = self.conn.execute("SELECT hint, updated_at FROM secrets WHERE name = ?", (name,)).fetchone()
        if row:
            return SecretStatus(name, label, help_, True, "panel", row[0], datetime.fromisoformat(row[1]))
        if os.environ.get(env):
            value = os.environ[env]
            return SecretStatus(name, label, help_, True, "entorno", value if name in PLAIN_FIELDS else _hint(value), None)
        return SecretStatus(name, label, help_, False, None, None, None)

    def all_status(self) -> list[SecretStatus]:
        return [self.status(n) for n in CREDENTIALS]
