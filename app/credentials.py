"""Credenciales de proveedor (Cloudflare, Gcore): varias por proveedor, asignables por dominio.

Cada credencial puede cubrir una cuenta entera o solo un dominio (p. ej. un token de
Cloudflare limitado a una zona). El secreto se guarda cifrado en el SecretStore como
"cred:<id>"; aquí solo viven los metadatos.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .secrets_store import SecretStore, _hint

PROVIDERS = {"cloudflare": "Cloudflare", "gcore": "Gcore"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS provider_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    label TEXT NOT NULL,
    hint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    checked_at TEXT,
    check_ok INTEGER,
    check_msg TEXT,
    scope TEXT,               -- p. ej. zonas visibles con el token
    UNIQUE(provider, label)
);
"""


@dataclass
class Credential:
    id: int
    provider: str
    label: str
    hint: str
    created_at: datetime
    checked_at: datetime | None
    check_ok: bool | None
    check_msg: str | None
    scope: str | None

    @property
    def provider_label(self) -> str:
        return PROVIDERS[self.provider]

    @property
    def display(self) -> str:
        return f"{self.label} ({self.provider_label} {self.hint})"


def _key(cred_id: int) -> str:
    return f"cred:{cred_id}"


def _ts(v: str | None) -> datetime | None:
    return datetime.fromisoformat(v) if v else None


class CredentialStore:
    def __init__(self, secrets: SecretStore):
        self.secrets = secrets
        self.conn = secrets.conn
        self.conn.executescript(SCHEMA)

    def add(self, provider: str, label: str, secret: str) -> int:
        if provider not in PROVIDERS:
            raise ValueError("proveedor no soportado")
        label, secret = label.strip(), secret.strip()
        if not label or not secret:
            raise ValueError("indica un nombre y la credencial")
        if self.conn.execute("SELECT 1 FROM provider_credentials WHERE provider=? AND label=?", (provider, label)).fetchone():
            raise ValueError(f"ya existe una credencial de {PROVIDERS[provider]} llamada «{label}»")
        cur = self.conn.execute(
            "INSERT INTO provider_credentials (provider, label, hint, created_at) VALUES (?, ?, ?, ?)",
            (provider, label, _hint(secret), datetime.now(UTC).isoformat(timespec="seconds")),
        )
        cred_id = cur.lastrowid
        self.secrets.set(_key(cred_id), secret)
        return cred_id

    def rotate(self, cred_id: int, secret: str) -> None:
        self.get(cred_id)
        self.secrets.set(_key(cred_id), secret)
        self.conn.execute("UPDATE provider_credentials SET hint=?, checked_at=NULL, check_ok=NULL, check_msg=NULL WHERE id=?",
                          (_hint(secret.strip()), cred_id))
        self.conn.commit()

    def record_check(self, cred_id: int, ok: bool, msg: str, scope: str | None = None) -> None:
        self.conn.execute(
            "UPDATE provider_credentials SET checked_at=?, check_ok=?, check_msg=?, scope=COALESCE(?, scope) WHERE id=?",
            (datetime.now(UTC).isoformat(timespec="seconds"), int(ok), msg, scope, cred_id),
        )
        self.conn.commit()

    def secret(self, cred_id: int | None) -> str | None:
        return self.secrets.get(_key(cred_id)) if cred_id else None

    def get(self, cred_id: int) -> Credential:
        row = self.conn.execute("SELECT * FROM provider_credentials WHERE id=?", (cred_id,)).fetchone()
        if not row:
            raise ValueError("credencial no encontrada")
        return self._row(row)

    def list(self, provider: str | None = None) -> list[Credential]:
        sql, args = "SELECT * FROM provider_credentials", ()
        if provider:
            sql, args = sql + " WHERE provider=?", (provider,)
        return [self._row(r) for r in self.conn.execute(sql + " ORDER BY provider, label", args)]

    def usage(self, cred_id: int) -> list[str]:
        return [r[0] for r in self.conn.execute(
            "SELECT name FROM domains WHERE cloudflare_credential=? OR gcore_credential=? ORDER BY name", (cred_id, cred_id))]

    def delete(self, cred_id: int) -> None:
        used = self.usage(cred_id)
        if used:
            raise ValueError(f"la usan {len(used)} dominios: {', '.join(used)}. Asígnales otra antes de borrarla")
        self.conn.execute("DELETE FROM provider_credentials WHERE id=?", (cred_id,))
        self.secrets.delete(_key(cred_id))

    @staticmethod
    def _row(r) -> Credential:
        return Credential(id=r[0], provider=r[1], label=r[2], hint=r[3], created_at=_ts(r[4]), checked_at=_ts(r[5]),
                          check_ok=None if r[6] is None else bool(r[6]), check_msg=r[7], scope=r[8])
