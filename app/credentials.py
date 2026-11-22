"""Credenciales de proveedor (Cloudflare, Gcore): varias por proveedor, asignables por dominio.

Cada credencial puede cubrir una cuenta entera o solo un dominio (p. ej. un token de
Cloudflare limitado a una zona). El secreto se guarda cifrado en el SecretStore como
"cred:<id>"; aquí solo viven los metadatos.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .i18n import N_, translate, tr, trn
from .secrets_store import SecretStore, _hint

PROVIDERS = {"cloudflare": "Cloudflare", "gcore": "Gcore"}
# Provider tokens that can also come from config/secrets.env (synced at startup, see envfile).
ENV_TOKENS = {"cloudflare": "CLOUDFLARE_API_TOKEN", "gcore": "GCORE_API_TOKEN"}
ENV_LABEL = N_("Imported from the environment")

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

    def add(self, provider: str, label: str, secret: str, source: str = "panel") -> int:
        if provider not in PROVIDERS:
            raise ValueError(tr("unsupported provider"))
        label, secret = label.strip(), secret.strip()
        if not label or not secret:
            raise ValueError(tr("enter a name and the credential"))
        if self.conn.execute("SELECT 1 FROM provider_credentials WHERE provider=? AND label=?", (provider, label)).fetchone():
            raise ValueError(tr("a {provider} credential named «{label}» already exists", provider=PROVIDERS[provider], label=label))
        cur = self.conn.execute(
            "INSERT INTO provider_credentials (provider, label, hint, created_at) VALUES (?, ?, ?, ?)",
            (provider, label, _hint(secret), datetime.now(UTC).isoformat(timespec="seconds")),
        )
        cred_id = cur.lastrowid
        assert cred_id is not None  # always set after an INSERT
        self.secrets.set(_key(cred_id), secret, source=source)
        return cred_id

    def rotate(self, cred_id: int, secret: str, source: str = "panel") -> None:
        self.get(cred_id)
        self.secrets.set(_key(cred_id), secret, source=source)
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
            raise ValueError(tr("credential not found"))
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
            raise ValueError(trn("{n} domain uses it: {domains}. Assign it another one before deleting it",
                                 "{n} domains use it: {domains}. Assign them another one before deleting it",
                                 len(used), domains=", ".join(used)))
        self.conn.execute("DELETE FROM provider_credentials WHERE id=?", (cred_id,))
        self.secrets.delete(_key(cred_id))

    # ---- sync with config/secrets.env (CLOUDFLARE_API_TOKEN, GCORE_API_TOKEN)
    def env_credential(self, provider: str) -> Credential | None:
        """The credential that holds the secrets-file token of this provider, if it still exists."""
        cred_id = self.secrets.meta(f"env_cred:{provider}")
        try:
            return self.get(int(cred_id)) if cred_id else None
        except ValueError:
            return None

    def import_env(self, label: str, source: dict[str, str]) -> list[str]:
        """At startup the token of each provider in `source` (variable -> value, see
        envfile.import_source) has priority: if it differs from the
        credential that holds it, that credential is updated (or created, named `label`; or an
        existing credential with that same token is adopted). Returns the providers updated."""
        imported = []
        for provider, env in ENV_TOKENS.items():
            value = (source.get(env) or "").strip()
            if not value:
                continue
            linked = self.env_credential(provider)
            if linked is None:
                # Before 0.3.1 the token was imported once, under ENV_LABEL: adopt that one if
                # it holds the same token, or any credential that does.
                names = {translate(ENV_LABEL, lang) for lang in ("en", "es")}
                existing = self.list(provider)
                linked = (next((c for c in existing if c.label in names and self.secret(c.id) == value), None)
                          or next((c for c in existing if self.secret(c.id) == value), None))
                if linked:
                    self.secrets.set_meta(f"env_cred:{provider}", str(linked.id))
            if linked and self.secret(linked.id) == value:
                continue
            if linked:
                self.rotate(linked.id, value, source="env")
            else:
                name, n = label, 2
                while self.conn.execute("SELECT 1 FROM provider_credentials WHERE provider=? AND label=?",
                                        (provider, name)).fetchone():
                    name, n = f"{label} ({n})", n + 1
                cred_id = self.add(provider, name, value, source="env")
                self.secrets.set_meta(f"env_cred:{provider}", str(cred_id))
            self.secrets.del_meta(f"env_error:{env}")
            imported.append(provider)
        return imported

    def env_status(self, cred: Credential) -> dict:
        """Where the credential's value comes from (env | panel), when, the secrets-file variable
        it is synced with (only the credential that holds that token) and how they compare."""
        from .secrets_store import env_state
        src = self.secrets.source(_key(cred.id))
        linked = self.env_credential(cred.provider)
        env = ENV_TOKENS[cred.provider] if linked and linked.id == cred.id else None
        state = env_state(env, self.secret(cred.id)) if env else None
        return {"source": src[0] if src else "panel", "at": src[1] if src else cred.created_at, "env": env,
                "state": state, "error": self.secrets.env_error(env) if env and state == "differs" else None}

    def env_removed(self) -> list[str]:
        """Secrets-file variables still set whose credential was deleted in the panel (the panel
        could not remove the line): the next start creates it again."""
        from .envfile import current
        return [env for provider, env in ENV_TOKENS.items()
                if current(env) and self.env_credential(provider) is None
                and self.secrets.meta(f"env_cred:{provider}")]

    @staticmethod
    def _row(r) -> Credential:
        return Credential(id=r[0], provider=r[1], label=r[2], hint=r[3], created_at=datetime.fromisoformat(r[4]), checked_at=_ts(r[5]),
                          check_ok=None if r[6] is None else bool(r[6]), check_msg=r[7], scope=r[8])
