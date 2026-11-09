"""Autenticación propia del panel: contraseña (scrypt) + TOTP (RFC 6238), sesiones y bloqueo.

Segunda capa además de Tailscale: protege el panel aunque alguien llegue a su puerto
local sin pasar por la tailnet (p. ej. otro proceso del mismo VPS).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .secrets_store import SecretStore
from .i18n import tr

PASSWORD_MIN = 12
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
TOTP_STEP, TOTP_DIGITS, TOTP_WINDOW = 30, 6, 1
IDLE_TIMEOUT = timedelta(minutes=30)
ABSOLUTE_TIMEOUT = timedelta(hours=12)
PENDING_TIMEOUT = timedelta(minutes=5)       # entre la contraseña y el código TOTP
MAX_FAILURES = 5
LOCK_FIRST, LOCK_REPEAT = timedelta(minutes=15), timedelta(hours=1)
RECOVERY_CODES = 10

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    totp_secret BLOB,             -- cifrado con la clave maestra
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    last_totp_step INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id_hash TEXT PRIMARY KEY,     -- sha256 del identificador de la cookie
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stage TEXT NOT NULL,          -- pending | enroll | full
    csrf TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT
);
CREATE TABLE IF NOT EXISTS login_attempts (
    key TEXT PRIMARY KEY,         -- u:<usuario> | ip:<ip>
    failures INTEGER NOT NULL,
    locked_until TEXT,
    lock_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS recovery_codes (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TEXT
);
"""


# ---------------------------------------------------------------- contraseña

def hash_password(password: str) -> str:
    if len(password) < PASSWORD_MIN:
        raise ValueError(tr("the password must have at least {min} characters", min=PASSWORD_MIN))
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                              maxmem=64 * 1024 * 1024, dklen=32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(calc, base64.b64decode(dk))


# Hash fijo para gastar el mismo tiempo cuando el usuario no existe (no revela si existe).
_DUMMY_HASH = hash_password("x" * PASSWORD_MIN)


# ---------------------------------------------------------------- TOTP (RFC 6238)

def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _b32(secret: str) -> bytes:
    return base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)


def totp_at(secret: str, step: int, digits: int = TOTP_DIGITS, digest=hashlib.sha1) -> str:
    mac = hmac.new(_b32(secret), struct.pack(">Q", step), digest).digest()
    offset = mac[-1] & 0x0F
    value = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 10**digits
    return str(value).zfill(digits)


def verify_totp(secret: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """Devuelve el paso aceptado (para impedir reutilizarlo) o None."""
    code = "".join(c for c in code if c.isdigit())
    if len(code) != TOTP_DIGITS:
        return None
    current = int((now if now is not None else time.time()) // TOTP_STEP)
    for step in range(current - TOTP_WINDOW, current + TOTP_WINDOW + 1):
        if step > last_step and hmac.compare_digest(totp_at(secret, step), code):
            return step
    return None


def totp_uri(secret: str, username: str, issuer: str = "Multi-CDN") -> str:
    from urllib.parse import quote
    return f"otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret}&issuer={quote(issuer)}&digits=6&period=30"


# ---------------------------------------------------------------- almacenamiento

@dataclass
class User:
    id: int
    username: str
    totp_enabled: bool


@dataclass
class Session:
    user: User
    stage: str
    csrf: str
    created_at: datetime
    last_seen: datetime
    id_hash: str
    ip: str | None
    user_agent: str | None


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class AuthStore:
    def __init__(self, secrets_store: SecretStore):
        self.secrets = secrets_store
        self.conn = secrets_store.conn
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)

    # ---- usuarios
    def has_users(self) -> bool:
        return self.conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None

    def create_user(self, username: str, password: str) -> int:
        username = username.strip().lower()
        if not username or not username.replace("-", "").replace("_", "").replace(".", "").isalnum():
            raise ValueError(tr("invalid username (letters, numbers, dot, hyphen or underscore)"))
        if self.conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            raise ValueError(tr("the user {user} already exists", user=username))
        cur = self.conn.execute("INSERT INTO users (username, pw_hash, created_at) VALUES (?, ?, ?)",
                                (username, hash_password(password), _iso(_now())))
        self.conn.commit()
        return cur.lastrowid

    def list_users(self) -> list[User]:
        return [User(r[0], r[1], bool(r[2])) for r in self.conn.execute("SELECT id, username, totp_enabled FROM users ORDER BY username")]

    def get_user(self, username: str) -> User | None:
        r = self.conn.execute("SELECT id, username, totp_enabled FROM users WHERE username=?", (username.strip().lower(),)).fetchone()
        return User(r[0], r[1], bool(r[2])) if r else None

    def set_password(self, user_id: int, password: str) -> None:
        self.conn.execute("UPDATE users SET pw_hash=? WHERE id=?", (hash_password(password), user_id))
        self.conn.commit()

    def check_password(self, username: str, password: str) -> User | None:
        r = self.conn.execute("SELECT id, username, totp_enabled, pw_hash FROM users WHERE username=?",
                              (username.strip().lower(),)).fetchone()
        if not r:
            verify_password(password, _DUMMY_HASH)
            return None
        return User(r[0], r[1], bool(r[2])) if verify_password(password, r[3]) else None

    # ---- TOTP
    def start_totp_enrollment(self, user_id: int) -> str:
        secret = new_totp_secret()
        self.conn.execute("UPDATE users SET totp_secret=?, totp_enabled=0, last_totp_step=0 WHERE id=?",
                          (self.secrets.fernet.encrypt(secret.encode()), user_id))
        self.conn.commit()
        return secret

    def totp_secret(self, user_id: int) -> str | None:
        r = self.conn.execute("SELECT totp_secret FROM users WHERE id=?", (user_id,)).fetchone()
        return self.secrets.fernet.decrypt(r[0]).decode() if r and r[0] else None

    def check_totp(self, user_id: int, code: str) -> bool:
        r = self.conn.execute("SELECT totp_secret, last_totp_step FROM users WHERE id=?", (user_id,)).fetchone()
        if not r or not r[0]:
            return False
        step = verify_totp(self.secrets.fernet.decrypt(r[0]).decode(), code, r[1])
        if step is None:
            return False
        self.conn.execute("UPDATE users SET last_totp_step=? WHERE id=?", (step, user_id))
        self.conn.commit()
        return True

    def enable_totp(self, user_id: int) -> None:
        self.conn.execute("UPDATE users SET totp_enabled=1 WHERE id=?", (user_id,))
        self.conn.commit()

    def reset_totp(self, user_id: int) -> None:
        with self.conn:
            self.conn.execute("UPDATE users SET totp_secret=NULL, totp_enabled=0, last_totp_step=0 WHERE id=?", (user_id,))
            self.conn.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
        self.close_sessions(user_id)

    # ---- códigos de recuperación
    def new_recovery_codes(self, user_id: int) -> list[str]:
        alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
        codes = ["-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(2)) for _ in range(RECOVERY_CODES)]
        with self.conn:
            self.conn.execute("DELETE FROM recovery_codes WHERE user_id=?", (user_id,))
            self.conn.executemany("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
                                  [(user_id, _sha(c)) for c in codes])
        return codes

    def use_recovery_code(self, user_id: int, code: str) -> bool:
        cur = self.conn.execute(
            "UPDATE recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL",
            (_iso(_now()), user_id, _sha(code.strip().lower())))
        self.conn.commit()
        return cur.rowcount == 1

    def recovery_left(self, user_id: int) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used_at IS NULL", (user_id,)).fetchone()[0]

    # ---- sesiones
    def create_session(self, user_id: int, stage: str, ip: str | None, user_agent: str | None) -> str:
        token = secrets.token_urlsafe(32)
        now = _iso(_now())
        self.conn.execute(
            "INSERT INTO sessions (id_hash, user_id, stage, csrf, created_at, last_seen, ip, user_agent) VALUES (?,?,?,?,?,?,?,?)",
            (_sha(token), user_id, stage, secrets.token_urlsafe(24), now, now, ip, (user_agent or "")[:200]))
        self.conn.commit()
        return token

    def get_session(self, token: str | None, touch: bool = True) -> Session | None:
        if not token:
            return None
        r = self.conn.execute(
            "SELECT s.id_hash, s.stage, s.csrf, s.created_at, s.last_seen, s.ip, s.user_agent, u.id, u.username, u.totp_enabled"
            " FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash=?", (_sha(token),)).fetchone()
        if not r:
            return None
        sess = Session(User(r[7], r[8], bool(r[9])), r[1], r[2], datetime.fromisoformat(r[3]),
                       datetime.fromisoformat(r[4]), r[0], r[5], r[6])
        now = _now()
        limit_idle = PENDING_TIMEOUT if sess.stage != "full" else IDLE_TIMEOUT
        if now - sess.last_seen > limit_idle or now - sess.created_at > ABSOLUTE_TIMEOUT:
            self.conn.execute("DELETE FROM sessions WHERE id_hash=?", (sess.id_hash,))
            self.conn.commit()
            return None
        if touch and sess.stage == "full" and (now - sess.last_seen).total_seconds() > 60:  # no escribir en cada petición
            self.conn.execute("UPDATE sessions SET last_seen=? WHERE id_hash=?", (_iso(now), sess.id_hash))
            self.conn.commit()
        return sess

    def delete_session(self, id_hash: str) -> None:
        self.conn.execute("DELETE FROM sessions WHERE id_hash=?", (id_hash,))
        self.conn.commit()

    def close_sessions(self, user_id: int | None = None, except_hash: str | None = None) -> int:
        sql, args = "DELETE FROM sessions WHERE 1=1", []
        if user_id is not None:
            sql, args = sql + " AND user_id=?", [user_id]
        if except_hash:
            sql, args = sql + " AND id_hash<>?", args + [except_hash]
        n = self.conn.execute(sql, args).rowcount
        self.conn.commit()
        return n

    def list_sessions(self, user_id: int) -> list[Session]:
        rows = self.conn.execute("SELECT id_hash FROM sessions WHERE user_id=? AND stage='full' ORDER BY last_seen DESC",
                                 (user_id,)).fetchall()
        out = []
        for (h,) in rows:
            r = self.conn.execute("SELECT stage, csrf, created_at, last_seen, ip, user_agent FROM sessions WHERE id_hash=?", (h,)).fetchone()
            user = self.conn.execute("SELECT id, username, totp_enabled FROM users WHERE id=?", (user_id,)).fetchone()
            out.append(Session(User(user[0], user[1], bool(user[2])), r[0], r[1], datetime.fromisoformat(r[2]),
                               datetime.fromisoformat(r[3]), h, r[4], r[5]))
        return out

    def purge_expired(self) -> None:
        now = _now()
        self.conn.execute("DELETE FROM sessions WHERE created_at < ?", (_iso(now - ABSOLUTE_TIMEOUT),))
        self.conn.execute("DELETE FROM sessions WHERE stage='full' AND last_seen < ?", (_iso(now - IDLE_TIMEOUT),))
        self.conn.execute("DELETE FROM sessions WHERE stage<>'full' AND last_seen < ?", (_iso(now - PENDING_TIMEOUT),))
        self.conn.commit()

    # ---- límite de intentos
    def locked(self, *keys: str) -> datetime | None:
        now = _now()
        until = None
        for key in keys:
            r = self.conn.execute("SELECT locked_until FROM login_attempts WHERE key=?", (key,)).fetchone()
            if r and r[0] and datetime.fromisoformat(r[0]) > now:
                t = datetime.fromisoformat(r[0])
                until = t if until is None or t > until else until
        return until

    def register_failure(self, *keys: str) -> None:
        now = _now()
        for key in keys:
            r = self.conn.execute("SELECT failures, lock_count FROM login_attempts WHERE key=?", (key,)).fetchone()
            failures, lock_count = (r[0] + 1, r[1]) if r else (1, 0)
            locked_until = None
            if failures >= MAX_FAILURES:
                locked_until = _iso(now + (LOCK_FIRST if lock_count == 0 else LOCK_REPEAT))
                failures, lock_count = 0, lock_count + 1
            self.conn.execute(
                "INSERT INTO login_attempts (key, failures, locked_until, lock_count) VALUES (?,?,?,?)"
                " ON CONFLICT(key) DO UPDATE SET failures=excluded.failures,"
                " locked_until=COALESCE(excluded.locked_until, login_attempts.locked_until), lock_count=excluded.lock_count",
                (key, failures, locked_until, lock_count))
        self.conn.commit()

    def register_success(self, *keys: str) -> None:
        self.conn.executemany("DELETE FROM login_attempts WHERE key=?", [(k,) for k in keys])
        self.conn.commit()
