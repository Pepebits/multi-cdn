from datetime import UTC, datetime, timedelta

import pytest

from app import auth
from app.secrets_store import SecretStore

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890" en base32 (RFC 6238)  # gitleaks:allow


@pytest.mark.parametrize("t, expected", [(59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"),
                                         (2000000000, "69279037")])
def test_totp_rfc6238_vectors(t, expected):
    assert auth.totp_at(RFC_SECRET, t // 30, digits=8) == expected


def test_totp_window_and_no_replay():
    secret = auth.new_totp_secret()
    now = 1_800_000_000
    code = auth.totp_at(secret, now // 30)
    step = auth.verify_totp(secret, code, last_step=0, now=now)
    assert step == now // 30
    assert auth.verify_totp(secret, code, last_step=step, now=now) is None  # no se reutiliza
    prev = auth.totp_at(secret, now // 30 - 1)
    assert auth.verify_totp(secret, prev, last_step=0, now=now) is not None  # ±1 ventana
    assert auth.verify_totp(secret, auth.totp_at(secret, now // 30 - 3), 0, now=now) is None
    assert auth.verify_totp(secret, "12", 0, now=now) is None


def test_password_hashing():
    with pytest.raises(ValueError):
        auth.hash_password("corta")
    a, b = auth.hash_password("una-contraseña-larga"), auth.hash_password("una-contraseña-larga")
    assert a != b  # sal distinta
    assert auth.verify_password("una-contraseña-larga", a)
    assert not auth.verify_password("otra-contraseña-larga", a)
    assert not auth.verify_password("x", "basura")


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.delenv("MULTICDN_SECRET_KEY", raising=False)
    return auth.AuthStore(SecretStore(tmp_path / "a.db"))


def test_user_and_totp_flow(store):
    assert not store.has_users()
    uid = store.create_user("Daniel", "contraseña-muy-larga")
    with pytest.raises(ValueError):
        store.create_user("daniel", "contraseña-muy-larga")
    assert store.check_password("daniel", "contraseña-muy-larga").id == uid
    assert store.check_password("daniel", "mala-contraseña-x") is None
    assert store.check_password("nadie", "contraseña-muy-larga") is None
    secret = store.start_totp_enrollment(uid)
    raw = store.conn.execute("SELECT totp_secret FROM users").fetchone()[0]
    assert secret.encode() not in raw  # cifrado en la base de datos
    import time
    assert store.check_totp(uid, auth.totp_at(secret, int(time.time()) // 30))
    assert not store.check_totp(uid, auth.totp_at(secret, int(time.time()) // 30))  # reutilización


def test_recovery_codes_single_use(store):
    uid = store.create_user("daniel", "contraseña-muy-larga")
    codes = store.new_recovery_codes(uid)
    assert len(codes) == 10 and len(set(codes)) == 10
    assert store.use_recovery_code(uid, codes[0])
    assert not store.use_recovery_code(uid, codes[0])
    assert store.recovery_left(uid) == 9
    assert codes[1] not in str(store.conn.execute("SELECT * FROM recovery_codes").fetchall())


def test_sessions_expire_and_rotate(store):
    uid = store.create_user("daniel", "contraseña-muy-larga")
    token = store.create_session(uid, "full", "127.0.0.1", "test")
    assert token not in str(store.conn.execute("SELECT * FROM sessions").fetchall())  # solo el hash
    s = store.get_session(token)
    assert s.user.username == "daniel" and s.stage == "full"
    old = (datetime.now(UTC) - auth.IDLE_TIMEOUT - timedelta(minutes=1)).isoformat(timespec="seconds")
    store.conn.execute("UPDATE sessions SET last_seen=?", (old,))
    assert store.get_session(token) is None  # inactividad
    token = store.create_session(uid, "full", None, None)
    store.conn.execute("UPDATE sessions SET created_at=?",
                       ((datetime.now(UTC) - auth.ABSOLUTE_TIMEOUT - timedelta(minutes=1)).isoformat(timespec="seconds"),))
    assert store.get_session(token) is None  # caducidad absoluta
    pending = store.create_session(uid, "pending", None, None)
    store.conn.execute("UPDATE sessions SET last_seen=?",
                       ((datetime.now(UTC) - auth.PENDING_TIMEOUT - timedelta(seconds=5)).isoformat(timespec="seconds"),))
    assert store.get_session(pending) is None


def test_lockout(store):
    keys = ("u:daniel", "ip:1.2.3.4")
    for _ in range(auth.MAX_FAILURES - 1):
        store.register_failure(*keys)
    assert store.locked(*keys) is None
    store.register_failure(*keys)
    until = store.locked(*keys)
    assert until and until > datetime.now(UTC) + timedelta(minutes=14)
    assert store.locked("ip:1.2.3.4") is not None
    store.register_success(*keys)
    assert store.locked(*keys) is None


def test_reset_totp_closes_sessions(store):
    uid = store.create_user("daniel", "contraseña-muy-larga")
    store.start_totp_enrollment(uid)
    store.enable_totp(uid)
    token = store.create_session(uid, "full", None, None)
    store.reset_totp(uid)
    assert store.get_session(token) is None
    assert not store.get_user("daniel").totp_enabled
