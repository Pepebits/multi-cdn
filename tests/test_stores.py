import sqlite3

import pytest

from app.inventory_store import InventoryStore, origin_key
from app.secrets_store import SecretStore


@pytest.fixture
def stores(tmp_path, monkeypatch):
    monkeypatch.delenv("MULTICDN_SECRET_KEY", raising=False)
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    db = tmp_path / "t.db"
    secrets = SecretStore(db)
    return db, secrets, InventoryStore(secrets)


def test_secret_is_encrypted_at_rest(stores):
    db, secrets, _ = stores
    secrets.set("cloudflare_token", "cf-super-secret-token-1234")
    raw = sqlite3.connect(db).execute("SELECT ciphertext, hint FROM secrets").fetchone()
    assert b"cf-super-secret" not in raw[0]
    assert raw[1] == "····1234"
    assert secrets.get("cloudflare_token") == "cf-super-secret-token-1234"
    assert (db.parent / ".secret_key").stat().st_mode & 0o777 == 0o600


def test_env_fallback_and_status(stores, monkeypatch):
    _, secrets, _ = stores
    assert secrets.status("telegram_token").configured is False
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "telegram-env-value-9999")
    st = secrets.status("telegram_token")
    assert st.configured and st.source == "entorno" and st.hint == "····9999"


def test_wrong_master_key_reads_as_unset(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet
    monkeypatch.setenv("MULTICDN_SECRET_KEY", Fernet.generate_key().decode())
    SecretStore(tmp_path / "t.db").set("telegram_token", "abcdefghijkl")
    monkeypatch.setenv("MULTICDN_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    assert SecretStore(tmp_path / "t.db").get("telegram_token") is None


def test_inventory_roundtrip_keeps_origin_out_of_plain_tables(stores):
    db, secrets, inv = stores
    inv.upsert_server("vps-1", "192.0.2.10", None)
    inv.upsert_domain("Example.COM.", policy="preventive", priority="critical")
    inv.upsert_hostname("example.com", "www.example.com", server="vps-1", gcore_target="example-com.a.gcdn.co")
    loaded = inv.load()
    assert loaded.origin_ips == {"192.0.2.10"}
    assert loaded.domains["example.com"].hostnames[0].gcore_target == "example-com.a.gcdn.co"
    dump = "\n".join(sqlite3.connect(db).iterdump())
    assert "192.0.2.10" not in dump
    assert secrets.get(origin_key("vps-1")) == "192.0.2.10"


def test_export_has_no_secrets(stores):
    _, _, inv = stores
    inv.upsert_server("vps-1", "192.0.2.10", None)
    inv.upsert_domain("example.com", policy="reactive", priority="low")
    out = inv.export_yaml()
    assert "192.0.2.10" not in out
    assert "${ORIGIN_VPS_1_IPV4}" in out


@pytest.mark.parametrize("bad", ["", "localhost", "exa mple.com", "-a.com", "a..com"])
def test_invalid_domain_names(stores, bad):
    _, _, inv = stores
    with pytest.raises(ValueError):
        inv.upsert_domain(bad, policy="reactive", priority="low")


def test_hostname_outside_zone_and_server_in_use(stores):
    _, _, inv = stores
    inv.upsert_server("vps-1", None, None)
    inv.upsert_domain("example.com", policy="reactive", priority="low")
    with pytest.raises(ValueError):
        inv.upsert_hostname("example.com", "example.net", server="vps-1")
    inv.upsert_hostname("example.com", "example.com", server="vps-1")
    with pytest.raises(ValueError):
        inv.delete_server("vps-1")
    inv.delete_domain("example.com")  # en cascada
    inv.delete_server("vps-1")
    assert inv.is_empty()


def test_event_retention(tmp_path):
    from datetime import UTC, datetime, timedelta

    from app.db import EventStore
    ev = EventStore(tmp_path / "e.db")
    old = (datetime.now(UTC) - timedelta(days=400)).isoformat(timespec="seconds")
    ev.conn.execute("INSERT INTO events (ts, actor, kind, summary) VALUES (?, 'auto', 'alert', 'viejo')", (old,))
    for i in range(30):
        ev.add(actor="auto", kind="alert", summary=f"nuevo {i}")
    assert ev.stats()["count"] == 31
    assert ev.prune() == 1  # 180 días por defecto
    ev.set_setting("events_max_rows", 500)
    with pytest.raises(ValueError):
        ev.set_setting("events_max_rows", 10)
    with pytest.raises(ValueError):
        ev.set_setting("events_max_days", 1)
    ev.conn.executemany("INSERT INTO events (ts, actor, kind, summary) VALUES (?, 'auto', 'alert', 'x')",
                        [(datetime.now(UTC).isoformat(timespec="seconds"),)] * 600)
    ev.prune()
    assert ev.stats()["count"] == 500
    assert ev.list(limit=1)[0].summary  # conserva los más recientes
