import pytest

from app.config import load_inventory

YAML = """
servers:
  vps-1:
    origin_ipv4: ${TEST_ORIGIN_IP}
domains:
  example.com:
    policy: preventive
    priority: critical
    hostnames:
      - {name: example.com, server: vps-1}
      - {name: www.example.com, server: vps-1}
  example.net:
    priority: low
    hostnames:
      - {name: example.net, server: vps-1}
"""


def write(tmp_path, text=YAML):
    p = tmp_path / "inv.yaml"
    p.write_text(text)
    return p


def test_origin_ip_comes_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_ORIGIN_IP", "192.0.2.10")
    inv = load_inventory(write(tmp_path))
    assert inv.origin_ips == {"192.0.2.10"}


def test_missing_env_means_not_configured(tmp_path, monkeypatch):
    monkeypatch.delenv("TEST_ORIGIN_IP", raising=False)
    inv = load_inventory(write(tmp_path))
    assert inv.origin_ips == set()


def test_order_by_priority(tmp_path):
    inv = load_inventory(write(tmp_path))
    assert [n for n, _ in inv.ordered_domains()] == ["example.com", "example.net"]


def test_hostname_must_belong_to_zone(tmp_path):
    bad = YAML.replace("www.example.com", "www.otro.com")
    with pytest.raises(ValueError):
        load_inventory(write(tmp_path, bad))


def test_unknown_server(tmp_path):
    bad = YAML.replace("{name: example.net, server: vps-1}", "{name: example.net, server: vps-9}")
    with pytest.raises(ValueError):
        load_inventory(write(tmp_path, bad))


def test_example_inventory_is_valid():
    inv = load_inventory("inventory.example.yaml")
    assert "example.com" in inv.domains


def test_private_address_accepts_hosts_and_ips_and_legacy_key():
    import pytest
    from app.config import Server
    assert Server(private_address=" VPS-2.Tailnet.ts.net. ").private_address == "vps-2.tailnet.ts.net"
    assert Server(private_address="100.101.102.103").private_address == "100.101.102.103"
    assert Server(private_address="fd7a:115c:a1e0::1").private_address == "fd7a:115c:a1e0::1"
    assert Server(tailscale="vps-1.example-tailnet.ts.net").private_address == "vps-1.example-tailnet.ts.net"
    assert Server(private_address="").private_address is None
    with pytest.raises(ValueError):
        Server(private_address="no vale/esto")


def test_old_database_keeps_its_value_after_the_rename(tmp_path, monkeypatch):
    import sqlite3
    from app.inventory_store import InventoryStore
    from app.secrets_store import SecretStore
    monkeypatch.delenv("MULTICDN_SECRET_KEY", raising=False)
    db = tmp_path / "old.db"
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE servers (id TEXT PRIMARY KEY, tailscale TEXT)")
        c.execute("INSERT INTO servers VALUES ('vps-1', 'vps-1.tailnet.ts.net')")
    store = InventoryStore(SecretStore(db))
    assert store.load().servers["vps-1"].private_address == "vps-1.tailnet.ts.net"
    assert "private_address: vps-1.tailnet.ts.net" in store.export_yaml()
