import json
from datetime import UTC, datetime, timedelta

from app import firewall_status

NOW = datetime(2026, 11, 9, 12, tzinfo=UTC)


def write(client, **kw):
    data = {"checked_at": "2026-11-09T11:30:00Z", "last_ok": "2026-11-09T11:30:00Z", "ipv4": 1000, "ipv6": 850,
            "caddy": "sin cambios", "error": ""} | kw
    (firewall_status.data_dir() / "firewall-status.json").write_text(json.dumps(data))


def alerts(state):
    return [e.summary for e in state.events.list(limit=20) if e.kind == "alert"]


def test_alerts_once_on_problem_and_on_recovery(client):
    state = client.app.state.mc
    firewall_status.check(state, NOW)  # sin script instalado: nada
    write(client)
    firewall_status.check(state, NOW)
    assert not alerts(state)
    write(client, error="la lista gc4 ha llegado vacía")
    firewall_status.check(state, NOW)
    firewall_status.check(state, NOW)
    assert alerts(state) == ["Firewall del origen: la última actualización falló: la lista gc4 ha llegado vacía"]
    write(client)
    firewall_status.check(state, NOW + timedelta(days=2))  # sin error pero con la lista vieja
    assert "no se actualizan desde 09/11 11:30" in alerts(state)[0]
    write(client, last_ok="2026-11-11T11:00:00Z")
    firewall_status.check(state, NOW + timedelta(days=2))
    assert alerts(state)[0] == "Firewall del origen: rangos actualizados de nuevo"


def test_settings_show_status_and_switch_requests_refresh(client):
    page = client.get("/ajustes/servidores").text
    assert "Sin instalar" in page
    write(client)
    page = client.get("/ajustes/servidores").text
    assert "1000 IPv4 · 850 IPv6" in page and "Al día" in page
    state = client.app.state.mc
    cf = state.creds.add("cloudflare", "CF", "cf-token-123456")
    state.store.set_credentials("example.com", cf, None)
    state.store.set_gcore("example.com", 33, 22, "2027-01-01T00:00:00+00:00", "cl-test.gcorecdn.com",
                          ["example.com", "www.example.com"])
    state.reload()
    client.post("/dominios/example.com/cambiar", data={"target": "gcore", "confirm": "example.com"})
    assert (firewall_status.data_dir() / "firewall-refresh-request").exists()


def test_requests_hourly_refresh_while_serving_gcore(client):
    from app.signals.dnscheck import Resolution
    state = client.app.state.mc
    request = firewall_status.data_dir() / "firewall-refresh-request"
    write(client)  # última lista: 11:30
    firewall_status.check(state, NOW)  # en Cloudflare: no pide nada
    assert not request.exists()
    state.resolutions = {"example.com": Resolution("example.com", ("5.188.126.61",), "cl-a.gcorecdn.com.", "gcore")}
    firewall_status.check(state, NOW)  # 30 min: aún vale
    assert not request.exists()
    firewall_status.check(state, NOW + timedelta(hours=1))
    assert request.exists()


def test_settings_list_recent_changes(client):
    write(client, added=3, removed=1)
    (firewall_status.data_dir() / "firewall-changes.log").write_text("2026-11-08T11:30:00Z +1850 -0\n2026-11-09T11:30:00Z +3 -1\n")
    page = client.get("/ajustes/servidores").text
    assert "+3 / −1" in page and "Cambios recientes en las listas" in page and "1850" in page
