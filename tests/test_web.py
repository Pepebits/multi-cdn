import pytest
from fastapi.testclient import TestClient


def test_pages_render(client):
    for url in ("/", "/dominios", "/dominios/example.com", "/historial", "/historial?actor=manual",
                "/ajustes/cuentas", "/ajustes/notificaciones", "/ajustes/servidores", "/ajustes/operacion"):
        r = client.get(url)
        assert r.status_code == 200, url
        assert 'lang="es"' in r.text


def test_unknown_domain_404(client):
    assert client.get("/dominios/nope.example").status_code == 404


def test_switch_requires_confirmation(client):
    r = client.post("/dominios/example.com/cambiar", data={"target": "gcore", "confirm": "otro"}, follow_redirects=False)
    assert r.status_code == 303 and "error=" in r.headers["location"]


def test_switch_refused_without_gcore_target(client):
    r = client.post("/dominios/example.com/cambiar", data={"target": "gcore", "confirm": "example.com"}, follow_redirects=False)
    assert "Gcore+no+configurado" in r.headers["location"]


def test_add_domain_and_configure_gcore_then_simulated_switch(client):
    r = client.post("/dominios", data={"name": "example.org", "server": "vps-1", "priority": "critical",
                                       "policy": "preventive", "hostnames": ""}, follow_redirects=False)
    assert r.headers["location"].startswith("http://testserver/dominios/example.org")
    page = client.get("/dominios/example.org").text
    assert "www.example.org" in page
    client.post("/dominios/example.org/hostnames", data={
        "server:example.org": "vps-1", "gcore:example.org": "example-org.a.gcdn.co", "failover:example.org": "1",
        "server:www.example.org": "vps-1", "gcore:www.example.org": "example-org.a.gcdn.co", "failover:www.example.org": "1",
    })
    r = client.post("/dominios/example.org/cambiar", data={"target": "gcore", "confirm": "example.org"}, follow_redirects=False)
    assert "simulado" in r.headers["location"]
    hist = client.get("/historial?dominio=example.org").text
    assert "CF → GCORE" in hist and "Simulado" in hist


def test_notification_fields_are_write_only(client):
    client.post("/ajustes/notificaciones/telegram_token", data={"value": "tg-token-que-no-debe-verse-7777"})
    page = client.get("/ajustes/notificaciones").text
    assert "tg-token-que-no-debe-verse" not in page and "····7777" in page
    assert 'name="provider"' not in page  # las cuentas de proveedor van en otra pestaña


def test_two_cloudflare_accounts_assigned_per_domain(client, monkeypatch):
    from app.providers import cloudflare as cfmod

    async def fake_verify(token):
        return True, "ok"

    async def fake_zones(token):
        return [{"id": "z-" + token[-4:], "name": "example.com" if token.endswith("AAAA") else "example.net", "status": "active"}]

    monkeypatch.setattr(cfmod, "verify_token", fake_verify)
    monkeypatch.setattr(cfmod, "list_zones", fake_zones)
    client.post("/ajustes/cuentas", data={"provider": "cloudflare", "label": "Cuenta A", "secret": "token-cuenta-AAAA"})
    client.post("/ajustes/cuentas", data={"provider": "cloudflare", "label": "Cuenta B", "secret": "token-cuenta-BBBB"})
    page = client.get("/ajustes/cuentas").text
    assert "token-cuenta" not in page
    assert "Usada por: example.com" in page and "Usada por: example.net" in page
    state = client.app.state.mc
    a, b = (c.id for c in state.creds.list("cloudflare"))
    assert state.inventory.domains["example.com"].cloudflare_credential == a
    assert state.inventory.domains["example.com"].zone_id == "z-AAAA"
    assert state.inventory.domains["example.net"].cloudflare_credential == b
    assert state.cloudflare_for(state.inventory.domains["example.net"]).token == "token-cuenta-BBBB"
    # no se puede borrar una credencial en uso
    r = client.post(f"/ajustes/cuentas/{a}/eliminar", follow_redirects=False)
    assert "error=" in r.headers["location"]
    # reasignar por dominio desde su configuración
    client.post("/dominios/example.com/configuracion", data={"priority": "critical", "policy": "preventive",
                                                            "zone_id": "z-AAAA", "cloudflare_credential": str(b)})
    assert state.inventory.domains["example.com"].cloudflare_credential == b
    r = client.post(f"/ajustes/cuentas/{a}/eliminar", follow_redirects=False)
    assert "ok=" in r.headers["location"]


def test_wrong_provider_credential_rejected(client):
    client.app.state.mc.creds.add("gcore", "Gcore", "gcore-key-123456")
    gid = client.app.state.mc.creds.list("gcore")[0].id
    r = client.post("/dominios/example.com/configuracion", data={"priority": "critical", "policy": "preventive",
                                                                 "cloudflare_credential": str(gid)}, follow_redirects=False)
    assert "error=" in r.headers["location"]


def test_origin_ip_only_on_servers_page(client):
    client.post("/ajustes/servidores", data={"server_id": "vps-1", "origin_ipv4": "192.0.2.77", "private_address": ""})
    assert "192.0.2.77" in client.get("/ajustes/servidores").text
    for url in ("/", "/ajustes/cuentas", "/ajustes/operacion", "/dominios", "/dominios/example.com", "/historial"):
        assert "192.0.2.77" not in client.get(url).text, url
    assert "192.0.2.77" not in client.get("/ajustes/inventario.yaml").text


def test_rename_server_moves_hostnames_and_ip(client):
    client.post("/ajustes/servidores", data={"server_id": "vps-1", "origin_ipv4": "192.0.2.77", "private_address": ""})
    client.post("/ajustes/servidores/vps-1/editar", data={"new_id": "contabo-1", "origin_ipv4": "192.0.2.78", "private_address": ""})
    inv = client.app.state.mc.inventory
    assert "vps-1" not in inv.servers and str(inv.servers["contabo-1"].origin_ipv4) == "192.0.2.78"
    assert all(h.server == "contabo-1" for d in inv.domains.values() for h in d.hostnames)
    r = client.post("/ajustes/servidores/contabo-1/editar", data={"new_id": "Mal Nombre", "origin_ipv4": "", "private_address": ""},
                    follow_redirects=False)
    assert "error=" in r.headers["location"]


def test_cross_origin_post_rejected(client):
    r = client.post("/ajustes/notificaciones/telegram_token", data={"value": "x" * 12},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_delete_domain_requires_name(client):
    r = client.post("/dominios/example.net/eliminar", data={"confirm": "no"}, follow_redirects=False)
    assert "error=" in r.headers["location"]
    client.post("/dominios/example.net/eliminar", data={"confirm": "example.net", "dns_action": "none"})
    assert client.get("/dominios/example.net").status_code == 404


def test_delete_restores_cloudflare_first(client):
    from app.signals.dnscheck import Resolution
    state = client.app.state.mc
    state.store.upsert_server("vps-1", "192.0.2.10", None)
    state.reload()
    state.resolutions = {"example.com": Resolution("example.com", ("92.223.1.1",), "cl-x.gcorecdn.com.", "gcore"),
                         "www.example.com": Resolution("www.example.com", ("104.16.0.1",), None, "cloudflare")}
    state.store.set_cloudflare_record("example.com", "rec-1", "ip", None)
    state.reload()
    r = client.post("/dominios/example.com/eliminar", data={"confirm": "example.com", "dns_action": "cloudflare"},
                    follow_redirects=False)
    assert "ok=" in r.headers["location"] and "simulados" in r.headers["location"]
    ev = state.events.list(limit=1)[0]
    assert ev.dns_diff == [["example.com", "CNAME → Gcore", "Cloudflare proxied"]]  # solo cambia el que no estaba en CF


def test_delete_aborts_when_restore_impossible(client):
    from app.signals.dnscheck import Resolution
    state = client.app.state.mc
    state.store.set_cloudflare_record("www.example.com", "rec-2", "cname", None)  # CNAME sin destino conocido
    state.reload()
    state.resolutions = {"www.example.com": Resolution("www.example.com", ("92.223.1.1",), "cl-x.gcorecdn.com.", "gcore")}
    r = client.post("/dominios/example.com/eliminar", data={"confirm": "example.com", "dns_action": "cloudflare"},
                    follow_redirects=False)
    assert "error=" in r.headers["location"]
    assert "example.com" in state.inventory.domains  # no se elimina si no se puede dejar bien


def test_delete_cannot_keep_gcore_and_delete_resource(client):
    r = client.post("/dominios/example.com/eliminar", data={"confirm": "example.com", "dns_action": "gcore", "delete_gcore": "1"},
                    follow_redirects=False)
    assert "error=" in r.headers["location"]


def test_notification_channel_saves_all_fields_and_keeps_empty_ones(client):
    secrets = client.app.state.mc.secrets
    client.post("/ajustes/notificaciones/canal/telegram", data={"telegram_token": "bot-token-123456", "telegram_chat_id": "-1001234"})
    assert secrets.get("telegram_token") == "bot-token-123456"
    assert secrets.get("telegram_chat_id") == "-1001234"
    # reemplazar solo el token: el chat id no se toca
    client.post("/ajustes/notificaciones/canal/telegram", data={"telegram_token": "bot-token-NEW999", "telegram_chat_id": ""})
    assert secrets.get("telegram_token") == "bot-token-NEW999"
    assert secrets.get("telegram_chat_id") == "-1001234"
    r = client.post("/ajustes/notificaciones/canal/telegram", data={"telegram_token": "", "telegram_chat_id": ""}, follow_redirects=False)
    assert "error=" in r.headers["location"]
    # eliminar desde el mismo formulario (formaction) borra solo ese campo
    client.post("/ajustes/notificaciones/telegram_chat_id/eliminar")
    assert secrets.get("telegram_chat_id") is None and secrets.get("telegram_token") == "bot-token-NEW999"


def test_cloudflare_sync_detects_tunnel_and_never_stores_origin_ip(client, monkeypatch):
    import asyncio
    import sqlite3

    from app.main import refresh_cloudflare
    from app.providers import cloudflare as cfmod

    async def fake_records(token, zone_id):
        return [
            {"id": "rec-apex", "name": "example.com", "type": "CNAME", "proxied": True,
             "origin_kind": "tunnel", "tunnel_target": "abc.cfargotunnel.com", "cname_target": None},
            {"id": "rec-www", "name": "www.example.com", "type": "A", "proxied": True,
             "origin_kind": "ip", "tunnel_target": None, "cname_target": None},
        ]

    monkeypatch.setattr(cfmod, "list_web_records", fake_records)
    state = client.app.state.mc
    cred = state.creds.add("cloudflare", "Cuenta", "token-xyz-123456")
    state.store.assign_zone("example.com", "zone-1", cred)
    state.reload()
    asyncio.run(refresh_cloudflare(state))
    hosts = {h.name: h for h in state.inventory.domains["example.com"].hostnames}
    assert hosts["example.com"].origin_kind == "tunnel" and hosts["example.com"].cloudflare_record_id == "rec-apex"
    assert hosts["www.example.com"].origin_kind == "ip" and hosts["www.example.com"].tunnel_target is None
    page = client.get("/dominios/example.com").text
    assert "Cloudflare Tunnel" in page


def test_list_web_records_parsing(monkeypatch):
    import asyncio

    import httpx

    from app.providers import cloudflare as cfmod

    payload = {"success": True, "result_info": {"total_pages": 1}, "result": [
        {"id": "1", "name": "example.com", "type": "CNAME", "proxied": True, "content": "abc.cfargotunnel.com"},
        {"id": "2", "name": "www.example.com", "type": "A", "proxied": True, "content": "192.0.2.10"},
        {"id": "3", "name": "example.com", "type": "MX", "content": "mail.example.com"},
        {"id": "4", "name": "abc._domainkey.mail.example.com", "type": "CNAME", "proxied": False, "content": "dkim.example.net"},
    ]}
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=payload))
    real_client = httpx.AsyncClient
    monkeypatch.setattr(cfmod.httpx, "AsyncClient", lambda **kw: real_client(transport=transport, **kw))
    recs = asyncio.run(cfmod.list_web_records("t", "z"))
    assert [r["origin_kind"] for r in recs] == ["tunnel", "ip"]
    assert all("192.0.2.10" not in str(r) for r in recs)  # la IP de origen no se conserva


def test_no_duplicate_ids_on_any_page(client):
    import re
    from collections import Counter
    pages = ["/", "/dominios", "/dominios/example.com", "/historial", "/ajustes/cuentas",
             "/ajustes/notificaciones", "/ajustes/servidores", "/ajustes/operacion"]
    for url in pages:
        ids = Counter(re.findall(r'\sid="([^"]+)"', client.get(url).text))
        dups = [i for i, n in ids.items() if n > 1]
        assert not dups, f"{url}: ids duplicados {dups}"


def test_return_to_cloudflare_restores_original_records(client):
    from app.signals.dnscheck import Resolution
    state = client.app.state.mc
    state.store.upsert_server("vps-1", "192.0.2.10", None)
    state.store.set_cloudflare_record("example.com", "rec-1", "ip", None)
    state.store.set_cloudflare_record("www.example.com", "rec-2", "cname", None, "example.com")
    state.reload()
    gc = Resolution("x", ("92.223.1.1",), "cl-x.gcorecdn.com.", "gcore")
    state.resolutions = {"example.com": gc, "www.example.com": gc}
    page = client.get("/dominios/example.com").text
    assert "Volver a Cloudflare…" in page
    r = client.post("/dominios/example.com/volver", data={"confirm": "example.com"}, follow_redirects=False)
    assert "simulada" in r.headers["location"]
    ev = state.events.list(limit=1)[0]
    assert ev.transition == "GCORE → CF"
    assert ev.dns_diff == [["example.com", "CNAME → Gcore", "Cloudflare proxied"],
                           ["www.example.com", "CNAME → Gcore", "Cloudflare proxied"]]


def test_excluded_hostname_is_never_switched(client):
    state = client.app.state.mc
    client.post("/dominios/example.com/hostnames", data={
        "server:example.com": "vps-1", "gcore:example.com": "cl-x.gcorecdn.com", "failover:example.com": "1",
        "server:www.example.com": "vps-1", "gcore:www.example.com": "",  # sin destino y sin marcar
    })
    hosts = {h.name: h for h in state.inventory.domains["example.com"].hostnames}
    assert hosts["example.com"].failover and not hosts["www.example.com"].failover
    page = client.get("/dominios/example.com").text
    assert "sin cambios (excluido)" in page  # el www excluido no bloquea el cambio
    client.post("/dominios/example.com/cambiar", data={"target": "gcore", "confirm": "example.com"})
    ev = state.events.list(limit=1)[0]
    assert [row[0] for row in ev.dns_diff] == ["example.com"]


def test_remove_single_hostname_keeps_dns_and_last_one_protected(client):
    state = client.app.state.mc
    r = client.post("/dominios/example.com/hostnames/www.example.com/quitar", follow_redirects=False)
    assert "ok=" in r.headers["location"]
    assert [h.name for h in state.inventory.domains["example.com"].hostnames] == ["example.com"]
    r = client.post("/dominios/example.com/hostnames/example.com/quitar", follow_redirects=False)
    assert "error=" in r.headers["location"]
    assert client.post("/dominios/example.com/hostnames/nope.example.com/quitar").status_code == 404


def test_flattened_apex_on_gcore_is_recognised(client):
    from app.main import apply_cf_live
    from app.signals.dnscheck import Resolution
    state = client.app.state.mc
    state.resolutions = {"example.com": Resolution("example.com", ("93.123.17.254",), None, "other")}
    apply_cf_live(state)
    assert state.resolutions["example.com"].provider == "other"  # sin datos de la API no se adivina
    state.cf_live["example.com"] = {"to_backup": True, "target": "cl-x.gcorecdn.com"}
    apply_cf_live(state)
    assert state.resolutions["example.com"].provider == "gcore"
    page = client.get("/dominios/example.com").text
    assert "CNAME → cl-x.gcorecdn.com" in page


def test_new_credential_help_has_one_text_per_provider(client):
    page = client.get("/ajustes/cuentas").text
    assert page.count('data-provider-help="cloudflare"') == 2 and page.count('data-provider-help="gcore" hidden') == 2
    assert 'data-placeholder="Gcore principal"' in page


def test_static_assets_carry_a_content_version(client):
    import re
    page = client.get("/").text
    urls = re.findall(r'(?:src|href)="(/static/[^"]+)"', page)
    assert urls and all("?v=" in u for u in urls)
    assert client.get(next(u for u in urls if "panel.js" in u)).status_code == 200


def test_footer_signs_as_a_pepebits_product(client, anon):
    from datetime import UTC, datetime
    for page in (client.get("/").text, anon.get("/login").text):
        assert f"© {datetime.now(UTC).year} Multi-CDN" in page
        assert page.count('href="https://pepebits.com"') == 1 and "un producto de" in page
        assert 'class="pb-wordmark" viewBox="0 0 302 75" width="100" height="25" aria-hidden="true"' in page
        assert "PEPEBITS (Ir a pepebits.com)" in page


def test_server_form_saves_and_validates_private_address(client):
    r = client.post("/ajustes/servidores", data={"server_id": "vps-2", "origin_ipv4": "", "private_address": "10.0.0.2"},
                    follow_redirects=True)
    assert "Servidor vps-2 guardado" in r.text and 'value="10.0.0.2"' in r.text and "Dirección privada (opcional)" in r.text
    r = client.post("/ajustes/servidores", data={"server_id": "vps-3", "origin_ipv4": "", "private_address": "no vale/esto"},
                    follow_redirects=True)
    assert "dirección privada no válida" in r.text and "vps-3" not in client.app.state.mc.inventory.servers


def test_access_indicator_reflects_how_the_panel_was_reached(client):
    page = client.get("/", headers={"host": "localhost:8765"}).text
    assert "Acceso por túnel SSH o local" in page and "dot--ok" in page
    page = client.get("/", headers={"host": "vps-1.tailnet.ts.net"}).text
    assert "Acceso por Tailscale" in page
    page = client.get("/", headers={"host": "panel.example.com"}).text
    assert "Acceso por panel.example.com: comprueba que no está expuesto" in page and "dot--warn" in page
