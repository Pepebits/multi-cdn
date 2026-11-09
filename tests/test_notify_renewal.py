import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx

from app import certs, gcore_setup
from app.notifier import Notifier, format_text, should_notify
from app.providers import gcore


def ev(kind, summary="x", **kw):
    return {"actor": "auto", "kind": kind, "summary": summary, "domain": "example.com", "transition": None,
            "dns_diff": [], "signals": [], "simulated": False} | kw


def test_rules_for_what_gets_notified():
    assert should_notify(ev("switch"))
    assert not should_notify(ev("switch", simulated=True))
    assert should_notify(ev("alert")) and should_notify(ev("error"))
    assert should_notify(ev("auth", "Acceso bloqueado por intentos fallidos"))
    assert not should_notify(ev("auth", "Inicio de sesión desde 1.2.3.4"))
    assert should_notify(ev("config", "Certificado renovado en Gcore, válido hasta 01/01/2027"))
    assert not should_notify(ev("config", "Hostnames actualizados"))


def test_format_includes_dns_diff():
    subject, body = format_text(ev("switch", "Cambio a Gcore", transition="CF → GCORE",
                                   dns_diff=[["example.com", "Cloudflare proxied", "CNAME → cl-x.gcorecdn.com · TTL 60"]]))
    assert "example.com" in subject and "CF → GCORE" in body and "cl-x.gcorecdn.com" in body


class FakeSecrets(dict):
    def get(self, k, default=None):
        return super().get(k, default)


def test_telegram_send_escapes_html_and_dedups():
    sent = []

    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    n = Notifier(FakeSecrets(telegram_token="t", telegram_chat_id="42"),
                 client_factory=lambda **kw: httpx.AsyncClient(transport=transport, **kw))
    result = asyncio.run(n.send(ev("alert", "Origen <expuesto> & roto")))
    assert result == {"telegram": "ok"}
    assert sent[0]["chat_id"] == "42" and "&lt;expuesto&gt; &amp;" in sent[0]["text"]

    async def twice():
        n(ev("error", "mismo fallo"))
        n(ev("error", "mismo fallo"))  # repetido en <10 min: se agrupa
        await asyncio.sleep(0.05)

    sent.clear()
    asyncio.run(twice())
    assert len(sent) == 1


def test_event_store_calls_listeners(tmp_path):
    from app.db import EventStore
    seen = []
    store = EventStore(tmp_path / "e.db")
    store.listeners.append(seen.append)
    store.listeners.append(lambda e: 1 / 0)  # un listener roto no impide registrar
    store.add(actor="auto", kind="alert", summary="hola", domain="example.com")
    assert seen[0]["summary"] == "hola" and store.stats()["count"] == 1


def test_block_start_and_end_alerts(client):
    from app.main import check_block_transitions
    from app.signals.dnscheck import Resolution
    from app.signals.hayahora import parse_feed
    state = client.app.state.mc
    state.resolutions = {"example.com": Resolution("example.com", ("188.114.96.5",), None, "cloudflare"),
                         "www.example.com": Resolution("www.example.com", ("188.114.96.5",), None, "cloudflare")}

    def feed(blocked):
        return parse_feed({"lastUpdate": "2026-11-08 20:00:00Z", "data": [
            {"ip": "188.114.96.5", "isp": "Movistar", "description": "Cloudflare",
             "stateChanges": [{"timestamp": "2026-11-08 20:00:00Z", "state": blocked}]}]})

    state.feed = feed(True)
    check_block_transitions(state)
    assert not [e for e in state.events.list(limit=10) if e.kind == "alert"]  # aún sin DNS comprobado: no avisa
    from datetime import UTC, datetime
    state.dns_checked_at = datetime.now(UTC)
    check_block_transitions(state)
    check_block_transitions(state)  # sin repetir mientras dure
    alerts = [e for e in state.events.list(limit=10) if e.kind == "alert"]
    assert len(alerts) == 1 and "bloqueadas en 1 operadora" in alerts[0].summary
    assert "sigue en Cloudflare" in alerts[0].summary
    # un reinicio no repite el aviso: el estado se recupera del historial
    from app.main import restore_block_state
    state.blocked_domains.clear()
    restore_block_state(state)
    check_block_transitions(state)
    assert len([e for e in state.events.list(limit=10) if e.kind == "alert"]) == 1
    state.feed = feed(False)
    check_block_transitions(state)
    assert "Fin del bloqueo" in state.events.list(limit=1)[0].summary


def test_due_for_renewal():
    from app.config import Domain
    soon = (datetime.now(UTC) + timedelta(days=10)).isoformat()
    later = (datetime.now(UTC) + timedelta(days=80)).isoformat()
    assert gcore_setup.due_for_renewal(Domain(hostnames=[], gcore_resource_id=1, cert_not_after=soon))
    assert not gcore_setup.due_for_renewal(Domain(hostnames=[], gcore_resource_id=1, cert_not_after=later))
    assert not gcore_setup.due_for_renewal(Domain(hostnames=[], cert_not_after=soon))


def test_renewal_uploads_new_cert_and_deletes_old(make_client, monkeypatch):
    client = make_client(ORIGIN_VPS1_IPV4="192.0.2.10")
    state = client.app.state.mc
    calls = {"deleted": []}

    async def account_cname(token): return "cl-test.gcorecdn.com"
    async def ensure_origin_group(token, name, ip): return 11
    async def upload_certificate(token, name, fc, pk): calls["uploaded"] = name; return 99
    async def ensure_resource(token, payload): calls["ssl"] = payload["sslData"]; return 33
    async def probe_edge(edge, host): return True, "ok"
    async def delete_certificate(token, ssl_id): calls["deleted"].append(ssl_id)
    async def issue(cert_name, hostnames, cf_token, log):
        return certs.IssuedCert("FC", "KEY", datetime.now(UTC) + timedelta(days=90), hostnames)
    for mod, fn in ((gcore, account_cname), (gcore, ensure_origin_group), (gcore, upload_certificate),
                    (gcore, ensure_resource), (gcore, probe_edge), (gcore, delete_certificate), (certs, issue)):
        monkeypatch.setattr(mod, fn.__name__, fn)

    cf_id = state.creds.add("cloudflare", "CF", "cf-token-123456")
    gc_id = state.creds.add("gcore", "GC", "gc-token-123456")
    state.store.set_credentials("example.com", cf_id, gc_id)
    soon = (datetime.now(UTC) + timedelta(days=5)).isoformat()
    state.store.set_gcore("example.com", 33, 22, soon, "cl-test.gcorecdn.com", ["example.com", "www.example.com"])
    state.reload()
    renewed = asyncio.run(gcore_setup.renew_due_certificates(state))
    assert renewed == ["example.com"]
    assert calls["ssl"] == 99 and calls["deleted"] == [22]
    assert state.inventory.domains["example.com"].gcore_ssl_id == 99
    assert any(e.summary.startswith("Certificado renovado") for e in state.events.list(limit=5))
    assert asyncio.run(gcore_setup.renew_due_certificates(state)) == []  # ya no toca


def test_cert_expiry_alerts_once_per_level(client):
    state = client.app.state.mc
    now = datetime.now(UTC)

    def set_cert(days):
        state.store.set_gcore("example.com", 33, 22, (now + timedelta(days=days, hours=1)).isoformat(), "cl-test.gcorecdn.com",
                              ["example.com", "www.example.com"])
        state.reload()
    set_cert(40)
    assert gcore_setup.cert_expiry_alerts(state, now) == []
    set_cert(20)
    assert gcore_setup.cert_expiry_alerts(state, now) == ["example.com"]
    assert gcore_setup.cert_expiry_alerts(state, now) == []  # mismo nivel: no repite
    assert "en 20 días" in state.events.list(limit=1)[0].summary
    assert gcore_setup.cert_expiry_alerts(state, now + timedelta(days=14)) == ["example.com"]  # nivel 7
    assert gcore_setup.cert_expiry_alerts(state, now + timedelta(days=25)) == ["example.com"]  # caducado
    assert "caducó el" in state.events.list(limit=1)[0].summary
    set_cert(90)  # renovado: certificado nuevo
    assert gcore_setup.cert_expiry_alerts(state, now) == []


def test_updating_an_existing_gcore_resource_is_not_announced():
    assert not should_notify(ev("config", "Actualizado en Gcore: recurso 1, certificado hasta 01/01/2027"))
    assert should_notify(ev("config", "Preparado en Gcore: recurso 1, certificado hasta 01/01/2027"))
