import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx

from app import certs, event_codes, gcore_setup
from app.notifier import Notifier, format_text, should_notify
from app.providers import gcore


def ev(kind, summary="x", **kw):
    return {"actor": "auto", "kind": kind, "summary": summary, "domain": "example.com", "transition": None,
            "dns_diff": [], "signals": [], "simulated": False} | kw


def test_rules_for_what_gets_notified():
    assert should_notify(ev("switch"))
    assert not should_notify(ev("switch", simulated=True))
    assert should_notify(ev("alert")) and should_notify(ev("error"))
    assert should_notify(ev("auth", "Acceso bloqueado por intentos fallidos", code=event_codes.LOGIN_LOCKED))
    assert not should_notify(ev("auth", "Inicio de sesión desde 1.2.3.4"))
    assert should_notify(ev("config", "Certificado renovado en Gcore, válido hasta 01/01/2027", code=event_codes.CERT_RENEWED))
    assert not should_notify(ev("config", "Hostnames actualizados"))


def test_rules_use_the_event_code_not_its_text():
    """Reescribir un texto del catálogo no puede cambiar qué se avisa."""
    assert should_notify(ev("auth", "cualquier texto", code=event_codes.LOGIN_LOCKED))
    assert not should_notify(ev("auth", "Acceso bloqueado (texto antiguo, sin código)"))
    assert should_notify(ev("config", "otro texto", code=event_codes.GCORE_PREPARED))


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
    from app.tasks import check_block_transitions
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
    from app.tasks import restore_block_state
    state.blocked_domains.clear()
    restore_block_state(state)
    check_block_transitions(state)
    assert len([e for e in state.events.list(limit=10) if e.kind == "alert"]) == 1
    # el fin solo se avisa tras BLOCK_END_GRACE seguido sin bloqueo; si vuelve antes, no hay avisos
    from app.tasks import BLOCK_END_GRACE
    t = datetime.now(UTC)
    state.feed = feed(False)
    check_block_transitions(state, now=t)
    state.feed = feed(True)
    check_block_transitions(state, now=t + timedelta(minutes=1))
    state.feed = feed(False)
    check_block_transitions(state, now=t + timedelta(minutes=2))
    check_block_transitions(state, now=t + timedelta(minutes=2) + BLOCK_END_GRACE - timedelta(seconds=1))
    assert len([e for e in state.events.list(limit=10) if e.kind == "alert"]) == 1
    check_block_transitions(state, now=t + timedelta(minutes=2) + BLOCK_END_GRACE)
    assert "Fin del bloqueo" in state.events.list(limit=1)[0].summary
    assert len([e for e in state.events.list(limit=10) if e.kind == "alert"]) == 2


def test_flapping_block_alerts_are_capped_per_domain():
    """Si el estado va y viene, tras BLOCK_BURST avisos se manda uno de silencio y nada más en 1 h."""
    from app import notifier
    sent = []
    n = Notifier(FakeSecrets(telegram_token="t", telegram_chat_id="42"))

    async def fake_send(event):
        sent.append(event["summary"])
    n.send = fake_send

    async def flap():
        for i in range(10):
            # textos distintos cada vez para que no los agrupe la deduplicación por texto
            code = event_codes.BLOCK_START if i % 2 else event_codes.BLOCK_END
            n(ev("alert", f"aviso {i}", code=code))
        n(ev("alert", "fin", domain="otro.example", code=event_codes.BLOCK_END))  # otro dominio: su propio tope
        n(ev("alert", "origen expuesto"))  # otros avisos no cuentan para el tope
        await asyncio.sleep(0.05)

    asyncio.run(flap())
    assert len(sent) == notifier.BLOCK_BURST + 3
    assert "silencian 1 h" in sent[notifier.BLOCK_BURST]


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
    assert any(e.code == event_codes.CERT_RENEWED for e in state.events.list(limit=5))
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
    assert should_notify(ev("config", "Preparado en Gcore: recurso 1, certificado hasta 01/01/2027",
                            code=event_codes.GCORE_PREPARED))


def test_restart_recovers_block_state_by_code(client):
    """El estado de bloqueo se recupera por el código, aunque el texto cambie o el aviso sea antiguo."""
    from app.tasks import restore_block_state
    state = client.app.state.mc
    ev_add = state.events.add
    ev_add(actor="auto", kind="alert", domain="example.com", summary="texto reescrito", code=event_codes.BLOCK_START)
    for i in range(250):  # más de 200 eventos después: antes se perdía
        ev_add(actor="auto", kind="verify", domain="example.com", summary=f"comprobación {i}")
    state.blocked_domains.clear()
    restore_block_state(state)
    assert "example.com" in state.blocked_domains
    ev_add(actor="auto", kind="alert", domain="example.com", summary="otro texto", code=event_codes.BLOCK_END)
    state.blocked_domains.clear()
    restore_block_state(state)
    assert "example.com" not in state.blocked_domains


def test_restart_recovers_legacy_block_alerts_without_code(client):
    from app.tasks import restore_block_state
    state = client.app.state.mc
    state.events.add(actor="auto", kind="alert", domain="example.com",
                     summary="IPs de Cloudflare bloqueadas en 1 operadora; ya se sirve por Gcore")
    state.blocked_domains.clear()
    restore_block_state(state)
    assert "example.com" in state.blocked_domains


def test_old_events_table_gets_the_code_column(tmp_path):
    import sqlite3
    from app.db import EventStore
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, domain TEXT,"
                 " actor TEXT NOT NULL, kind TEXT NOT NULL, summary TEXT NOT NULL, transition TEXT, dns_diff TEXT,"
                 " signals TEXT, simulated INTEGER NOT NULL DEFAULT 0)")
    conn.execute("INSERT INTO events (ts, actor, kind, summary) VALUES ('2026-11-01T00:00:00+00:00', 'auto', 'alert', 'viejo')")
    conn.commit()
    conn.close()
    store = EventStore(path)
    assert store.list()[0].code is None
    store.add(actor="auto", kind="alert", summary="nuevo", code=event_codes.BLOCK_END)
    assert store.list()[0].code == event_codes.BLOCK_END
