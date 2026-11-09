import asyncio
from datetime import UTC, datetime, timedelta

import httpx

from app import heartbeat

NOW = datetime(2026, 11, 9, 12, tzinfo=UTC)


def capture(state):
    calls = []

    def handler(request):
        calls.append((str(request.url), request.content.decode()))
        return httpx.Response(200)
    state.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return calls


def test_pings_success_while_tasks_run_and_fail_when_they_stop(client):
    state = client.app.state.mc
    calls = capture(state)
    assert asyncio.run(heartbeat.beat(state, NOW)) is None  # sin URL: nada
    state.secrets.set("heartbeat_url", "https://hc-ping.com/abc")
    state.dns_checked_at = NOW - timedelta(minutes=1)
    b = asyncio.run(heartbeat.beat(state, NOW))
    assert b.ok and calls[-1][0] == "https://hc-ping.com/abc" and "modo simulación" in calls[-1][1]
    state.dns_checked_at = NOW - timedelta(minutes=20)
    b = asyncio.run(heartbeat.beat(state, NOW))
    assert not b.ok and calls[-1][0] == "https://hc-ping.com/abc/fail"
    assert "comprobación del DNS lleva más de 5 min parada" in calls[-1][1]


def test_cloudflare_sync_counts_only_when_a_domain_needs_it(client):
    state = client.app.state.mc
    state.dns_checked_at = NOW
    assert heartbeat.health(state, NOW)[0]
    cf = state.creds.add("cloudflare", "CF", "cf-token-123456")
    state.store.set_credentials("example.com", cf, None)
    state.reload()
    ok, messages = heartbeat.health(state, NOW)
    assert not ok and "lectura de Cloudflare" in messages[0]


def test_settings_validate_and_send(client):
    r = client.post("/ajustes/notificaciones/latido", data={"heartbeat_url": "http://inseguro"}, follow_redirects=True)
    assert "Pega la URL de ping completa" in r.text
    state = client.app.state.mc
    capture(state)
    state.dns_checked_at = datetime.now(UTC)
    r = client.post("/ajustes/notificaciones/latido", data={"heartbeat_url": "https://hc-ping.com/abc"}, follow_redirects=True)
    assert "Aviso enviado: todo en orden" in r.text and "Funcionando" in r.text
    assert state.secrets.get("heartbeat_url") == "https://hc-ping.com/abc"
