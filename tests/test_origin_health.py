import asyncio
from datetime import UTC, datetime

from app import origin_health


def prober(results):
    seen = []

    async def fake(ip, hostname, headers):
        seen.append((ip, hostname, "X-Origin-Auth" in headers))
        return results.pop(0)
    return fake, seen


def alerts(state):
    return [e.summary for e in state.events.list(limit=20) if e.kind == "alert"]


def test_alerts_after_two_failures_and_on_recovery(make_client):
    client = make_client(ORIGIN_VPS1_IPV4="192.0.2.10")
    state = client.app.state.mc
    fake, seen = prober([(True, "HTTP 200"), (False, "no conecta (TimeoutError)"),
                         (False, "no conecta (TimeoutError)"), (False, "HTTP 502"), (True, "HTTP 200")])
    for _ in range(5):
        asyncio.run(origin_health.check(state, datetime.now(UTC), prober=fake))
        if len(seen) == 3:
            assert alerts(state) == ["El origen vps-1 no responde (example.com: no conecta (TimeoutError)); el problema no es el CDN"]
    assert seen[0] == ("192.0.2.10", "example.com", True)
    assert len(alerts(state)) == 2 and alerts(state)[0] == "El origen vps-1 responde de nuevo (example.com: HTTP 200)"
    assert "Responde" in client.get("/").text


def test_switch_failure_mentions_a_down_origin(make_client):
    client = make_client(ORIGIN_VPS1_IPV4="192.0.2.10")
    state = client.app.state.mc
    fake, _ = prober([(False, "HTTP 502")])
    asyncio.run(origin_health.check(state, datetime.now(UTC), prober=fake))
    assert "tampoco responde directamente: HTTP 502" in origin_health.down_note(state, "example.com")
    assert "No responde" in client.get("/").text
