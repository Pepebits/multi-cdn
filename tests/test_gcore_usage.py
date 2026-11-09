"""Consumo de Gcore: avisos por umbral (una vez por mes) y su presentación en el panel."""

import asyncio
from datetime import UTC, datetime

from app import gcore_usage
from app.providers import gcore

NOW = datetime(2026, 11, 20, 12, tzinfo=UTC)


def setup(state, monkeypatch, total, resources=2):
    async def traffic(token, start, end):
        assert start == datetime(2026, 11, 1, tzinfo=UTC)
        return {"total_bytes": total, "sent_bytes": total // 2, "upstream_bytes": total // 2, "by_resource": {33: total}}

    async def account_limits(token):
        return {"resources": resources, "max_resources": 30}
    monkeypatch.setattr(gcore, "traffic", traffic)
    monkeypatch.setattr(gcore, "account_limits", account_limits)


def alerts(state):
    return [e.summary for e in state.events.list(limit=20) if e.kind == "alert"]


def test_alerts_once_per_threshold_and_month(client, monkeypatch):
    state = client.app.state.mc
    state.creds.add("gcore", "Gcore", "gc-token-123456")
    setup(state, monkeypatch, 500 * 1000**3)
    asyncio.run(gcore_usage.refresh_usage(state, NOW))
    assert not alerts(state)
    setup(state, monkeypatch, 720 * 1000**3)
    asyncio.run(gcore_usage.refresh_usage(state, NOW))
    asyncio.run(gcore_usage.refresh_usage(state, NOW))
    assert len(alerts(state)) == 1 and "al 72 %" in alerts(state)[0]
    setup(state, monkeypatch, 950 * 1000**3)
    asyncio.run(gcore_usage.refresh_usage(state, NOW))
    assert len(alerts(state)) == 2 and "950,0 GB de 1000 GB" in alerts(state)[0]
    # mes nuevo: vuelve a avisar al pasar el umbral
    setup(state, monkeypatch, 950 * 1000**3)
    monkeypatch.setattr(gcore_usage, "month_start", lambda now: datetime(2026, 11, 1, tzinfo=UTC))
    asyncio.run(gcore_usage.refresh_usage(state, datetime(2026, 12, 2, tzinfo=UTC)))
    assert len(alerts(state)) == 3


def test_resource_limit_alert_and_panel(client, monkeypatch):
    state = client.app.state.mc
    cid = state.creds.add("gcore", "Gcore", "gc-token-123456")
    setup(state, monkeypatch, 6_900_000, resources=28)
    asyncio.run(gcore_usage.refresh_usage(state, NOW))
    assert any("28 de 30 recursos" in a for a in alerts(state))
    page = client.get("/ajustes/cuentas").text
    assert "6,9 MB de 1000 GB" in page and "recursos CDN 28 de 30" in page
    assert "28/30 recursos" in client.get("/").text
    r = client.post("/ajustes/operacion/cuota", data={"gcore_quota_gb": "500"}, follow_redirects=True)
    assert "Cuota guardada: 500 GB" in r.text and state.events.get_setting("gcore_quota_gb") == 500
    assert cid in state.gcore_usage


def test_human_sizes():
    assert gcore_usage.human(6_868_856) == "6,9 MB" and gcore_usage.human(1_200 * 1000**3) == "1,2 TB"
