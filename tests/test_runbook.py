"""Cambio de CDN desde la terminal (runbook sin panel)."""

import asyncio

import pytest

from app import runbook
from app.engine import failover
from app.signals.dnscheck import Resolution


@pytest.fixture
def setup(client, monkeypatch):
    state = client.app.state.mc
    cf = state.creds.add("cloudflare", "CF", "cf-token-123456")
    state.store.set_credentials("example.com", cf, None)
    state.store.set_gcore("example.com", 33, 22, "2027-01-01T00:00:00+00:00", "cl-test.gcorecdn.com",
                          ["example.com", "www.example.com"])

    async def observe(st):
        st.resolutions = {h: Resolution(h, ("188.114.96.5",), None, "cloudflare") for h in ("example.com", "www.example.com")}
    monkeypatch.setattr(runbook, "_observe", observe)
    return state


def run(coro):
    return asyncio.run(coro)


def test_switch_asks_for_confirmation_and_records_it(setup, monkeypatch):
    async def ok(state, name):
        return None
    monkeypatch.setattr(failover, "check_backup", ok)
    out = []
    assert run(runbook.switch("example.com", "gcore", out=out.append, ask=lambda _: "otra.com")) == 1
    assert "Cancelado" in out[-1]
    out.clear()
    assert run(runbook.switch("example.com", "gcore", out=out.append, ask=lambda _: "example.com")) == 0
    assert "Simulado" in out[-1] and "pausa 1 h" in out[-1]
    events = setup.events.list(limit=5)
    assert events[0].actor == "cli" and events[0].transition == "CF → GCORE" and events[0].simulated
    from app.engine.failover import EngineStore
    assert EngineStore(setup.store.conn).get("example.com").hold_until is not None


def test_failed_backup_check_stops_unless_forced(setup, monkeypatch):
    async def broken(state, name):
        return "example.com: HTTP 503 vía Gcore"
    monkeypatch.setattr(failover, "check_backup", broken)
    out = []
    assert run(runbook.switch("example.com", "gcore", assume_yes=True, out=out.append)) == 1
    assert any("--forzar" in line for line in out)
    assert run(runbook.switch("example.com", "gcore", assume_yes=True, force=True, out=out.append)) == 0


def test_unknown_domain_and_status(setup):
    out = []
    assert run(runbook.switch("nope.com", "gcore", out=out.append)) == 2
    out.clear()
    assert run(runbook.status(out=out.append)) == 0
    assert out[0].startswith("Modo: SIMULACIÓN") and any(line.strip().startswith("example.com") for line in out)
