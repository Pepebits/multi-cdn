"""The origin IP never reaches the history, alerts, URLs or the panel (ADR-003)."""

import asyncio
import json
from datetime import timedelta

import pytest

from app import error_reporting, gcore_setup
from app.db import EventStore
from app.engine import failover
from app.providers import gcore
from tests.test_failover import T0, feed

ORIGIN, ORIGIN6 = "192.0.2.10", "2001:db8::10"


@pytest.fixture
def origins(monkeypatch):
    monkeypatch.setattr(error_reporting, "_origin_ips", lambda: {ORIGIN, ORIGIN6})


def test_exact_match_only(origins):
    text = f"connect to {ORIGIN}:443 failed; edge 192.0.2.100 and 192.0.2.1 fine; {ORIGIN}."
    assert error_reporting.scrub_origin(text) == \
        "connect to [origin IP]:443 failed; edge 192.0.2.100 and 192.0.2.1 fine; [origin IP]."


@pytest.mark.parametrize("form", ["2001:db8::10", "2001:0db8:0000:0000:0000:0000:0000:0010", "2001:DB8:0:0::10",
                                  "[2001:db8::10]:443"])
def test_ipv6_in_any_notation(origins, form):
    out = error_reporting.scrub_origin(f"source {form} refused")
    assert "[origin IP]" in out and "db8" not in out.lower()


def test_other_texts_unchanged(origins):
    for text in ("token rejected (HTTP 403)", "Gcore edge 198.51.100.7 answered 502", "2001:db8::11 is fine",
                 "version 1.2.3.4.5", "", None):
        assert error_reporting.scrub_origin(text) == text


def test_events_add_scrubs_before_storing_and_alerting(origins, tmp_path):
    events = EventStore(tmp_path / "e.db")
    seen = []
    events.listeners.append(seen.append)
    events.add(actor="auto", kind="error", summary=f"Gcore rejected source {ORIGIN}:443",
               dns_diff=[["example.com", ORIGIN, "cl-test.gcorecdn.com"]], signals=[f"origin {ORIGIN6}"])
    ev = events.list(limit=1)[0]
    assert ORIGIN not in ev.summary and ev.dns_diff == [["example.com", "[origin IP]", "cl-test.gcorecdn.com"]]
    assert ev.signals == ["origin [origin IP]"]
    assert ORIGIN not in json.dumps(seen) and "2001:db8::10" not in json.dumps(seen)


def test_redirect_location_has_no_origin_ip(origins):
    from app.main import _back
    r = _back("/ajustes/servidores", error=f"Server: cannot reach {ORIGIN}", anchor="x")
    assert ORIGIN not in r.headers["location"] and "origin+IP" in r.headers["location"]


def test_engine_last_error_is_scrubbed(make_client, monkeypatch):
    client = make_client(ORIGIN_VPS1_IPV4=ORIGIN)
    state = client.app.state.mc
    cf_id = state.creds.add("cloudflare", "CF", "cf-token-123456")
    state.store.set_credentials("example.com", cf_id, None)
    state.store.set_gcore("example.com", 33, 22, (T0 + timedelta(days=80)).isoformat(), "cl-test.gcorecdn.com",
                          ["example.com", "www.example.com"])
    state.reload()
    from app.signals.dnscheck import Resolution
    state.resolutions = {h: Resolution(h, ("188.114.96.5",), None, "cloudflare") for h in ("example.com", "www.example.com")}
    state.dns_checked_at = state.cf_sync_at = T0

    async def broken(state_, name):
        return f"origin {ORIGIN} refused the connection"
    monkeypatch.setattr(failover, "check_backup", broken)
    state.feed = feed(True)
    asyncio.run(failover.evaluate(state, now=T0))
    assert "[origin IP]" in state.engine.get("example.com").last_error
    assert ORIGIN not in state.engine.get("example.com").last_error
    assert all(ORIGIN not in e.summary for e in state.events.list(limit=20))


def test_prepare_domain_error_is_scrubbed(make_client, monkeypatch):
    client = make_client(ORIGIN_VPS1_IPV4=ORIGIN)
    state = client.app.state.mc

    async def account_cname(token): return "cl-test.gcorecdn.com"
    async def ensure_origin_group(token, name, ip):
        raise RuntimeError(f'Gcore rejected the origin creation (HTTP 400): {{"source": "{ip}:443"}}')
    monkeypatch.setattr(gcore, "account_cname", account_cname)
    monkeypatch.setattr(gcore, "ensure_origin_group", ensure_origin_group)
    cf_id = state.creds.add("cloudflare", "CF", "cf-token-123456")
    gc_id = state.creds.add("gcore", "GC", "gc-token-123456")
    state.store.set_credentials("example.com", cf_id, gc_id)
    state.reload()
    job = gcore_setup.Job("example.com")
    asyncio.run(gcore_setup.prepare_domain(state, "example.com", job))
    assert not job.ok and "[origin IP]" in job.lines[-1][1]
    assert all(ORIGIN not in text for _level, text in job.lines)
    assert all(ORIGIN not in e.summary for e in state.events.list(limit=20))
    assert ORIGIN not in client.get("/historial").text


def test_scrub_history_is_idempotent(origins, tmp_path):
    events = EventStore(tmp_path / "h.db")
    events.scrubber = None  # rows written before 0.3.0
    events.add(actor="auto", kind="error", summary=f"failed: {ORIGIN}", dns_diff=[["example.com", ORIGIN, "x"]],
               signals=[f"source {ORIGIN6}"])
    events.add(actor="auto", kind="alert", summary="nothing to hide 198.51.100.7")
    events.conn.execute("CREATE TABLE failover_state (domain TEXT PRIMARY KEY, last_error TEXT)")
    events.conn.execute("INSERT INTO failover_state VALUES ('example.com', ?), ('example.net', NULL)",
                        (f"switch failed: {ORIGIN}",))
    events.scrubber = error_reporting.scrub_origin
    assert events.scrub_history() == 2
    stored = json.dumps([[e.summary, e.dns_diff, e.signals] for e in events.list()])
    assert ORIGIN not in stored and "2001:db8::10" not in stored and "198.51.100.7" in stored
    assert events.conn.execute("SELECT last_error FROM failover_state WHERE domain='example.com'").fetchone()[0] \
        == "switch failed: [origin IP]"
    assert events.scrub_history() == 0
