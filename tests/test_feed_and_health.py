"""Block feed (conditional GET, adaptive interval, down/recovered alerts), Cloudflare read
alerts, heartbeat health and /healthz (v0.3.0)."""

import asyncio
import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app import alerts, heartbeat
from app import main as app_main
from app import tasks
from app.db import EventStore
from app.signals import hayahora
from app.signals.calendar import Calendar, Match
from app.signals.dnscheck import Resolution

T0 = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
CF_IP = "203.0.113.5"


def payload(now=T0, blocked=False, extra_blocked=0):
    ts = now.strftime("%Y-%m-%d %H:%M:%SZ")
    data = [{"ip": CF_IP, "isp": "Movistar", "description": "Cloudflare",
             "stateChanges": [{"timestamp": ts, "state": blocked}]}]
    for i in range(extra_blocked):
        data += [{"ip": f"198.51.100.{i}", "isp": isp, "description": "Cloudflare",
                  "stateChanges": [{"timestamp": ts, "state": True}]} for isp in ("Movistar", "Vodafone", "Orange")]
    return {"lastUpdate": ts, "data": data}


def feed_server(responses):
    """MockTransport that answers from the list (dict = 200 with ETag, int = that status,
    Exception = raised) and records the If-None-Match headers it receives."""
    seen = []

    def handler(request):
        seen.append(request.headers.get("If-None-Match"))
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, int):
            return httpx.Response(item)
        return httpx.Response(200, json=item, headers={"ETag": f'"v{len(seen)}"'})
    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), seen


def summaries(state, kind="alert"):
    return [e.summary for e in state.events.list(limit=50) if e.kind == kind]


# ---------------------------------------------------------------- 5. feed

def test_fetch_feed_sends_etag_and_handles_304():
    client, seen = feed_server([payload(), 304])
    snap, etag = asyncio.run(hayahora.fetch_feed(client))
    assert snap is not None and snap.monitored(CF_IP) and etag == '"v1"' and seen == [None]
    snap, etag2 = asyncio.run(hayahora.fetch_feed(client, etag))
    assert snap is None and etag2 == '"v1"' and seen[-1] == '"v1"'


def test_refresh_feed_on_304_keeps_data_and_refreshes_fetched_at(client):
    state = client.app.state.mc
    state.client, seen = feed_server([payload(), 304])
    asyncio.run(tasks.refresh_feed(state))
    first = state.feed
    first.fetched_at = datetime.now(UTC) - timedelta(minutes=5)
    asyncio.run(tasks.refresh_feed(state))
    assert seen == [None, '"v1"'] and state.feed is first
    assert datetime.now(UTC) - state.feed.fetched_at < timedelta(seconds=30) and state.feed_error is None


@pytest.fixture
def quiet(client):
    """Nothing going on: fresh feed without blocks, calendar with no match near, all on Cloudflare."""
    state = client.app.state.mc
    state.feed = hayahora.parse_feed(payload(T0), fetched_at=T0)
    state.calendar = Calendar([Match("LaLiga", "Home", "Away", T0 + timedelta(days=2), "STATUS_SCHEDULED")], fetched_at=T0)
    state.resolutions = {"example.com": Resolution("example.com", (CF_IP,), None, "cloudflare")}
    return state


def test_feed_interval_idle_and_setting(quiet, client):
    assert tasks.feed_interval(quiet, T0) == 300
    r = client.post("/ajustes/operacion/feed", data={"seconds": "120"}, follow_redirects=False)
    assert "ok=" in r.headers["location"] and quiet.events.get_setting("feed_interval") == 120
    assert tasks.feed_interval(quiet, T0) == 120
    for bad in ("100", "600", "x"):
        r = client.post("/ajustes/operacion/feed", data={"seconds": bad}, follow_redirects=False)
        assert "error=" in r.headers["location"]
    assert quiet.events.get_setting("feed_interval") == 120
    assert summaries(quiet, "config") == ["Feed de bloqueos leído cada 120 s cuando no pasa nada"]
    page = client.get("/ajustes/operacion").text
    assert "Consulta del feed de bloqueos" in page and 'name="seconds"' in page
    assert '<option value="120" selected>' in page


def test_feed_interval_fast_conditions(quiet):
    lead_max = max(tasks.failover.match_lead(quiet, p) for p in tasks.failover.PRIORITIES)
    cases = []
    quiet.feed_error = "ConnectError: x"
    cases.append(tasks.feed_interval(quiet, T0))
    quiet.feed_error = None
    cases.append(tasks.feed_interval(quiet, T0 + timedelta(minutes=11)))  # stale feed
    quiet.calendar = None
    cases.append(tasks.feed_interval(quiet, T0))
    quiet.calendar = Calendar([Match("LaLiga", "Home", "Away", T0 + lead_max - timedelta(minutes=1), "STATUS_SCHEDULED")],
                              fetched_at=T0)
    cases.append(tasks.feed_interval(quiet, T0))  # match window (longest lead)
    quiet.calendar = Calendar([], fetched_at=T0 - timedelta(days=2))
    cases.append(tasks.feed_interval(quiet, T0))  # expired calendar
    quiet.calendar = Calendar([], fetched_at=T0)
    assert tasks.feed_interval(quiet, T0) == 300
    quiet.resolutions = {"example.com": Resolution("example.com", ("198.51.100.200",), "cl-x.gcorecdn.com.", "gcore")}
    cases.append(tasks.feed_interval(quiet, T0))
    quiet.resolutions = {}
    es = quiet.engine.get("example.com")
    es.sim_backup = True
    quiet.engine.save(es)
    cases.append(tasks.feed_interval(quiet, T0))
    es.sim_backup = None
    quiet.engine.save(es)
    quiet.blocked_domains.add("example.com")
    cases.append(tasks.feed_interval(quiet, T0))
    quiet.blocked_domains.clear()
    assert tasks.feed_interval(quiet, T0) == 300
    quiet.feed = hayahora.parse_feed(payload(T0, extra_blocked=tasks.FEED_FAST_MASS), fetched_at=T0)
    cases.append(tasks.feed_interval(quiet, T0))
    assert cases == [90] * len(cases)


def test_feed_interval_logs_only_mode_changes(quiet, caplog):
    caplog.set_level("INFO", logger="multicdn")
    for _ in range(3):
        tasks.feed_interval(quiet, T0)
    quiet.calendar = None
    tasks.feed_interval(quiet, T0)
    tasks.feed_interval(quiet, T0, quiet=True)
    lines = [r.getMessage() for r in caplog.records if "feed polling" in r.getMessage()]
    assert lines == ["feed polling: every 300 s (idle)", "feed polling: every 90 s (no match calendar)"]


def test_loop_accepts_a_callable_interval(monkeypatch):
    waits, runs = [], []

    async def fake_sleep(seconds):
        waits.append(seconds)
        if len(waits) == 2:
            raise asyncio.CancelledError

    async def task():
        runs.append(1)
    monkeypatch.setattr(tasks.asyncio, "sleep", fake_sleep)
    values = iter([300, 90])
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(tasks._loop(lambda: next(values), task))
    assert waits == [300, 90] and len(runs) == 2


# ---------------------------------------------------------------- 2. feed down

def test_feed_down_alerts_once_after_second_failure_and_recovers(client, tmp_path):
    state = client.app.state.mc
    down = httpx.ConnectError("refused")
    state.client, _ = feed_server([down, down, down, payload(datetime.now(UTC))])
    asyncio.run(tasks.refresh_feed(state, now=T0))
    assert state.feed_error and not summaries(state)  # an isolated failure is silent
    # The open problem lives in the database: a restart in between keeps it.
    state.events = EventStore(os.environ["MULTICDN_DB"])
    asyncio.run(tasks.refresh_feed(state, now=T0 + timedelta(seconds=95)))
    asyncio.run(tasks.refresh_feed(state, now=T0 + timedelta(seconds=190)))
    assert summaries(state) == ["Feed de bloqueos no disponible (ConnectError)"]
    asyncio.run(tasks.refresh_feed(state, now=T0 + timedelta(minutes=7)))
    assert state.feed_error is None
    assert summaries(state)[0] == "El feed de bloqueos vuelve a estar disponible (caído 7 min)"
    assert not alerts.active(state, "feed_down")


# ---------------------------------------------------------------- 1. Cloudflare reads

@pytest.fixture
def cf_state(make_client, monkeypatch):
    c = make_client(ORIGIN_VPS1_IPV4="192.0.2.10")
    state = c.app.state.mc
    cred = state.creds.add("cloudflare", "Main", "cf-token-123456")
    state.store.set_credentials("example.com", cred, None)
    state.reload()
    result = {"fail": True}

    async def records(token, zone_id):
        if result["fail"]:
            raise RuntimeError("HTTP 403: origin 192.0.2.10 rejected")
        return []
    monkeypatch.setattr(tasks.cf, "list_web_records", records)
    state.result = result
    return state


def test_cloudflare_read_failure_alerts_once_and_recovers(cf_state):
    asyncio.run(tasks.refresh_cloudflare(cf_state, alert=False))
    assert cf_state.cf_sync_errors["example.com"] == "HTTP 403: origin [origin IP] rejected"
    tasks.check_cloudflare_read(cf_state, T0)
    tasks.check_cloudflare_read(cf_state, T0 + timedelta(minutes=5))
    assert not summaries(cf_state)
    tasks.check_cloudflare_read(cf_state, T0 + timedelta(minutes=9))
    tasks.check_cloudflare_read(cf_state, T0 + timedelta(minutes=14))
    alerts_ = summaries(cf_state)
    assert len(alerts_) == 1 and "«Main»" in alerts_[0] and "1 dominio(s)" in alerts_[0]
    assert "192.0.2.10" not in alerts_[0]
    cf_state.result["fail"] = False
    asyncio.run(tasks.refresh_cloudflare(cf_state, alert=False))
    assert "example.com" in cf_state.cf_ok_at and "example.com" not in cf_state.cf_sync_errors
    tasks.check_cloudflare_read(cf_state, T0 + timedelta(minutes=20))
    assert summaries(cf_state)[0] == "Cloudflare vuelve a poder leerse con la credencial «Main» (falló durante 20 min)"


def test_cloudflare_read_without_alerts_from_the_cli(cf_state):
    for _ in range(2):
        asyncio.run(tasks.refresh_cloudflare(cf_state, alert=False))
    assert not alerts.active(cf_state, "cf_read:") and not summaries(cf_state)
    asyncio.run(tasks.refresh_cloudflare(cf_state))  # the panel's loop does alert (from 8 min)
    assert alerts.active(cf_state, "cf_read:")


def test_health_fails_after_15_min_without_a_good_cloudflare_read(cf_state):
    cf_state.dns_checked_at = cf_state.cf_sync_at = T0
    cf_state.cf_ok_at["example.com"] = T0 - timedelta(minutes=10)
    assert heartbeat.health(cf_state, T0)[0]
    cf_state.cf_ok_at["example.com"] = T0 - timedelta(minutes=16)
    ok, messages = heartbeat.health(cf_state, T0)
    assert not ok and messages[0] == "la lectura de Cloudflare lleva más de 15 min fallando"
    assert heartbeat.liveness(cf_state, T0) == []  # the loop itself is alive


# ---------------------------------------------------------------- 4. /healthz

def test_healthz_offline_and_grace_answer_200(client, monkeypatch):
    state = client.app.state.mc
    state.dns_checked_at = None
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["ok"] and r.json()["stale"] == []
    monkeypatch.setenv("MULTICDN_OFFLINE", "0")
    state.started_at = datetime.now(UTC) - timedelta(minutes=1)
    assert client.get("/healthz").status_code == 200


def test_healthz_503_when_dns_loop_stopped_not_for_cloudflare_errors(cf_state, monkeypatch):
    monkeypatch.setenv("MULTICDN_OFFLINE", "0")
    from fastapi.testclient import TestClient
    tc = TestClient(app_main.app)
    now = datetime.now(UTC)
    cf_state.started_at = now - timedelta(minutes=30)
    cf_state.dns_checked_at = now - timedelta(minutes=10)
    cf_state.cf_sync_at = now
    r = tc.get("/healthz")
    assert r.status_code == 503 and r.json() == {"ok": False, "stale": ["dns"], "feed": False,
                                                 "dns_checked_at": r.json()["dns_checked_at"]}
    cf_state.dns_checked_at = now
    cf_state.cf_sync_errors["example.com"] = "HTTP 403: token rejected"
    cf_state.cf_ok_at["example.com"] = now - timedelta(hours=1)
    r = tc.get("/healthz")
    assert r.status_code == 200 and r.json()["ok"]
    assert "403" not in r.text and "token" not in r.text
