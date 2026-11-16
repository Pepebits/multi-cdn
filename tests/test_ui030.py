"""0.3.0 panel additions: open problems, error reporting status and the domain timeline."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app import alerts, charts, error_reporting, stats
from app.origin_health import OriginHealth
from app.problems import open_problems
from app.signals.calendar import Match
from app.signals.dnscheck import Resolution
from app.signals.hayahora import parse_feed

NOW = datetime(2026, 11, 15, 15, 30, tzinfo=UTC)
TO_GCORE = [["example.com", "Cloudflare proxied", "CNAME → cl-a.gcorecdn.com · TTL 60"]]
TO_CF = [["example.com", "CNAME → Gcore", "Cloudflare proxied"]]


def ev(at, diff, actor="auto", simulated=False):
    return SimpleNamespace(ts=at, kind="switch", dns_diff=diff, actor=actor, simulated=simulated)


def feed(changes, ip="192.0.2.10"):
    fmt = "%Y-%m-%d %H:%M:%SZ"
    return parse_feed({"lastUpdate": NOW.strftime(fmt), "data": [
        {"ip": ip, "isp": "Movistar", "description": "Cloudflare",
         "stateChanges": [{"timestamp": t.strftime(fmt), "state": b} for t, b in changes]}]})


# ---------------------------------------------------------------- timeline

def test_window_is_whole_utc_days():
    start, end = stats.timeline_window(7, NOW)
    assert end == datetime(2026, 11, 16, tzinfo=UTC) and start == datetime(2026, 11, 9, tzinfo=UTC)


def test_period_started_before_the_window_and_one_still_open():
    start, end = stats.timeline_window(7, NOW)
    events = [ev(start - timedelta(hours=10), TO_GCORE),                      # before the window, automatic
              ev(start + timedelta(hours=5), TO_CF, actor="admin"),           # manual return
              ev(start + timedelta(days=2), TO_GCORE, simulated=True),         # dry run: not counted
              ev(NOW - timedelta(hours=3), TO_GCORE, actor="admin")]           # still on Gcore
    tl = stats.domain_timeline(events, ["example.com"], {"example.com": "gcore"}, start, end, NOW)
    gcore = [p for p in tl["periods"] if p.kind == "gcore"]
    assert len(gcore) == 2
    first, last = gcore
    assert (first.start, first.end, first.start_before) == (start, start + timedelta(hours=5), True)
    assert (first.actor, first.ended_by) == ("auto", "admin")
    assert (last.start, last.end, last.start_before) == (NOW - timedelta(hours=3), None, False)
    assert last.actor == "admin" and last.ended_by is None
    assert last.duration(NOW) == timedelta(hours=3)
    # The bar ends now: nothing is drawn in the future part of today.
    assert tl["segments"][-1].end == NOW and [s.kind for s in tl["segments"]] == ["gcore", "cloudflare", "gcore"]


def test_on_gcore_the_whole_window_without_switch_events():
    start, end = stats.timeline_window(7, NOW)
    tl = stats.domain_timeline([], ["example.com"], {"example.com": "gcore"}, start, end, NOW)
    (p,) = tl["periods"]
    assert (p.kind, p.start, p.end, p.start_before, p.actor) == ("gcore", start, None, True, None)


def test_blocks_and_matches_are_cut_to_the_window():
    start, end = stats.timeline_window(7, NOW)
    f = feed([(start - timedelta(hours=2), True), (start + timedelta(hours=1), False),
              (NOW - timedelta(hours=1), True)])
    matches = [Match("LaLiga", "Home", "Away", NOW + timedelta(hours=4), "scheduled"),
               Match("LaLiga", "Old", "Match", start - timedelta(days=2), "finished")]
    tl = stats.domain_timeline([], ["example.com"], {"example.com": "cloudflare"}, start, end, NOW,
                               feed=f, ips=["192.0.2.10"], matches=matches)
    blocked = [p for p in tl["periods"] if p.kind == "blocked"]
    assert [(p.start, p.end, p.start_before) for p in blocked] == [
        (start, start + timedelta(hours=1), True), (NOW - timedelta(hours=1), None, False)]
    (m,) = [p for p in tl["periods"] if p.kind == "match"]
    assert m.start == NOW + timedelta(hours=4) and m.detail == "LaLiga: Home – Away"
    assert not [p for p in tl["periods"] if p.kind == "gcore"]


def test_lanes_geometry_in_hours():
    start, end = stats.timeline_window(7, NOW)
    events = [ev(NOW - timedelta(hours=3), TO_GCORE)]
    tl = stats.domain_timeline(events, ["example.com"], {"example.com": "gcore"}, start, end, NOW,
                               matches=[Match("LaLiga", "Home", "Away", NOW + timedelta(hours=4), "scheduled")])
    lanes = charts.domain_lanes(tl)
    assert lanes["hours"] == 168 and len(lanes["days"]) == 7 and lanes["ticks"][0] == 24
    assert lanes["now"] == 6 * 24 + 15.5
    assert [(s["kind"], s["x"], s["w"]) for s in lanes["served"]] == [("cloudflare", 0, 159.5 - 3), ("gcore", 156.5, 3)]
    assert lanes["matches"][0]["x"] == 6 * 24 + 19.5


def test_domain_page_shows_the_timeline(client):
    state = client.app.state.mc
    state.events.add(actor="admin", kind="switch", domain="example.com", transition="CF → GCORE", summary="x",
                     dns_diff=[[h, "Cloudflare proxied", "CNAME → cl-a.gcorecdn.com · TTL 60"]
                               for h in ("example.com", "www.example.com")])
    page = client.get("/dominios/example.com").text
    assert 'aria-labelledby="linea-tiempo"' in page and "Últimos 7 días" in page
    assert "c-seg--gcore" in page and 'preserveAspectRatio="none"' in page
    assert "Lista de periodos" in page and "sigue en Gcore" in page and "manual, de admin" in page
    assert "style=" not in page.split('aria-labelledby="linea-tiempo"')[1].split("</section>")[0]


# ---------------------------------------------------------------- open problems

def test_open_problems_merges_every_source(client, monkeypatch):
    monkeypatch.setattr("app.firewall_status.read", lambda: None)
    state = client.app.state.mc
    assert open_problems(state, NOW) == []
    cred = state.creds.add("cloudflare", "Main account", "cf-token-for-tests")
    alerts.problem(state, "feed_down", "down", now=NOW - timedelta(hours=2))
    alerts.problem(state, f"cf_read:{cred}", "x", now=NOW - timedelta(hours=1))
    alerts.problem(state, "auto_not_ready:example.net", "x", now=NOW - timedelta(hours=5))
    alerts.problem(state, "cf_read:999", "grace", after=timedelta(minutes=8), now=NOW)  # not alerted yet
    state.origin_health["vps-1"] = OriginHealth("vps-1", "example.com", False, "HTTP 502", NOW, fails=3, alerted=True)
    state.resolutions["www.example.com"] = Resolution("www.example.com", ("192.0.2.1",), None, "origin")
    state.exposure_alerted.add("www.example.com")
    state.events.set_value("firewall_problem", "no list has been applied yet")

    items = open_problems(state, NOW)
    by_key = {p.key: p for p in items}
    assert set(by_key) == {"feed_down", f"cf_read:{cred}", "auto_not_ready:example.net", "origin:vps-1",
                           "exposed:www.example.com", "firewall"}
    assert by_key[f"cf_read:{cred}"].href == f"/ajustes/cuentas#cuenta-{cred}"
    assert "Main account" in by_key[f"cf_read:{cred}"].text
    assert by_key["auto_not_ready:example.net"].href == "/dominios/example.net#config"
    assert by_key["auto_not_ready:example.net"].severity == "warn"
    assert by_key["exposed:www.example.com"].href == "/dominios/example.com"
    assert by_key["origin:vps-1"].since == NOW - timedelta(minutes=4)
    assert by_key["feed_down"].since == NOW - timedelta(hours=2)
    # errors first, oldest first; the warning last
    assert items[-1].key == "auto_not_ready:example.net"
    assert [p.key for p in items[:3]] == ["feed_down", f"cf_read:{cred}", "origin:vps-1"]
    assert "192.0.2.1" not in " ".join(p.text for p in items)


def test_stale_feed_and_failed_heartbeat_are_warnings(client, monkeypatch):
    monkeypatch.setattr("app.firewall_status.read", lambda: None)
    state = client.app.state.mc
    state.feed = feed([])
    state.feed_stale_alerted = True
    from app.heartbeat import Beat
    state.last_beat = Beat(NOW, True, "HTTP 500", "")
    items = open_problems(state, NOW)
    assert [(p.key, p.severity) for p in items] == [("feed_stale", "warn"), ("heartbeat", "warn")]
    assert items[1].href == "/ajustes/notificaciones"


def test_overview_strip_hidden_when_nothing_is_open_and_shown_otherwise(client):
    page = client.get("/").text
    assert 'aria-labelledby="problemas"' not in page
    alerts.problem(client.app.state.mc, "feed_down", "down", now=datetime.now(UTC) - timedelta(minutes=20))
    page = client.get("/").text
    assert 'aria-labelledby="problemas"' in page and "1 problema abierto" in page
    assert 'href="/ajustes/cambio#feed"' in page and "Ir a Ajustes → Cambio automático" in page
    assert 'class="rel"' in page and 'data-abs' in page
    client.cookies.set("lang", "en")
    assert "1 open problem" in client.get("/").text


# ---------------------------------------------------------------- error reporting

DSN = "https://f0e1d2c3b4a5968778695a4b3c2d1e0f@o4242.ingest.example.com/1234567"


def test_status_shows_only_scheme_and_host(monkeypatch):
    monkeypatch.setitem(error_reporting._live, "dsn", None)
    assert error_reporting.status()["enabled"] is False
    monkeypatch.setitem(error_reporting._live, "dsn", DSN)
    monkeypatch.setenv("MULTICDN_SENTRY_ENVIRONMENT", "staging")
    st = error_reporting.status()
    assert st == {"enabled": True, "configured": True, "installed": True, "server": "https://o4242.ingest.example.com",
                  "environment": "staging", "restart_note": False}
    monkeypatch.setitem(error_reporting._live, "dsn", "https://key:secret@errors.example.com:8443/9")
    assert error_reporting.status()["server"] == "https://errors.example.com:8443"
    monkeypatch.setitem(error_reporting._live, "dsn", "not a url")
    assert error_reporting.status()["server"] is None


def test_system_page_never_shows_the_key(client, monkeypatch):
    monkeypatch.setitem(error_reporting._live, "dsn", None)
    page = client.get("/ajustes/sistema").text
    assert 'aria-labelledby="errores"' in page and "MULTICDN_SENTRY_DSN" in page and "Desactivado" in page
    assert 'formaction="/ajustes/sistema/errores/probar" formnovalidate disabled' in page
    monkeypatch.setitem(error_reporting._live, "dsn", DSN)
    client.app.state.mc.secrets.set("sentry_dsn", DSN)
    page = client.get("/ajustes/sistema").text
    assert "https://o4242.ingest.example.com" in page and "production" in page
    assert "f0e1d2c3b4a5968778695a4b3c2d1e0f" not in page and "1234567" not in page
    assert "se eliminan antes de salir del servidor" in page
