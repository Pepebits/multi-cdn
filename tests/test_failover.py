"""Conmutación automática: decisiones, salvaguardas y pausas (en modo simulación)."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from app.engine import failover
from app.signals.dnscheck import Resolution
from app.signals.hayahora import parse_feed

CF_IP = "188.114.96.5"
T0 = datetime(2026, 11, 8, 20, 0, tzinfo=UTC)


def feed(blocked: bool, now: datetime = T0, extra_blocked: int = 0):
    data = [{"ip": CF_IP, "isp": "Movistar", "description": "Cloudflare",
             "stateChanges": [{"timestamp": now.strftime("%Y-%m-%d %H:%M:%SZ"), "state": blocked}]}]
    for i in range(extra_blocked):  # otras IPs de Cloudflare bloqueadas (bloqueo masivo)
        data += [{"ip": f"104.16.0.{i}", "isp": isp, "description": "Cloudflare",
                  "stateChanges": [{"timestamp": now.strftime("%Y-%m-%d %H:%M:%SZ"), "state": True}]}
                 for isp in ("Movistar", "Vodafone", "Orange")]
    return parse_feed({"lastUpdate": now.strftime("%Y-%m-%d %H:%M:%SZ"), "data": data})


@pytest.fixture
def st(client, monkeypatch):
    """example.com preparado en Gcore, con credencial de Cloudflare y resolviendo a Cloudflare."""
    state = client.app.state.mc
    cf_id = state.creds.add("cloudflare", "CF", "cf-token-123456")
    state.store.set_credentials("example.com", cf_id, None)
    state.store.set_gcore("example.com", 33, 22, (T0 + timedelta(days=80)).isoformat(), "cl-test.gcorecdn.com",
                          ["example.com", "www.example.com"])
    state.store.upsert_domain("example.net", policy="manual", priority="low")
    state.reload()
    state.resolutions = {h: Resolution(h, (CF_IP,), None, "cloudflare") for h in ("example.com", "www.example.com")}
    state.dns_checked_at = state.cf_sync_at = T0
    checks = []

    async def ok(state_, name):
        checks.append(name)
        return None
    monkeypatch.setattr(failover, "check_backup", ok)
    state.checks = checks
    return state


def run(state, now):
    asyncio.run(failover.evaluate(state, now=now))


def switches(state):
    return [e for e in state.events.list(limit=50) if e.kind == "switch"]


def test_switches_on_block_and_returns_after_quiet_period(st):
    st.feed = feed(True)
    run(st, T0)
    run(st, T0 + timedelta(minutes=2))  # sin repetir
    sw = switches(st)
    assert len(sw) == 1 and sw[0].transition == "CF → GCORE" and sw[0].simulated and sw[0].actor == "auto"
    assert "bloqueadas en 1 operadora" in sw[0].summary and st.checks == ["example.com"]
    assert st.engine.get("example.com").sim_backup

    st.feed = feed(False, T0 + timedelta(minutes=20))
    run(st, T0 + timedelta(minutes=20))
    st.feed = feed(False, T0 + timedelta(minutes=60))
    run(st, T0 + timedelta(minutes=60))  # crítico: 45 min sin bloqueos aún no
    assert len(switches(st)) == 1
    st.feed = feed(False, T0 + timedelta(minutes=66))
    run(st, T0 + timedelta(minutes=66))
    sw = switches(st)
    assert len(sw) == 2 and sw[0].transition == "GCORE → CF" and "sin bloqueos desde las 20:20" in sw[0].summary
    assert not st.engine.get("example.com").sim_backup


def test_preventive_switches_on_mass_block(st):
    st.feed = feed(False, extra_blocked=failover.MASS_BLOCK)
    run(st, T0)
    assert "bloqueo masivo" in switches(st)[0].summary


def test_stale_feed_or_disabled_engine_does_nothing(st):
    st.feed = feed(True, T0 - timedelta(hours=1))
    run(st, T0)
    st.feed = feed(True)
    st.events.set_setting("auto_switch", 0)
    run(st, T0)
    assert not switches(st)


def test_failed_backup_check_keeps_cloudflare_and_alerts_once(st, monkeypatch):
    async def broken(state_, name):
        return "example.com: HTTP 502 vía Gcore"
    monkeypatch.setattr(failover, "check_backup", broken)
    st.feed = feed(True)
    run(st, T0)
    run(st, T0 + timedelta(minutes=2))
    errors = [e for e in st.events.list(limit=20) if e.kind == "error"]
    assert not switches(st) and len(errors) == 1 and "Sigue en Cloudflare" in errors[0].summary


def test_flapping_pauses_the_domain(st):
    t = T0
    for i in range(failover.FLAP_MAX):
        st.feed = feed(i % 2 == 0, t)
        es = st.engine.get("example.com")
        es.clear_since = t - timedelta(hours=1)  # la vuelta ya toca
        st.engine.save(es)
        run(st, t)
        t += timedelta(minutes=16)
    assert len(switches(st)) == failover.FLAP_MAX
    st.feed = feed(True, t)
    run(st, t)
    assert st.engine.get("example.com").paused and len(switches(st)) == failover.FLAP_MAX
    assert "pausada" in st.events.list(limit=1)[0].summary


def test_manual_change_holds_automation(st, client):
    r = client.post("/dominios/example.com/cambiar", data={"target": "gcore", "confirm": "example.com"}, follow_redirects=False)
    assert "pausa" in r.headers["location"]
    st.feed = feed(False)
    now = datetime.now(UTC)
    st.feed = feed(False, now)
    es = st.engine.get("example.com")
    es.clear_since = now - timedelta(hours=2)
    st.engine.save(es)
    run(st, now)  # en pausa: no vuelve aunque toque
    assert switches(st)[0].actor != "auto"
    assert "pausa" in failover.describe(st, "example.com")["text"]
    client.post("/dominios/example.com/automatico/reanudar")
    run(st, now + timedelta(seconds=1))
    assert switches(st)[0].actor == "auto" and switches(st)[0].transition == "GCORE → CF"


def test_remembered_ips_track_the_block_while_on_gcore(st):
    """Estando en Gcore el DNS no muestra las IPs de Cloudflare: se usan las recordadas."""
    from app.main import check_block_transitions
    st.engine.remember_ips("example.com", [CF_IP])
    st.resolutions = {h: Resolution(h, ("5.188.126.61",), "cl-test.gcorecdn.com.", "gcore")
                      for h in ("example.com", "www.example.com")}
    st.feed = feed(True, datetime.now(UTC))
    view = next(v for v in st.views() if v.name == "example.com")
    assert view.status == "gcore" and view.blocked_count == 1
    check_block_transitions(st)
    assert "ya se sirve por Gcore" in st.events.list(limit=1)[0].summary


def test_decide_uses_real_dns_outside_simulation(st):
    st.feed = feed(False)
    view = next(v for v in st.views() if v.name == "example.com")
    for h in view.hosts:
        h.provider = "gcore"
    es = failover.DomainState("example.com", clear_since=T0 - timedelta(hours=1))
    d = failover.decide(view, st.inventory.domains["example.com"], es, dry_run=False, mass=0, now=T0)
    assert d.action == "return"
    es.clear_since = None
    assert failover.decide(view, st.inventory.domains["example.com"], es, dry_run=False, mass=0, now=T0).action == "none"


def test_simulation_starts_from_real_dns(st):
    """En simulación, un dominio que ya está en Gcore de verdad no se «cambia» otra vez."""
    st.resolutions = {h: Resolution(h, ("5.188.126.61",), "cl-test.gcorecdn.com.", "gcore")
                      for h in ("example.com", "www.example.com")}
    st.engine.remember_ips("example.com", [CF_IP])
    st.feed = feed(True)
    run(st, T0)
    assert not switches(st)


def test_old_engine_table_is_migrated(tmp_path):
    import sqlite3
    conn = sqlite3.connect(tmp_path / "x.db")
    conn.execute("CREATE TABLE failover_state (domain TEXT PRIMARY KEY, cf_ips TEXT NOT NULL DEFAULT '[]',"
                 " sim_backup INTEGER NOT NULL DEFAULT 0, hold_until TEXT, paused INTEGER NOT NULL DEFAULT 0,"
                 " clear_since TEXT, switches TEXT NOT NULL DEFAULT '[]', last_error TEXT)")
    store = failover.EngineStore(conn)
    store.save(failover.DomainState("example.com"))
    assert failover.EngineStore(conn).get("example.com").sim_backup is None


def test_cli_origin_secrets_fingerprints_caddy_file_and_rotation(tmp_path, monkeypatch, capsys):
    import re
    from app import cli
    monkeypatch.setenv("MULTICDN_DB", str(tmp_path / "c.db"))
    monkeypatch.delenv("MULTICDN_SECRET_KEY", raising=False)

    def values(text):
        return re.findall(r"header X-Origin-Auth (\S+)", text)
    assert cli.main(["secretos-origen"]) == 0
    out = capsys.readouterr().out
    assert "huella" in out and "no se muestran" in out
    cli.main(["secretos-origen", "--caddy"])
    first = values(capsys.readouterr().out)
    assert len(first) == 2 and first[0] != first[1]
    cli.main(["secretos-origen", "--caddy"])
    assert values(capsys.readouterr().out) == first  # estable
    cli.main(["rotar-secreto-origen", "gcore"])
    capsys.readouterr()
    cli.main(["secretos-origen", "--caddy"])
    rotating = values(capsys.readouterr().out)
    assert len(rotating) == 3 and first[1] in rotating  # el anterior sigue aceptado
    cli.main(["retirar-secreto-anterior", "gcore"])
    capsys.readouterr()
    cli.main(["secretos-origen", "--caddy"])
    final = values(capsys.readouterr().out)
    assert len(final) == 2 and first[1] not in final and first[0] in final

def test_panel_shows_engine_state_and_global_switch(st, client):
    page = client.get("/dominios/example.com").text
    assert "Cambio automático:" in page and "Activo: pasa a Gcore" in page and "bloqueo masivo" in page
    assert "Política manual" in client.get("/dominios/example.net").text
    r = client.post("/ajustes/operacion/automatico", data={"enabled": "0"}, follow_redirects=True)
    assert "Desactivado" in r.text and not failover.auto_enabled(st)
    assert "desactivado en Ajustes" in client.get("/dominios/example.com").text


def calendar_at(kickoff):
    from app.signals.calendar import Calendar, Match
    return Calendar([Match("LaLiga", "Celta Vigo", "Levante", kickoff, "STATUS_SCHEDULED")], fetched_at=kickoff - timedelta(hours=2))


def test_preventive_switches_before_a_match_and_waits_after_it(st):
    kickoff = T0 + timedelta(hours=1)
    st.calendar = calendar_at(kickoff)
    st.feed = feed(False, kickoff - timedelta(minutes=50))
    run(st, kickoff - timedelta(minutes=50))  # aún fuera de la ventana (45 min en críticos)
    assert not switches(st)
    st.feed = feed(False, kickoff - timedelta(minutes=44))
    run(st, kickoff - timedelta(minutes=44))
    assert "partido de LaLiga (Celta Vigo – Levante, 21:00 UTC)" in switches(st)[0].summary
    end = kickoff + timedelta(hours=2, minutes=30)
    st.feed = feed(False, end - timedelta(minutes=1))
    run(st, end - timedelta(minutes=1))
    assert st.engine.get("example.com").clear_since is None  # el partido sigue contando
    for minutes in (1, 30, 47):
        st.feed = feed(False, end + timedelta(minutes=minutes))
        run(st, end + timedelta(minutes=minutes))
    sw = switches(st)
    assert len(sw) == 2 and sw[0].transition == "GCORE → CF"


def test_reactive_ignores_the_calendar(st):
    st.store.upsert_domain("example.com", policy="reactive", priority="critical")
    st.reload()
    st.calendar = calendar_at(T0)
    st.feed = feed(False)
    run(st, T0)
    assert not switches(st)


def test_feed_down_during_a_match_still_switches_but_never_returns(st):
    st.calendar = calendar_at(T0)
    st.feed = None
    run(st, T0)
    assert switches(st)[0].transition == "CF → GCORE"
    st.calendar = None
    es = st.engine.get("example.com")
    es.switches = []
    st.engine.save(es)
    run(st, T0 + timedelta(hours=5))
    assert len(switches(st)) == 1


def test_parse_scoreboard_skips_postponed():
    from app.signals.calendar import parse_scoreboard

    def ev(date, status, home, away):
        return {"date": date, "status": {"type": {"name": status}}, "competitions": [{"competitors": [
            {"homeAway": "home", "team": {"displayName": home}}, {"homeAway": "away", "team": {"displayName": away}}]}]}
    matches = parse_scoreboard({"events": [ev("2026-11-08T17:30Z", "STATUS_SCHEDULED", "Celta Vigo", "Levante"),
                                           ev("2026-11-08T13:00Z", "STATUS_POSTPONED", "Andorra", "Mallorca")]}, "LaLiga")
    assert [m.name for m in matches] == ["Celta Vigo – Levante"] and matches[0].kickoff.hour == 17


def test_maintenance_pauses_automation_until_its_end(st, client):
    r = client.post("/dominios/example.com/automatico/mantenimiento", data={"horas": "6"}, follow_redirects=True)
    assert "en pausa 6 h" in r.text and "en mantenimiento" in r.text
    now = datetime.now(UTC)
    st.feed = feed(True, now)
    run(st, now)
    assert not switches(st)  # en mantenimiento no cambia
    run(st, now + timedelta(hours=7))
    st.feed = feed(True, now + timedelta(hours=7))
    run(st, now + timedelta(hours=7))
    assert switches(st)  # pasado el plazo, vuelve a actuar


def test_maintenance_until_resumed_and_bad_duration(st, client):
    client.post("/dominios/example.com/automatico/mantenimiento", data={"horas": "0"})
    assert failover.describe(st, "example.com")["text"] == "En mantenimiento hasta que lo reanudes"
    st.feed = feed(True, datetime.now(UTC))
    run(st, datetime.now(UTC) + timedelta(days=30))
    assert not switches(st)
    r = client.post("/dominios/example.com/automatico/mantenimiento", data={"horas": "5"}, follow_redirects=True)
    assert "Duración no válida" in r.text
    client.post("/dominios/example.com/automatico/reanudar")
    text = failover.describe(st, "example.com")["text"]
    assert "pausa" not in text and "mantenimiento" not in text  # reanudado (y el motor ya actúa)


def test_engine_table_gets_hold_reason_column(tmp_path):
    import sqlite3
    conn = sqlite3.connect(tmp_path / "y.db")
    conn.execute("CREATE TABLE failover_state (domain TEXT PRIMARY KEY, cf_ips TEXT NOT NULL DEFAULT '[]',"
                 " sim_backup INTEGER, hold_until TEXT, paused INTEGER NOT NULL DEFAULT 0, clear_since TEXT,"
                 " switches TEXT NOT NULL DEFAULT '[]', last_error TEXT)")
    conn.execute("INSERT INTO failover_state (domain, paused) VALUES ('example.com', 1)")
    store = failover.EngineStore(conn)
    assert store.get("example.com").paused and store.get("example.com").hold_reason is None
    store.maintenance("example.com", None)
    assert failover.EngineStore(conn).get("example.com").hold_reason == "mantenimiento"


def test_change_indicator_propagating_then_done(st):
    gcore = {h: Resolution(h, ("5.188.126.61",), "cl-test.gcorecdn.com.", "gcore") for h in ("example.com", "www.example.com")}
    st.resolutions = gcore
    st.events.add(actor="auto", kind="switch", domain="example.com", transition="GCORE → CF", summary="vuelta",
                  dns_diff=[["example.com", "CNAME → Gcore", "Cloudflare proxied"]])
    c = failover.change_indicator(st, "example.com")
    assert c["kind"] == "propagating" and c["text"] == "Cambiando a Cloudflare… propagando DNS"
    st.resolutions = {h: Resolution(h, (CF_IP,), None, "cloudflare") for h in gcore}
    assert failover.change_indicator(st, "example.com") is None  # propagado: nada que mostrar


def test_change_indicator_pending_return_and_preventive_match(st):
    now = datetime.now(UTC)
    st.resolutions = {h: Resolution(h, ("5.188.126.61",), "cl-test.gcorecdn.com.", "gcore") for h in ("example.com", "www.example.com")}
    es = st.engine.get("example.com")
    es.clear_since = now - timedelta(minutes=10)
    st.engine.save(es)
    c = failover.change_indicator(st, "example.com", now)
    assert c["kind"] == "pending" and c["text"] == f"Vuelta a Cloudflare hacia las {(es.clear_since + timedelta(minutes=45)):%H:%M} UTC"
    st.engine.maintenance("example.com", None)
    assert failover.change_indicator(st, "example.com", now) is None  # en pausa: no se promete nada
    st.engine.resume("example.com")
    st.resolutions = {h: Resolution(h, (CF_IP,), None, "cloudflare") for h in ("example.com", "www.example.com")}
    st.calendar = calendar_at(now + timedelta(hours=2))
    c = failover.change_indicator(st, "example.com", now)
    assert c["target"] == "gcore" and "Pasa a Gcore a las" in c["text"] and "Celta Vigo – Levante" in c["text"]
    assert "Pasa a Gcore" in __import__("app.main", fromlist=["x"]).templates.env.get_template("_macros.html").module.change_badge(c)
