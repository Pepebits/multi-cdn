"""Settings pages: error reporting DSN, the six tabs, card messages and confirmations (the secrets
file: test_secrets_file.py)."""

import re
from datetime import UTC, datetime

import pytest
import sentry_sdk

from app import error_reporting
from app.db import EventStore
from app.problems import open_problems
from app.secrets_store import SecretStore

TOKEN = "123456789:telegram-token-for-tests-0001"
DSN = "https://f0e1d2c3b4a5968778695a4b3c2d1e0f@errors.example.com/42"


# ---------------------------------------------------------------- error reporting DSN

class Capture(sentry_sdk.transport.Transport):
    sent: list = []

    def capture_envelope(self, envelope):
        Capture.sent.append(envelope)


@pytest.fixture
def capture_sentry(monkeypatch):
    real = sentry_sdk.init

    def init(*args, **kwargs):
        if kwargs.get("dsn"):
            kwargs["transport"] = Capture
        return real(*args, **kwargs)
    monkeypatch.setattr(sentry_sdk, "init", init)
    Capture.sent.clear()
    yield Capture.sent
    error_reporting.reconfigure(None)


def test_dsn_validation():
    assert error_reporting.dsn_problem(DSN) is None
    assert error_reporting.dsn_problem("https://key:secret@errors.example.com:8443/sentry/7") is None
    assert error_reporting.dsn_problem("http://key@errors.example.com/1") == "https"
    assert error_reporting.dsn_problem("https://errors.example.com/1") == "shape"          # no key
    assert error_reporting.dsn_problem("https://key@errors.example.com/") == "shape"       # no project
    assert error_reporting.dsn_problem("https://key@errors.example.com/1\nX") == "shape"
    assert error_reporting.dsn_problem("https://key@192.0.2.10/1") == "host"
    assert error_reporting.dsn_problem("https://key@sentry.local/1") == "host"
    assert error_reporting.dsn_problem("https://key@localhost/1") == "host"


def test_dsn_saved_live_tested_and_removed(client, capture_sentry):
    r = client.post("/ajustes/sistema/errores", data={"dsn": "http://key@errors.example.com/1"}, follow_redirects=True)
    assert "El DSN debe usar https" in r.text and "card=errores" in str(r.url)
    r = client.post("/ajustes/sistema/errores", data={"dsn": DSN}, follow_redirects=True)
    assert sentry_sdk.get_client().is_active()
    assert "DSN del informe de errores guardado" in r.text
    assert "reinicia el panel para capturar también todos los errores web" in r.text
    assert "https://errors.example.com" in r.text and "f0e1d2c3b4a5968778695a4b3c2d1e0f" not in r.text
    r = client.post("/ajustes/sistema/errores/probar", follow_redirects=True)
    event_id = re.search(r"evento ([0-9a-f]{32})", r.text).group(1)
    assert any(event_id in str(e.headers) or e.get_event() and e.get_event().get("event_id") == event_id
               for e in capture_sentry)
    r = client.post("/ajustes/sistema/errores/quitar", follow_redirects=True)
    assert not sentry_sdk.get_client().is_active() and "Informe de errores desactivado" in r.text
    summaries = [e.summary for e in client.app.state.mc.events.list(limit=5)]
    assert "DSN del informe de errores actualizado" in summaries and "DSN del informe de errores quitado" in summaries
    assert not any("f0e1d2c3" in s for s in summaries)


def test_dsn_is_read_from_the_database_at_import_time(tmp_path, monkeypatch, capture_sentry):
    db = tmp_path / "t.db"
    monkeypatch.setenv("MULTICDN_DB", str(db))
    SecretStore(db).set("sentry_dsn", DSN)
    EventStore(db)
    assert error_reporting.stored_dsn() == DSN
    assert error_reporting.init("test") is True and error_reporting.status()["server"] == "https://errors.example.com"
    # the .env has priority at startup, also here
    monkeypatch.setenv("MULTICDN_SENTRY_DSN", "https://other@errors.example.org/9")
    assert error_reporting.stored_dsn() == "https://other@errors.example.org/9"
    # anything wrong reading it: off, the panel still starts
    monkeypatch.setattr("app.secrets_store.SecretStore.get", lambda *a: 1 / 0)
    assert error_reporting.stored_dsn() is None


# ---------------------------------------------------------------- tabs, messages, confirmations

def test_six_tabs_in_setup_order_and_old_urls(client):
    page = client.get("/ajustes/cuentas").text
    tabs = re.findall(r'<li><a href="/ajustes/(\w+)"', page.split('class="tabs"')[1].split("</nav>")[0])
    assert tabs == ["cuentas", "servidores", "notificaciones", "cambio", "sistema", "cuenta"]
    assert "Ajustes · Cuentas de proveedor" in page
    r = client.get("/ajustes/operacion", follow_redirects=False)
    assert r.status_code == 301 and r.headers["location"].endswith("/ajustes/cambio")
    r = client.post("/ajustes/operacion/feed", data={"seconds": "120"}, follow_redirects=False)
    assert "/ajustes/cambio?" in r.headers["location"] and r.headers["location"].endswith("#feed")
    r = client.post("/ajustes/operacion/retencion", data={"events_max_days": "90", "events_max_rows": "5000"},
                    follow_redirects=False)
    assert "/ajustes/sistema?" in r.headers["location"]
    for url in ("/ajustes/servidores", "/ajustes/notificaciones", "/ajustes/cambio", "/ajustes/sistema", "/ajustes/cuenta"):
        assert client.get(url).status_code == 200
        main = client.get(url).text.split('id="contenido"')[1].split('</main>')[0]
        assert 'style="margin' not in main, url


def test_message_shows_inside_the_saved_card(client):
    r = client.post("/ajustes/cambio/feed", data={"seconds": "120"}, follow_redirects=True)
    page = r.text
    feed_card = page.split('aria-labelledby="feed"')[1].split("</section>")[0]
    assert "Intervalo del feed guardado" in feed_card
    assert page.count("Intervalo del feed guardado") == 1  # not also at the top of the page
    assert '<option value="120" selected>2 min</option>' in page and "5 min (por defecto)" in page
    assert "ahora cada" in page and "sin calendario de partidos" in page


def test_dangerous_actions_ask_first(client):
    state = client.app.state.mc
    state.events.set_setting("auto_switch", 1)
    cred = state.creds.add("cloudflare", "Zone token", "cf-token-zone-0001")
    state.store.assign_zone("example.com", "zone-example", cred)
    state.reload()
    page = client.get("/ajustes/cambio").text
    assert "1 dominio deja de cambiar por sí solo." in page
    state.store.assign_zone("example.net", "zone-example-net", cred)
    state.reload()
    page = client.get("/ajustes/cambio").text
    assert 'data-open="auto-off"' in page and 'id="auto-off"' in page
    assert "dejan de cambiar por sí solos" in page and "se quedan allí hasta que los devuelvas a Cloudflare" in page
    assert 'data-open="tiempos-reset"' in page and 'name="reset" value="1"' in page
    state.creds.add("cloudflare", "Unused", "cf-token-unused-1")
    assert 'data-open="del-cred-' in client.get("/ajustes/cuentas").text
    client.post("/ajustes/servidores", data={"server_id": "vps-9", "origin_ipv4": "203.0.113.9"})
    page = client.get("/ajustes/servidores").text
    assert 'data-open="del-srv-' in page and 'data-open="quitar-ip-' in page
    assert 'data-open="nuevos-codigos"' in client.get("/ajustes/cuenta").text
    state.secrets.set("smtp_url", "smtps://user:pw@mail.example.com:465")
    assert 'data-open="quitar-smtp_url"' in client.get("/ajustes/notificaciones").text


def test_origin_ip_is_masked_kept_and_removed_on_purpose(client):
    client.post("/ajustes/servidores", data={"server_id": "vps-9", "origin_ipv4": "203.0.113.9"})
    state = client.app.state.mc
    page = client.get("/ajustes/servidores").text
    assert "203.0.113.9" not in page and "···.9" in page
    client.post("/ajustes/servidores/vps-9/editar", data={"new_id": "vps-9", "origin_ipv4": "", "private_address": ""})
    assert str(state.inventory.servers["vps-9"].origin_ipv4) == "203.0.113.9"  # empty keeps it
    r = client.post("/ajustes/servidores/vps-9/quitar-ip", follow_redirects=False)
    assert r.headers["location"].endswith("#servidor-vps-9")
    assert state.inventory.servers["vps-9"].origin_ipv4 is None


def test_recovery_codes_running_low(client):
    state = client.app.state.mc
    user = state.auth.get_user("admin")
    state.auth.conn.execute("UPDATE recovery_codes SET used_at='x' WHERE user_id=? AND rowid NOT IN "
                            "(SELECT rowid FROM recovery_codes WHERE user_id=? LIMIT 2)", (user.id, user.id))
    state.auth.conn.commit()
    page = client.get("/ajustes/cuenta").text
    assert "Solo quedan 2 códigos" in page
    assert any(p.key == "recovery:admin" and p.href == "/ajustes/cuenta#recuperacion" for p in open_problems(state))


def test_account_page_details(client):
    page = client.get("/ajustes/cuenta", headers={"User-Agent": "x"}).text
    order = [page.index(f'id="{i}"') for i in ("current", "new", "new2", "code-pw")]
    assert order == sorted(order)
    from app.routes.common import ua_summary
    assert ua_summary("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/130.0 Safari/537.36") == "Chrome · macOS"
    assert ua_summary("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Version/18.0 Mobile Safari/604.1") == "Safari · iOS"


def test_notifications_page_details(client, monkeypatch):
    monkeypatch.setattr("app.firewall_status.read", lambda: None)
    page = client.get("/ajustes/notificaciones").text
    assert 'formaction="/ajustes/notificaciones/probar/telegram" formnovalidate disabled' in page
    assert 'formaction="/ajustes/notificaciones/latido/probar" formnovalidate disabled' in page
    assert 'id="v-heartbeat_url" type="url"' in page and "URL de latido externo" in page
    assert "beat-list" in page and "modo simulación" in page
    page = client.get("/ajustes/servidores").text
    assert "pill--warn" in page and "deploy/README.md#9-protect-the-origin" in page


def test_feed_reason(client):
    from datetime import timedelta

    from app.routes.settings import feed_reason_text
    from app.signals.calendar import Calendar, Match
    from app.signals.hayahora import parse_feed
    state = client.app.state.mc
    now = datetime.now(UTC)
    state.feed = parse_feed({"lastUpdate": now.strftime("%Y-%m-%d %H:%M:%SZ"), "data": []})
    state.calendar = Calendar([Match("LaLiga", "A", "B", now + timedelta(hours=1), "pre")], fetched_at=now)
    assert feed_reason_text(state, now) == "partido en 60 min"
    state.calendar = Calendar([], fetched_at=now)
    assert feed_reason_text(state, now) == "sin actividad"
