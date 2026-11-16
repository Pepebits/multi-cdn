"""0.3.1 Settings overhaul: .env sync, error reporting DSN, six tabs, card messages and confirmations."""

import os
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
import sentry_sdk

from app import env_sync, envfile, error_reporting
from app.config import _unquote
from app.db import EventStore
from app.problems import open_problems
from app.secrets_store import SecretStore

TOKEN = "123456789:telegram-token-for-tests-0001"
DSN = "https://f0e1d2c3b4a5968778695a4b3c2d1e0f@errors.example.com/42"


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    path = tmp_path / "config.env"
    path.write_text("# Multi-CDN\nMULTICDN_SECRET_KEY=keep-me\n\n# alerts\nTELEGRAM_CHAT_ID=-100\nMULTICDN_DRY_RUN=true\n")
    path.chmod(0o600)
    monkeypatch.setenv("MULTICDN_ENV_PATH", str(path))
    monkeypatch.setenv("MULTICDN_DB", str(tmp_path / "t.db"))
    return path


# ---------------------------------------------------------------- envfile

def test_render_updates_in_place_and_keeps_everything_else():
    text = "# head\nA=1\nTELEGRAM_CHAT_ID=-100  \n  # TELEGRAM_BOT_TOKEN=commented\nexport SMTP_URL=x\nZ=2"
    out = envfile.render(text, "TELEGRAM_CHAT_ID", "-200")
    assert out == text.replace("TELEGRAM_CHAT_ID=-100  ", "TELEGRAM_CHAT_ID=-200")
    out = envfile.render(text, "SMTP_URL", "smtps://user:pa ss@mail.example.com:465")
    assert "export SMTP_URL='smtps://user:pa ss@mail.example.com:465'\n" in out and out.startswith("# head\nA=1\n")
    # a commented line is not the variable: append at the end, under the marker
    out = envfile.render(text, "TELEGRAM_BOT_TOKEN", TOKEN)
    assert out == text + "\n\n" + envfile.MARKER + "\nTELEGRAM_BOT_TOKEN=" + TOKEN + "\n"
    assert envfile.render(out, "ALERT_EMAIL_TO", "ops@example.com").count(envfile.MARKER) == 1
    # removal: the line goes, nothing else moves
    assert envfile.render(text, "TELEGRAM_CHAT_ID", None) == "# head\nA=1\n  # TELEGRAM_BOT_TOKEN=commented\nexport SMTP_URL=x\nZ=2"


@pytest.mark.parametrize("value", ["a=b=c", "with spaces", "x#y", "it's $HOME", 'q"uote\'s', "plain-value_1"])
def test_quoting_round_trips(value):
    line = envfile.render("", "SMTP_URL", value).splitlines()[-1]
    assert _unquote(line.partition("=")[2]) == value


def test_update_env_rejects_newlines_and_unmanaged_keys(env_file):
    with pytest.raises(ValueError):
        envfile.update_env(env_file, "SMTP_URL", "a\nMULTICDN_DRY_RUN=false")
    for key in ("MULTICDN_SECRET_KEY", "MULTICDN_DRY_RUN", "PATH"):
        with pytest.raises(ValueError):
            envfile.update_env(env_file, key, "x")
    assert "MULTICDN_SECRET_KEY=keep-me" in env_file.read_text()


def test_update_env_writes_in_place_with_backups(env_file, monkeypatch):
    inode = env_file.stat().st_ino
    before = env_file.read_text()
    assert envfile.update_env(env_file, "TELEGRAM_CHAT_ID", "-300") is True
    assert env_file.read_text() == before.replace("-100", "-300")
    assert env_file.stat().st_ino == inode and env_file.stat().st_mode & 0o777 == 0o600  # same file (bind mount)
    backups = sorted(envfile.backups_dir().glob(".env-*"))
    assert len(backups) == 1 and backups[0].read_text() == before and backups[0].stat().st_mode & 0o777 == 0o600
    assert envfile.update_env(env_file, "TELEGRAM_CHAT_ID", "-300") is False  # no change, no backup
    for i in range(12):
        envfile.update_env(env_file, "TELEGRAM_CHAT_ID", f"-{400 + i}")
    assert len(list(envfile.backups_dir().glob(".env-*"))) == envfile.BACKUPS_KEEP


def test_update_env_reasons(tmp_path, monkeypatch):
    monkeypatch.setenv("MULTICDN_DB", str(tmp_path / "t.db"))
    with pytest.raises(envfile.EnvFileError) as exc:
        envfile.update_env(tmp_path / "missing.env", "SMTP_URL", "x")
    assert exc.value.code == "missing"
    if os.geteuid() != 0:
        locked = tmp_path / "locked.env"
        locked.write_text("A=1\n")
        locked.chmod(0o400)
        with pytest.raises(envfile.EnvFileError) as exc:
            envfile.update_env(locked, "SMTP_URL", "x")
        assert exc.value.code == "not_writable"


# ---------------------------------------------------------------- sync at startup

def test_env_wins_at_startup_and_leaves_an_event_without_the_value(make_client, monkeypatch):
    client = make_client(TELEGRAM_BOT_TOKEN=TOKEN)
    state = client.app.state.mc
    assert state.secrets.get("telegram_token") == TOKEN and state.secrets.status("telegram_token").source == "env"
    events = [e.summary for e in state.events.list(limit=20)]
    assert "Token del bot de Telegram actualizado desde el .env del servidor" in events
    assert not any(TOKEN in e for e in events)
    # a value saved in the panel (with .env not writable) is replaced by .env on the next start
    state.secrets.set("telegram_token", "999:panel-value-that-loses-on-restart")
    env_sync.sync(state.secrets, state.events)  # what the next start does (lifespan)
    assert state.secrets.get("telegram_token") == TOKEN
    # same value: no new event
    n = len(state.events.list(limit=100))
    env_sync.sync(state.secrets, state.events)
    assert len(state.events.list(limit=100)) == n


def test_provider_tokens_follow_the_env(make_client, monkeypatch):
    client = make_client(CLOUDFLARE_API_TOKEN="cf-env-token-0001", GCORE_API_TOKEN="gc-env-token-0001")
    state = client.app.state.mc
    cf = state.creds.list("cloudflare")
    assert len(cf) == 1 and state.creds.secret(cf[0].id) == "cf-env-token-0001"
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-env-token-0002")
    assert state.creds.import_env("Imported") == ["cloudflare"]
    assert [state.creds.secret(c.id) for c in state.creds.list("cloudflare")] == ["cf-env-token-0002"]  # same one
    assert state.creds.env_status(cf[0])["state"] == "sync"
    # deleting it in the panel removes the line from .env (here: not configured, so it stays and says so)
    client.post(f"/ajustes/cuentas/{cf[0].id}/eliminar")
    assert state.creds.env_removed() == ["CLOUDFLARE_API_TOKEN"]
    page = client.get("/ajustes/cuentas").text
    assert "No se pudo quitar <code>CLOUDFLARE_API_TOKEN</code>" in page


def test_provider_token_adopts_an_existing_credential(tmp_path, monkeypatch):
    monkeypatch.setenv("MULTICDN_DB", str(tmp_path / "t.db"))
    secrets = SecretStore(tmp_path / "t.db")
    from app.credentials import CredentialStore
    creds = CredentialStore(secrets)
    cid = creds.add("gcore", "Importada del entorno", "gc-same-token-1")  # imported by 0.3.0, in Spanish
    monkeypatch.setenv("GCORE_API_TOKEN", "gc-same-token-1")
    assert creds.import_env("Imported from the environment") == [] and creds.env_credential("gcore").id == cid


def test_cli_startup_imports_too(tmp_path, monkeypatch):
    monkeypatch.setenv("MULTICDN_DB", str(tmp_path / "t.db"))
    monkeypatch.setenv("FOOTBALL_DATA_TOKEN", "fd-token-from-env-1")
    from app import cli
    _auth, events = cli._store()
    assert SecretStore(tmp_path / "t.db").get("football_data_token") == "fd-token-from-env-1"
    assert "football-data.org" in events.list(limit=1)[0].summary


# ---------------------------------------------------------------- write-back from the panel

def test_panel_save_writes_env_and_process_environment(make_client, env_file):
    client = make_client(MULTICDN_ENV_PATH=str(env_file))
    r = client.post("/ajustes/notificaciones/canal/telegram", data={"telegram_token": TOKEN, "telegram_chat_id": ""},
                    follow_redirects=False)
    assert "card=canal-telegram" in r.headers["location"] and r.headers["location"].endswith("#canal-telegram")
    text = env_file.read_text()
    assert text.startswith("# Multi-CDN\nMULTICDN_SECRET_KEY=keep-me\n\n# alerts\nTELEGRAM_CHAT_ID=-100\n")
    assert f"{envfile.MARKER}\nTELEGRAM_BOT_TOKEN={TOKEN}\n" in text
    assert os.environ["TELEGRAM_BOT_TOKEN"] == TOKEN
    page = client.get("/ajustes/notificaciones").text
    assert "igual que en el .env" in page
    client.post("/ajustes/notificaciones/telegram_token/eliminar")
    assert "TELEGRAM_BOT_TOKEN" not in env_file.read_text() and "TELEGRAM_BOT_TOKEN" not in os.environ
    page = client.get("/ajustes/sistema").text
    assert "El panel puede escribirlo" in page and str(env_file) in page


def test_unwritable_env_warns_keeps_db_and_loses_on_restart(make_client, tmp_path, monkeypatch):
    if os.geteuid() == 0:
        pytest.skip("root can write anything")
    path = tmp_path / "ro.env"
    path.write_text("TELEGRAM_CHAT_ID=-100\n")
    path.chmod(0o400)
    client = make_client(MULTICDN_ENV_PATH=str(path), TELEGRAM_CHAT_ID="-100")
    state = client.app.state.mc
    r = client.post("/ajustes/notificaciones/canal/telegram", data={"telegram_chat_id": "-555"}, follow_redirects=True)
    assert state.secrets.get("telegram_chat_id") == "-555"
    assert "No se pudo actualizar el .env del servidor (sin permiso para escribirlo)" in r.text
    page = client.get("/ajustes/notificaciones").text
    assert "Actualiza <code>TELEGRAM_CHAT_ID</code> en el .env a mano" in page
    assert any(p.key == "env:TELEGRAM_CHAT_ID" and p.href == "/ajustes/sistema#env" for p in open_problems(state))
    assert "<code>TELEGRAM_CHAT_ID</code>" in client.get("/ajustes/sistema").text
    env_sync.sync(state.secrets, state.events)  # next start
    assert state.secrets.get("telegram_chat_id") == "-100"


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
    from app.main import ua_summary
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

    from app.main import feed_reason_text
    from app.signals.calendar import Calendar, Match
    from app.signals.hayahora import parse_feed
    state = client.app.state.mc
    now = datetime.now(UTC)
    state.feed = parse_feed({"lastUpdate": now.strftime("%Y-%m-%d %H:%M:%SZ"), "data": []})
    state.calendar = Calendar([Match("LaLiga", "A", "B", now + timedelta(hours=1), "pre")], fetched_at=now)
    assert feed_reason_text(state, now) == "partido en 60 min"
    state.calendar = Calendar([], fetched_at=now)
    assert feed_reason_text(state, now) == "sin actividad"


def test_startup_reads_the_env_file_not_the_stale_container_environment(env_file, monkeypatch):
    # `docker restart` keeps the environment the container was created with: the file wins.
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-1")            # stale: the panel changed it to -100 in the file
    monkeypatch.setenv("SMTP_URL", "smtps://old@mail.example.com:465")  # stale: removed from the file
    secrets, events = SecretStore(env_file.parent / "t.db"), EventStore(env_file.parent / "t.db")
    env_sync.sync(secrets, events)
    assert secrets.get("telegram_chat_id") == "-100" and secrets.get("smtp_url") is None
    assert os.environ["TELEGRAM_CHAT_ID"] == "-100" and "SMTP_URL" not in os.environ
    assert os.environ.get("MULTICDN_SECRET_KEY") != "keep-me"  # unmanaged lines are never loaded or touched
