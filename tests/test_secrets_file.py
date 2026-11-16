"""0.3.1 panel secrets file (config/secrets.env): atomic writes, backups, startup precedence, the
upgrade migration and the messages in the panel (reading the file: test_envparse.py)."""

import os
import stat
from pathlib import Path

import pytest

from app import env_sync, envfile, envparse
from app.db import EventStore
from app.migrate_secrets import MANAGED_KEYS, migrate, plan
from app.problems import open_problems
from app.secrets_store import SecretStore

TOKEN = "123456789:telegram-token-for-tests-0001"


# ---------------------------------------------------------------- writing

@pytest.mark.parametrize("bad", ["a\nb", "a\rb", "a\x00b", "a\tb", "a\u2028b", "a\x85b", "a\x0bb"])
def test_control_characters_never_reach_the_file(bad, tmp_path):
    path = tmp_path / "secrets.env"
    with pytest.raises(ValueError):
        envfile.update_file(path, "SMTP_URL", bad)
    assert not path.exists()


@pytest.fixture
def secrets_file(tmp_path, monkeypatch):
    folder = tmp_path / "config"
    folder.mkdir(mode=0o700)
    path = folder / "secrets.env"
    path.write_text("# Panel secrets\nTELEGRAM_CHAT_ID=-100\n\n# by hand\nSMTP_URL=smtps://u:pw@mail.example.com:465\n")
    path.chmod(0o600)
    monkeypatch.setenv("MULTICDN_SECRETS_PATH", str(path))
    monkeypatch.setenv("MULTICDN_DB", str(tmp_path / "t.db"))
    return path


def test_update_file_is_atomic_keeps_everything_else_and_backs_up_only_managed_lines(secrets_file):
    secrets_file.write_text(secrets_file.read_text() + "MULTICDN_SECRET_KEY=never-copied\n")
    inode, before = secrets_file.stat().st_ino, secrets_file.read_text()
    assert envfile.update_file(secrets_file, "TELEGRAM_CHAT_ID", "-300") is True
    assert secrets_file.read_text() == before.replace("-100", "-300")
    assert secrets_file.stat().st_ino != inode  # a new file, renamed over the old one
    assert stat.S_IMODE(secrets_file.stat().st_mode) == 0o600
    assert not [p for p in secrets_file.parent.iterdir() if p.name != "secrets.env"]  # no temporary file left
    folder = envfile.backups_dir()
    assert folder.name == "secrets-backups" and stat.S_IMODE(folder.stat().st_mode) == 0o700
    backups = sorted(folder.glob("secrets.env-*"))
    assert len(backups) == 1 and stat.S_IMODE(backups[0].stat().st_mode) == 0o600
    assert backups[0].read_text() == "TELEGRAM_CHAT_ID=-100\nSMTP_URL=smtps://u:pw@mail.example.com:465\n"
    assert envfile.update_file(secrets_file, "TELEGRAM_CHAT_ID", "-300") is False  # no change, no backup
    for i in range(12):
        envfile.update_file(secrets_file, "TELEGRAM_CHAT_ID", f"-{400 + i}")
    assert len(list(folder.glob("secrets.env-*"))) == envfile.BACKUPS_KEEP
    assert not any("never-copied" in p.read_text() for p in folder.iterdir())


def test_update_file_refuses_other_keys_and_reports_why(secrets_file, tmp_path):
    for key in ("MULTICDN_SECRET_KEY", "MULTICDN_DRY_RUN", "MULTICDN_ENV_FILE", "PATH"):
        with pytest.raises(ValueError):
            envfile.update_file(secrets_file, key, "x")
    with pytest.raises(envfile.EnvFileError) as exc:
        envfile.update_file(tmp_path / "missing-folder" / "secrets.env", "SMTP_URL", "x")
    assert exc.value.code == "missing"
    created = tmp_path / "config" / "new.env"  # a missing file in an existing folder is created
    assert envfile.update_file(created, "SMTP_URL", "x") and created.read_text() == f"{envparse.MARKER}\nSMTP_URL=x\n"
    if os.geteuid() != 0:
        secrets_file.parent.chmod(0o500)
        try:
            with pytest.raises(envfile.EnvFileError) as exc:
                envfile.update_file(secrets_file, "SMTP_URL", "y")
            assert exc.value.code == "not_writable"
        finally:
            secrets_file.parent.chmod(0o700)


# ---------------------------------------------------------------- startup

def _stores(path: Path):
    db = path.parent.parent / "t.db"
    return SecretStore(db), EventStore(db)


def test_file_wins_at_startup_with_an_event_without_the_value(secrets_file, monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "999:stale-container-value")  # also in the file: the file wins
    secrets_file.write_text(secrets_file.read_text() + f"TELEGRAM_BOT_TOKEN={TOKEN}\nCLOUDFLARE_API_TOKEN=cf-file-token-1\n")
    secrets, events = _stores(secrets_file)
    env_sync.sync(secrets, events)
    assert secrets.get("telegram_token") == TOKEN and secrets.get("telegram_chat_id") == "-100"
    assert os.environ["TELEGRAM_BOT_TOKEN"] == TOKEN
    summaries = [e.summary for e in events.list(limit=20)]
    assert "Token del bot de Telegram actualizado desde config/secrets.env" in summaries  # notification language
    assert "Token de Cloudflare actualizado desde config/secrets.env" in summaries
    assert not any(TOKEN in s or "cf-file-token" in s for s in summaries)
    n = len(events.list(limit=100))
    envfile.reset()
    env_sync.sync(secrets, events)  # same values: nothing new
    assert len(events.list(limit=100)) == n


def test_removing_a_line_keeps_the_panel_value_and_stale_environment_does_not_come_back(secrets_file, monkeypatch):
    secrets, events = _stores(secrets_file)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100")  # what the container was created with
    env_sync.sync(secrets, events)
    envfile.save(secrets, "telegram_chat_id", "-555")  # changed in the panel
    secrets_file.write_text("# the line was removed by hand\n")
    envfile.reset()  # next start: `docker restart` keeps TELEGRAM_CHAT_ID=-100 in the environment
    env_sync.sync(secrets, events)
    assert secrets.get("telegram_chat_id") == "-555"
    envfile.save(secrets, "telegram_chat_id", None)  # removed in the panel
    envfile.reset()
    env_sync.sync(secrets, events)
    assert secrets.get("telegram_chat_id") is None


def test_other_routes_are_imported_when_new_and_never_dropped(secrets_file, monkeypatch):
    secrets, events = _stores(secrets_file)
    monkeypatch.setenv("FOOTBALL_DATA_TOKEN", "fd-from-compose-environment-1")  # not in the file
    env_sync.sync(secrets, events)
    assert secrets.get("football_data_token") == "fd-from-compose-environment-1"
    assert os.environ["FOOTBALL_DATA_TOKEN"] == "fd-from-compose-environment-1"  # not dropped
    assert "Clave de football-data.org actualizado desde el entorno" in [e.summary for e in events.list(limit=5)]
    envfile.save(secrets, "football_data_token", "fd-saved-in-panel-1")
    secrets_file.write_text("")
    envfile.reset()
    env_sync.sync(secrets, events)  # the same old value of that route: not new, the panel keeps its own
    assert secrets.get("football_data_token") == "fd-saved-in-panel-1"
    monkeypatch.setenv("FOOTBALL_DATA_TOKEN", "fd-from-compose-environment-2")
    envfile.reset()
    env_sync.sync(secrets, events)  # a new value there: imported
    assert secrets.get("football_data_token") == "fd-from-compose-environment-2"


def test_unreadable_file_imports_nothing_and_is_a_problem(make_client, secrets_file, monkeypatch):
    secrets_file.write_bytes(b"TELEGRAM_CHAT_ID=\xff\xfe\n")  # not UTF-8: cannot be read
    client = make_client(MULTICDN_SECRETS_PATH=str(secrets_file), TELEGRAM_CHAT_ID="-777", MULTICDN_DB=os.environ["MULTICDN_DB"])
    state = client.app.state.mc
    assert state.secrets.get("telegram_chat_id") is None  # not from the container's environment
    assert any(p.key == "secrets-file" and p.severity == "error" for p in open_problems(state))
    page = client.get("/ajustes/sistema").text
    assert "El panel no puede leer config/secrets.env" in page


def test_no_secrets_file_falls_back_to_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("FOOTBALL_DATA_TOKEN", "fd-token-from-env-1")
    secrets, events = SecretStore(tmp_path / "t.db"), EventStore(tmp_path / "t.db")
    env_sync.sync(secrets, events)
    assert secrets.get("football_data_token") == "fd-token-from-env-1"


def test_unmanaged_keys_in_the_file_are_ignored_and_reported(make_client, secrets_file, monkeypatch):
    secrets_file.write_text("MULTICDN_DRY_RUN=false\nORIGIN_VPS1_IPV4=192.0.2.10\nTELEGRAM_CHAT_ID=-100\n")
    client = make_client(MULTICDN_SECRETS_PATH=str(secrets_file), MULTICDN_DRY_RUN="false", MULTICDN_DB=os.environ["MULTICDN_DB"])
    state = client.app.state.mc
    assert state.dry_run_env is True and os.environ["MULTICDN_DRY_RUN"] == "true"
    keys = {p.key for p in open_problems(state)}
    assert {"secrets-unmanaged", "secrets-dry-run"} <= keys
    page = client.get("/ajustes/sistema").text
    assert "MULTICDN_DRY_RUN, ORIGIN_VPS1_IPV4" in page and "192.0.2.10" not in page


# ---------------------------------------------------------------- the panel

def test_panel_save_writes_the_file_and_the_environment(make_client, secrets_file):
    client = make_client(MULTICDN_SECRETS_PATH=str(secrets_file), MULTICDN_DB=os.environ["MULTICDN_DB"])
    r = client.post("/ajustes/notificaciones/canal/telegram", data={"telegram_token": TOKEN, "telegram_chat_id": ""},
                    follow_redirects=False)
    assert "card=canal-telegram" in r.headers["location"]
    text = secrets_file.read_text()
    assert text.startswith("# Panel secrets\nTELEGRAM_CHAT_ID=-100\n") and f"\nTELEGRAM_BOT_TOKEN={TOKEN}\n" in text
    assert os.environ["TELEGRAM_BOT_TOKEN"] == TOKEN
    assert "igual que en config/secrets.env" in client.get("/ajustes/notificaciones").text
    client.post("/ajustes/notificaciones/telegram_token/eliminar")
    assert "TELEGRAM_BOT_TOKEN" not in secrets_file.read_text() and "TELEGRAM_BOT_TOKEN" not in os.environ
    page = client.get("/ajustes/sistema").text
    assert "Fichero de secretos del panel (config/secrets.env)" in page and str(secrets_file) in page
    assert "El panel puede escribirlo</dt><dd>sí" in page


def test_every_save_says_when_the_file_could_not_be_written(make_client, tmp_path, monkeypatch):
    if os.geteuid() == 0:
        pytest.skip("root can write anything")
    folder = tmp_path / "ro"
    folder.mkdir()
    path = folder / "secrets.env"
    path.write_text("TELEGRAM_CHAT_ID=-100\n")
    folder.chmod(0o500)
    try:
        client = make_client(MULTICDN_SECRETS_PATH=str(path))
        state = client.app.state.mc
        r = client.post("/ajustes/notificaciones/canal/telegram", data={"telegram_chat_id": "-555", "telegram_token": TOKEN},
                        follow_redirects=True)
        assert state.secrets.get("telegram_chat_id") == "-555"
        assert "No se pudo actualizar config/secrets.env (sin permiso para escribirlo)" in r.text
        assert "TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID" in r.text
        page = client.get("/ajustes/notificaciones").text
        assert "Actualiza <code>TELEGRAM_CHAT_ID</code> en el fichero a mano" in page
        assert any(p.key == "env:TELEGRAM_CHAT_ID" and p.href == "/ajustes/sistema#env" for p in open_problems(state))
        monkeypatch.setattr("app.heartbeat.beat", _no_beat)
        r = client.post("/ajustes/notificaciones/latido", data={"heartbeat_url": "https://hc-ping.example.com/abc"},
                        follow_redirects=True)
        assert "MULTICDN_HEARTBEAT_URL" in r.text and "sin permiso para escribirlo" in r.text
        r = client.post("/ajustes/cambio/football-data", data={"token": "fd-token-0001"}, follow_redirects=True)
        assert "FOOTBALL_DATA_TOKEN" in r.text and "sin permiso para escribirlo" in r.text
        envfile.reset()
        env_sync.sync(state.secrets, state.events)  # next start: the file wins
        assert state.secrets.get("telegram_chat_id") == "-100"
    finally:
        folder.chmod(0o700)


async def _no_beat(state):
    return None


def test_conftest_keeps_the_secrets_file_unset():
    assert "MULTICDN_SECRETS_PATH" not in os.environ and envfile.view().configured is False


# ---------------------------------------------------------------- upgrade: .env -> config/secrets.env

def test_migration_plan_moves_only_managed_lines():
    env = ("# settings\nMULTICDN_SECRET_KEY=k\nMULTICDN_DRY_RUN=true\nTELEGRAM_CHAT_ID=-100 # alerts\n"
           "export SMTP_URL='smtps://u:p$w@mail.example.com:465'\nGCORE_API_TOKEN=old\nGCORE_API_TOKEN=gc-new\n"
           "ORIGIN_VPS1_IPV4=192.0.2.10\nCLOUDFLARE_API_TOKEN=cf-env\n")
    secrets = "CLOUDFLARE_API_TOKEN=cf-already-in-file\n"
    new_env, new_secrets, moved, kept = plan(env, secrets)
    assert new_env == "# settings\nMULTICDN_SECRET_KEY=k\nMULTICDN_DRY_RUN=true\nORIGIN_VPS1_IPV4=192.0.2.10\n"
    assert moved == ["TELEGRAM_CHAT_ID", "SMTP_URL", "GCORE_API_TOKEN"] and kept == ["CLOUDFLARE_API_TOKEN"]
    values = envparse.parse(new_secrets, {}).values
    assert values == {"CLOUDFLARE_API_TOKEN": "cf-already-in-file", "TELEGRAM_CHAT_ID": "-100",
                      "SMTP_URL": "smtps://u:p$w@mail.example.com:465", "GCORE_API_TOKEN": "gc-new"}
    assert plan("MULTICDN_SECRET_KEY=k\n", "")[2:] == ([], [])


def test_migration_writes_both_files_with_a_backup(tmp_path):
    env = tmp_path / ".env"
    env.write_text("MULTICDN_SECRET_KEY=k\nTELEGRAM_BOT_TOKEN=" + TOKEN + "\n")
    env.chmod(0o600)
    (tmp_path / "config").mkdir()
    secrets = tmp_path / "config" / "secrets.env"
    secrets.write_text("MULTICDN_DRY_RUN=false\n")
    out = []
    assert migrate(env, secrets, out=out.append) == 0
    assert env.read_text() == "MULTICDN_SECRET_KEY=k\n" and stat.S_IMODE(env.stat().st_mode) == 0o600
    assert f"TELEGRAM_BOT_TOKEN={TOKEN}" in secrets.read_text() and stat.S_IMODE(secrets.stat().st_mode) == 0o600
    backup = next(tmp_path.glob(".env.bak-*"))
    assert TOKEN in backup.read_text() and stat.S_IMODE(backup.stat().st_mode) == 0o600
    report = "\n".join(out)
    assert "TELEGRAM_BOT_TOKEN" in report and TOKEN not in report and "MULTICDN_DRY_RUN" in report  # warns
    out.clear()
    assert migrate(env, secrets, out=out.append) == 0 and len(list(tmp_path.glob(".env.bak-*"))) == 1  # nothing left


def test_migration_keys_are_the_managed_ones():
    assert MANAGED_KEYS == envfile.MANAGED


def test_cli_migrate_secrets(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path(".env").write_text("MULTICDN_SECRET_KEY=k\nSMTP_URL=x\n")
    Path("config").mkdir()
    from app import cli
    assert cli.main(["migrate-secrets"]) == 0
    assert Path("config/secrets.env").read_text().endswith("SMTP_URL=x\n") and "SMTP_URL" not in Path(".env").read_text()
