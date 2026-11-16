"""0.3.1 pre-deploy fixes: messages that are not lost, Enter that saves, the Remove IP guard, the
runbook order and deploy/install.sh (error reporting: test_error_reporting.py)."""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from app.signals.dnscheck import Resolution

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------- 3. messages

def test_a_message_for_a_card_that_is_not_there_shows_at_the_top(client):
    page = client.get("/ajustes/sistema?card=servidor-gone&ok=Mensaje+de+prueba").text
    main = page.split('id="contenido"')[1]
    assert main.count("Mensaje de prueba") == 1 and 'class="notice notice--ok" role="status"' in main
    page = client.get("/ajustes/sistema?card=errores&error=Fallo+de+prueba").text
    assert page.count("Fallo de prueba") == 1 and 'card__flash" role="alert"' in page


def test_invalid_ip_does_not_rename_the_server(client):
    state = client.app.state.mc
    client.post("/ajustes/servidores", data={"server_id": "vps-9", "origin_ipv4": "203.0.113.9"})
    r = client.post("/ajustes/servidores/vps-9/editar", data={"new_id": "vps-10", "origin_ipv4": "203.0.113.999",
                                                              "private_address": ""}, follow_redirects=True)
    assert "vps-9" in state.inventory.servers and "vps-10" not in state.inventory.servers
    assert "card=servidor-vps-9" in str(r.url)


# ---------------------------------------------------------------- 4. Enter saves

def _before(page: str, first: str, second: str) -> bool:
    return page.index(first) < page.index(second)


def test_enter_presses_save_not_the_test(client):
    client.app.state.mc.secrets.set("telegram_token", "123456789:telegram-token-for-tests-0001")
    page = client.get("/ajustes/sistema").text
    assert _before(page, "Guardar DSN", 'formaction="/ajustes/sistema/errores/probar"')
    page = client.get("/ajustes/notificaciones").text
    assert _before(page, "Guardar Telegram", 'formaction="/ajustes/notificaciones/probar/telegram"')
    assert _before(page, "Guardar Email", 'formaction="/ajustes/notificaciones/probar/email"')
    assert _before(page, "Guardar y enviar latido", 'formaction="/ajustes/notificaciones/latido/probar"')
    assert "btn--last" in page
    page = client.get("/dominios/example.com").text
    form = page.split('action="/dominios/example.com/hostnames"')[1]
    assert form.index('type="submit" tabindex="-1"') < form.index("/quitar")


# ---------------------------------------------------------------- 7. Remove IP

def test_remove_ip_refused_while_a_hostname_is_on_gcore(client):
    state = client.app.state.mc
    client.post("/ajustes/servidores/vps-1/editar", data={"new_id": "vps-1", "origin_ipv4": "203.0.113.10",
                                                          "private_address": ""})
    state.resolutions["www.example.com"] = Resolution("www.example.com", ("198.51.100.7",), "x.gcdn.co.", "gcore")
    r = client.post("/ajustes/servidores/vps-1/quitar-ip", follow_redirects=True)
    assert "www.example.com está ahora en Gcore" in r.text
    assert str(state.inventory.servers["vps-1"].origin_ipv4) == "203.0.113.10"
    state.resolutions.clear()
    state.cf_live["example.com"] = {"to_backup": True, "target": "x.gcdn.co"}  # flattened apex, live record
    assert "example.com está ahora en Gcore" in client.post("/ajustes/servidores/vps-1/quitar-ip", follow_redirects=True).text
    state.cf_live.clear()
    client.post("/ajustes/servidores/vps-1/quitar-ip")
    assert state.inventory.servers["vps-1"].origin_ipv4 is None


# ---------------------------------------------------------------- 6. runbook

def test_runbook_registers_the_notifier_after_the_import(tmp_path, monkeypatch):
    monkeypatch.setenv("MULTICDN_DB", str(tmp_path / "t.db"))
    seen = []
    import app.env_sync

    real = app.env_sync.sync
    monkeypatch.setattr(app.env_sync, "sync", lambda secrets, events, *a: (seen.append(len(events.listeners)),
                                                                            real(secrets, events, *a))[1])
    from app import runbook
    state = runbook._state()
    assert seen == [0] and len(state.events.listeners) == 1


# ---------------------------------------------------------------- deploy/install.sh

def _shim(bindir: Path, name: str, body: str) -> None:
    f = bindir / name
    f.write_text(f"#!/usr/bin/env bash\necho \"{name} $*\" >> \"$SHIM_LOG\"\n{body}\n")
    f.chmod(f.stat().st_mode | stat.S_IEXEC)


@pytest.mark.skipif(not shutil.which("bash") or not shutil.which("python3"), reason="needs bash and python3")
def test_install_moves_the_panel_values_and_survives_a_dotenv_that_is_not_ours(tmp_path):
    repo = tmp_path / "repo"
    (repo / "deploy").mkdir(parents=True)
    shutil.copy(ROOT / "deploy" / "install.sh", repo / "deploy" / "install.sh")
    (repo / "app").symlink_to(ROOT / "app")
    (repo / ".env").write_text("MULTICDN_SECRET_KEY=k\nMULTICDN_DRY_RUN=true\nTELEGRAM_CHAT_ID=-100\n")
    bindir, log = tmp_path / "bin", tmp_path / "shims.log"
    bindir.mkdir()
    _shim(bindir, "docker", "exit 0")
    _shim(bindir, "sudo", 'exit 0')  # chown/setfacl as root: only recorded
    _shim(bindir, "setfacl", "exit 0")
    _shim(bindir, "curl", "exit 0")
    # chmod of .env fails, as when the file belongs to someone else
    _shim(bindir, "chmod", 'case "${@: -1}" in .env) exit 1;; esac; exec /bin/chmod "$@"')
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "SHIM_LOG": str(log)}
    env.pop("MULTICDN_ENV_FILE", None)
    env.pop("MULTICDN_SECRETS_DIR", None)
    r = subprocess.run(["bash", str(repo / "deploy" / "install.sh")], cwd=repo, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "is not yours" in r.stdout and "Moved from .env to config/secrets.env: TELEGRAM_CHAT_ID" in r.stdout
    assert (repo / ".env").read_text() == "MULTICDN_SECRET_KEY=k\nMULTICDN_DRY_RUN=true\n"
    assert "TELEGRAM_CHAT_ID=-100" in (repo / "config" / "secrets.env").read_text()
    assert stat.S_IMODE((repo / "config").stat().st_mode) == 0o700
    assert stat.S_IMODE((repo / "config" / "secrets.env").stat().st_mode) == 0o600
    calls = log.read_text()
    assert "u:10001:rwx" in calls and "d:u:10001:rw" in calls and "docker compose up -d --build" in calls
    assert "setfacl -x u:10001 .env" in calls  # the write access of 0.3.1 builds is taken back
