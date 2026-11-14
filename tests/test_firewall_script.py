"""multicdn-firewall.sh con listas falsas (file://) y nft/caddy/systemctl sustituidos."""

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "deploy" / "firewall" / "multicdn-firewall.sh"
pytestmark = pytest.mark.skipif(not shutil.which("jq") or not shutil.which("bash"), reason="necesita bash y jq")


def shim(bindir: Path, name: str, body: str) -> None:
    f = bindir / name
    f.write_text(f"#!/usr/bin/env bash\necho \"{name} $*\" >> \"$SHIM_LOG\"\n{body}\n")
    f.chmod(f.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def env(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "v4").write_text("173.245.48.0/20\n103.21.244.0/22\nnot-an-ip\n")
    (src / "v6").write_text("2400:cb00::/32\n")
    (src / "gcore.json").write_text(json.dumps({"addresses": ["93.123.17.194/32", "92.223.78.23/32"],
                                                "addresses_v6": ["2a03:90c0:9992::1/128"]}))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    # NFT_LIST_EXIT=1: la tabla multicdn no está cargada (p. ej. recién arrancado).
    shim(bindir, "nft", '[[ "$1 $2" == "list table" ]] && exit "${NFT_LIST_EXIT:-0}"; exit 0')
    shim(bindir, "caddy", 'exit "${CADDY_VALIDATE_EXIT:-0}"')
    shim(bindir, "systemctl", "exit 0")
    caddydir = tmp_path / "caddy"
    caddydir.mkdir()
    (caddydir / "Caddyfile").write_text("{\n\tservers {\n\t\timport cdn-ranges.caddy\n\t}\n}\n")
    panel = tmp_path / "data"
    panel.mkdir()
    (panel / "firewall-refresh-request").write_text("")
    e = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", SHIM_LOG=str(tmp_path / "calls.log"),
             MULTICDN_FIREWALL_TEST="1", MULTICDN_FIREWALL_CONFIG="/nonexistent",
             CF_V4_URL=f"file://{src}/v4", CF_V6_URL=f"file://{src}/v6", GCORE_URL=f"file://{src}/gcore.json",
             STATE_DIR=str(tmp_path / "state"), CADDY_RANGES=str(caddydir / "cdn-ranges.caddy"),
             CADDYFILE=str(caddydir / "Caddyfile"), CADDY_ENVFILE="/nonexistent", PANEL_DATA=str(panel))
    return {"env": e, "tmp": tmp_path, "src": src, "caddy": caddydir, "panel": panel}


def run(env, *args, **extra):
    return subprocess.run(["bash", str(SCRIPT), *args], env=env["env"] | extra, capture_output=True, text=True)


def calls(env):
    log = env["tmp"] / "calls.log"
    return log.read_text() if log.exists() else ""


def test_ruleset_only_filters_traffic_to_the_host(env):
    out = run(env, "print").stdout
    assert "fib daddr type != local accept" in out  # las conexiones salientes de contenedores no se tocan
    assert "ip saddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12" in out
    assert "103.21.244.0/22, 173.245.48.0/20, 92.223.78.23/32, 93.123.17.194/32" in out
    assert "not-an-ip" not in out


def test_apply_writes_caddy_ranges_status_and_reloads_once(env):
    r = run(env, "apply")
    assert r.returncode == 0, r.stderr
    ranges = (env["caddy"] / "cdn-ranges.caddy").read_text()
    assert "trusted_proxies static 103.21.244.0/22 173.245.48.0/20 2400:cb00::/32" in ranges
    status = json.loads((env["panel"] / "firewall-status.json").read_text())
    assert status["ipv4"] == 4 and status["ipv6"] == 2 and status["error"] == "" and status["last_ok"]
    assert status["caddy"] == "actualizado y recargado"
    assert not (env["panel"] / "firewall-refresh-request").exists()
    assert calls(env).count("systemctl reload caddy") == 1
    run(env, "apply")  # misma lista: Caddy no se recarga otra vez
    assert calls(env).count("systemctl reload caddy") == 1
    assert json.loads((env["panel"] / "firewall-status.json").read_text())["caddy"] == "sin cambios"


def test_caddy_validation_failure_restores_previous_ranges(env):
    run(env, "apply")
    before = (env["caddy"] / "cdn-ranges.caddy").read_text()
    (env["src"] / "v4").write_text("173.245.48.0/20\n103.21.244.0/22\n104.16.0.0/13\n")
    r = run(env, "apply", CADDY_VALIDATE_EXIT="1")
    assert r.returncode == 1
    assert (env["caddy"] / "cdn-ranges.caddy").read_text() == before
    assert "Caddy no valida" in json.loads((env["panel"] / "firewall-status.json").read_text())["error"]


def test_shrunken_list_is_rejected(env):
    run(env, "apply")
    (env["src"] / "gcore.json").write_text(json.dumps({"addresses": [], "addresses_v6": ["2a03:90c0:9992::1/128"]}))
    (env["panel"] / "firewall-refresh-request").write_text("")
    r = run(env, "apply")
    assert r.returncode == 1 and "vacía" in r.stderr
    assert not (env["panel"] / "firewall-refresh-request").exists()  # no se relanza en bucle
    status = json.loads((env["panel"] / "firewall-status.json").read_text())
    assert status["error"] and status["last_ok"]  # la última lista buena sigue registrada


def test_counts_ranges_added_and_removed_and_logs_them(env):
    run(env, "apply")
    first = json.loads((env["panel"] / "firewall-status.json").read_text())
    assert (first["added"], first["removed"]) == (6, 0)
    (env["src"] / "v4").write_text("173.245.48.0/20\n104.16.0.0/13\n")  # entra una, sale otra
    assert run(env, "apply").returncode == 0
    status = json.loads((env["panel"] / "firewall-status.json").read_text())
    assert (status["added"], status["removed"]) == (1, 1)
    log = (env["panel"] / "firewall-changes.log").read_text().splitlines()
    assert len(log) == 2 and log[-1].endswith("+1 -1")


def test_panel_files_replace_planted_symlinks_instead_of_following_them(env):
    host = env["tmp"] / "host-file"
    host.write_text("root:x:0:0\n")
    for name in ("firewall-status.json", "firewall-changes.log"):
        (env["panel"] / name).symlink_to(host)
    r = run(env, "apply")
    assert r.returncode == 0, r.stderr
    assert host.read_text() == "root:x:0:0\n"
    for name in ("firewall-status.json", "firewall-changes.log"):
        f = env["panel"] / name
        assert not f.is_symlink() and oct(f.stat().st_mode)[-3:] == "644"
    assert json.loads((env["panel"] / "firewall-status.json").read_text())["error"] == ""
    assert (env["panel"] / "firewall-changes.log").read_text().endswith("+6 -0\n")
    assert not [p.name for p in env["panel"].iterdir() if p.name.startswith(".")]  # sin temporales


def test_failed_download_restores_previous_rules_when_table_is_not_loaded(env):
    assert run(env, "apply").returncode == 0
    rules = env["tmp"] / "state" / "rules.nft"
    assert rules.exists()
    (env["src"] / "v4").unlink()  # sin red al arrancar
    r = run(env, "apply")  # la tabla sigue cargada: no se toca
    assert r.returncode == 1 and f"nft -f {rules}" not in calls(env)
    r = run(env, "apply", NFT_LIST_EXIT="1")  # tras reiniciar: tabla no cargada
    assert r.returncode == 1 and "restauradas las reglas anteriores" in r.stderr
    assert f"nft -c -f {rules}" in calls(env) and f"nft -f {rules}" in calls(env)
    status = json.loads((env["panel"] / "firewall-status.json").read_text())
    assert "IPv4 de Cloudflare" in status["error"] and "restauradas las reglas anteriores" in status["error"]


def test_failed_first_download_without_previous_rules_says_so(env):
    (env["src"] / "v4").unlink()
    r = run(env, "apply", NFT_LIST_EXIT="1")
    assert r.returncode == 1 and "no hay reglas anteriores" in r.stderr
    assert "nft -f" not in calls(env)


def test_service_retries_on_failure():
    unit = (SCRIPT.parent / "multicdn-firewall.service").read_text()
    assert "Type=oneshot" in unit and "Restart=on-failure" in unit and "RestartSec=5min" in unit
