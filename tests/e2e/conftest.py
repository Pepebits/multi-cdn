"""Browser tests: the real panel (uvicorn, offline, a throwaway database) driven by Playwright.

Run with `uv run pytest -m e2e` (the normal run skips them). The first time, install the browser:
`uv run playwright install chromium`.
"""

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "contraseña-de-pruebas-e2e"
DESKTOP = {"width": 1280, "height": 860}
PHONE = {"width": 390, "height": 844}

SEED = """
import json, os
os.environ["MULTICDN_OFFLINE"] = "1"
from fastapi.testclient import TestClient
from app.main import app
with TestClient(app) as c:
    s = c.app.state.mc
    uid = s.auth.create_user("prueba", {password!r})
    s.auth.start_totp_enrollment(uid)
    s.auth.enable_totp(uid)
    codes = s.auth.new_recovery_codes(uid)
    print(json.dumps({{"secret": s.auth.totp_secret(uid), "codes": codes}}))
"""


def pytest_collection_modifyitems(items):
    for item in items:
        if "tests/e2e/" in str(item.path).replace(os.sep, "/"):
            item.add_marker(pytest.mark.e2e)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def panel(tmp_path_factory):
    """Starts the panel on a free port with example.com and example.net and one TOTP user."""
    from cryptography.fernet import Fernet
    data = tmp_path_factory.mktemp("panel")
    env = os.environ | {
        "MULTICDN_DB": str(data / "multicdn.db"), "MULTICDN_INVENTORY": "inventory.example.yaml",
        "MULTICDN_OFFLINE": "1", "MULTICDN_SECRET_KEY": Fernet.generate_key().decode(),
        "MULTICDN_ENV_FILE": str(data / "none.env"), "PYTHONPATH": str(ROOT),
    }
    seeded = subprocess.run([sys.executable, "-c", SEED.format(password=PASSWORD)], cwd=ROOT, env=env,
                            capture_output=True, text=True, check=True)
    user = json.loads(seeded.stdout.strip().splitlines()[-1])
    port = _free_port()
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
                              cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if httpx.get(url + "/healthz", timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    else:
        server.kill()
        raise RuntimeError("the panel did not start")
    yield {"url": url, "secret": user["secret"], "codes": user["codes"]}
    server.terminate()
    server.wait(timeout=10)


def totp_now(secret: str) -> str:
    from app.auth import totp_at
    # Wait out the end of a 30 s step: a code about to expire could be one step behind on submit.
    if (left := 30 - time.time() % 30) < 3:
        time.sleep(left + 0.1)
    return totp_at(secret, int(time.time()) // 30)


@pytest.fixture(scope="session")
def session_state(panel, browser, tmp_path_factory):
    """Signs in once through the real form (each TOTP code works once) and keeps the cookies."""
    context = browser.new_context(viewport=DESKTOP, locale="es-ES")
    page = context.new_page()
    page.goto(panel["url"] + "/login")
    page.fill("#username", "prueba")
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url("**/login/codigo**")
    page.fill("#code", totp_now(panel["secret"]))
    page.click("form:not(details form) button[type=submit]")
    page.wait_for_url(panel["url"] + "/")
    path = tmp_path_factory.mktemp("state") / "state.json"
    context.storage_state(path=path)
    context.close()
    return path


@pytest.fixture(params=["desktop", "phone"])
def signed_in(request, browser, panel, session_state):
    """A signed-in page at desktop and at phone size; fails the test on any console error."""
    viewport = DESKTOP if request.param == "desktop" else PHONE
    context = browser.new_context(storage_state=session_state, viewport=viewport, locale="es-ES",
                                  is_mobile=request.param == "phone", has_touch=request.param == "phone")
    page = context.new_page()
    errors: list[str] = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.base = panel["url"]
    page.form_factor = request.param
    yield page
    context.close()
    assert not errors, errors
