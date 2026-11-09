"""Cliente de pruebas autenticado: hace el login real (contraseña + TOTP) y añade el token CSRF."""

import time

import pytest
from fastapi.testclient import TestClient

from app.auth import totp_at

USER, PASSWORD = "admin", "contraseña-de-pruebas"


class AuthedClient:
    def __init__(self, client: TestClient):
        self._c = client

    def __getattr__(self, name):
        return getattr(self._c, name)

    @property
    def csrf(self) -> str:
        session = self._c.app.state.mc.auth.get_session(self._c.cookies.get("mcdn_session"))
        return session.csrf if session else ""

    def post(self, url, data=None, **kwargs):
        data = dict(data or {})
        data.setdefault("csrf", self.csrf)
        return self._c.post(url, data=data, **kwargs)


def login(client: TestClient, username: str = USER, password: str = PASSWORD) -> None:
    auth = client.app.state.mc.auth
    user = auth.get_user(username)
    if user is None:
        uid = auth.create_user(username, password)
        auth.start_totp_enrollment(uid)
        auth.enable_totp(uid)
        user = auth.get_user(username)
    r = client.post("/login", data={"username": username, "password": password, "next": "/"}, follow_redirects=False)
    assert r.headers["location"].startswith("/login/codigo"), r.text
    code = totp_at(auth.totp_secret(user.id), int(time.time()) // 30 - 1)  # deja libres los pasos actual y siguiente
    r = client.post("/login/codigo", data={"code": code, "next": "/"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/", r.text


@pytest.fixture(autouse=True)
def no_developer_env(monkeypatch):
    """Los tests nunca leen el .env del desarrollador (ni su IP de origen ni sus tokens)."""
    monkeypatch.setenv("MULTICDN_DOTENV", "/nonexistent/.env")


@pytest.fixture
def make_client(tmp_path, monkeypatch):
    clients = []

    def factory(**env):
        monkeypatch.setenv("MULTICDN_OFFLINE", "1")
        monkeypatch.setenv("MULTICDN_INVENTORY", "inventory.example.yaml")
        monkeypatch.setenv("MULTICDN_DB", str(tmp_path / "t.db"))
        monkeypatch.setenv("MULTICDN_DRY_RUN", "true")
        for var in ("CLOUDFLARE_API_TOKEN", "GCORE_API_TOKEN", "MULTICDN_SECRET_KEY", "ORIGIN_VPS1_IPV4",
                    "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
            monkeypatch.delenv(var, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        from app.main import app
        tc = TestClient(app)
        tc.__enter__()
        clients.append(tc)
        login(tc)
        return AuthedClient(tc)

    yield factory
    for tc in clients:
        tc.__exit__(None, None, None)


@pytest.fixture
def client(make_client):
    return make_client()


@pytest.fixture
def anon(tmp_path, monkeypatch):
    """Cliente sin sesión (para probar que todo exige login)."""
    monkeypatch.setenv("MULTICDN_OFFLINE", "1")
    monkeypatch.setenv("MULTICDN_INVENTORY", "inventory.example.yaml")
    monkeypatch.setenv("MULTICDN_DB", str(tmp_path / "anon.db"))
    monkeypatch.delenv("MULTICDN_SECRET_KEY", raising=False)
    from app.main import app
    with TestClient(app) as tc:
        yield tc
