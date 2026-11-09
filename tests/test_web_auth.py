import re
import time

from fastapi.routing import APIRoute

from app.auth import totp_at
from tests.conftest import PASSWORD, USER


def _code(client, offset=1):
    auth = client.app.state.mc.auth
    return totp_at(auth.totp_secret(auth.get_user(USER).id), int(time.time()) // 30 + offset)


def test_every_route_requires_session(anon):
    public = ("/login", "/static", "/healthz")
    checked = 0
    for route in anon.app.routes:
        if not isinstance(route, APIRoute) or route.path.startswith(public):
            continue
        path = re.sub(r"\{[^}]+\}", "x", route.path)
        for method in route.methods:
            r = anon.request(method, path, follow_redirects=False)
            assert r.status_code in (303, 401), f"{method} {route.path} -> {r.status_code}"
            if path.startswith("/api/"):
                assert r.status_code == 401 and r.json()["error"]  # el sondeo recibe 401 en JSON
            elif method == "GET":
                assert r.headers["location"].startswith("/login?next=")
            checked += 1
    assert checked > 25


def test_no_users_shows_cli_instructions(anon):
    page = anon.get("/login").text
    assert "app.cli crear-usuario" in page and 'name="password"' not in page


def test_post_without_csrf_rejected(client):
    r = client._c.post("/ajustes/servidores", data={"server_id": "vps-9"})  # sin token
    assert r.status_code == 403
    r = client._c.post("/ajustes/servidores", data={"server_id": "vps-9", "csrf": "inventado"})
    assert r.status_code == 403
    assert client.post("/ajustes/servidores", data={"server_id": "vps-9"}).status_code == 200


def test_security_headers(client):
    r = client.get("/")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"
    assert "<script>" not in r.text  # sin scripts en línea
    cookie = client._c.cookies
    assert cookie.get("mcdn_session")


def test_next_cannot_redirect_outside(anon):
    anon.app.state.mc.auth.create_user("eve", "contraseña-de-pruebas")
    for evil in ("//evil.example", "https://evil.example", "/\\evil.example"):
        page = anon.get("/login", params={"next": evil}).text
        assert 'name="next" value="/"' in page


def test_lockout_after_failures_and_generic_message(anon):
    anon.app.state.mc.auth.create_user("daniel", "contraseña-de-pruebas")
    msgs = set()
    for _ in range(5):
        r = anon.post("/login", data={"username": "daniel", "password": "mala-contraseña-1"})
        msgs.add("incorrectos" in r.text)
    r_unknown = anon.post("/login", data={"username": "nadie", "password": "mala-contraseña-1"})
    assert "incorrectos" in r_unknown.text or "Demasiados" in r_unknown.text
    r = anon.post("/login", data={"username": "daniel", "password": "contraseña-de-pruebas"})
    assert "Demasiados intentos" in r.text  # bloqueado aunque ahora acierte


def test_enrollment_flow_with_qr_and_recovery(anon):
    auth = anon.app.state.mc.auth
    uid = auth.create_user("nuevo", "contraseña-de-pruebas")
    r = anon.post("/login", data={"username": "nuevo", "password": "contraseña-de-pruebas", "next": "/historial"},
                  follow_redirects=False)
    assert r.headers["location"].startswith("/login/alta")
    page = anon.get("/login/alta").text
    assert "<svg" in page
    secret = auth.totp_secret(uid)
    assert " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)) in page
    assert anon.get("/").status_code == 200 and "Iniciar sesión" in anon.get("/").text  # aún sin acceso
    r = anon.post("/login/alta", data={"code": "000000", "next": "/historial"}, follow_redirects=False)
    assert "error=" in r.headers["location"]
    r = anon.post("/login/alta", data={"code": totp_at(secret, int(time.time()) // 30), "next": "/historial"})
    codes = re.findall(r'<li class="mono">([a-z0-9]{5}-[a-z0-9]{5})</li>', r.text)
    assert len(codes) == 10
    assert anon.get("/historial").status_code == 200
    # cerrar sesión y entrar con un código de recuperación
    sess = auth.get_session(anon.cookies.get("mcdn_session"))
    anon.post("/logout", data={"csrf": sess.csrf})
    assert "Iniciar sesión" in anon.get("/").text
    anon.post("/login", data={"username": "nuevo", "password": "contraseña-de-pruebas"})
    r = anon.post("/login/codigo", data={"code": codes[0], "next": "/"}, follow_redirects=False)
    assert r.headers["location"] == "/"
    sess = auth.get_session(anon.cookies.get("mcdn_session"))
    anon.post("/logout", data={"csrf": sess.csrf})
    anon.post("/login", data={"username": "nuevo", "password": "contraseña-de-pruebas"})
    r = anon.post("/login/codigo", data={"code": codes[0], "next": "/"})
    assert "Código incorrecto" in r.text  # ya usado


def test_session_id_rotates_on_login(anon):
    auth = anon.app.state.mc.auth
    uid = auth.create_user("rot", "contraseña-de-pruebas")
    auth.start_totp_enrollment(uid)
    auth.enable_totp(uid)
    anon.post("/login", data={"username": "rot", "password": "contraseña-de-pruebas"})
    pending = anon.cookies.get("mcdn_session")
    anon.post("/login/codigo", data={"code": totp_at(auth.totp_secret(uid), int(time.time()) // 30)})
    assert anon.cookies.get("mcdn_session") != pending
    assert auth.get_session(pending) is None


def test_actor_is_session_user_not_header(client):
    client.post("/ajustes/servidores", data={"server_id": "vps-7"}, headers={"Tailscale-User-Login": "mallory"})
    ev = client.app.state.mc.events.list(limit=1)[0]
    assert ev.actor == USER


def test_change_password_closes_other_sessions(client, make_client):
    auth = client.app.state.mc.auth
    uid = auth.get_user(USER).id
    other = auth.create_session(uid, "full", "10.0.0.2", "otro")
    r = client.post("/ajustes/cuenta/password", data={"current": "mala", "code": _code(client, 0), "new": "x" * 12, "new2": "x" * 12},
                    follow_redirects=False)
    assert "error=" in r.headers["location"]
    r = client.post("/ajustes/cuenta/password", data={"current": PASSWORD, "code": _code(client, 1),
                                                     "new": "nueva-contraseña-123", "new2": "nueva-contraseña-123"},
                    follow_redirects=False)
    assert "ok=" in r.headers["location"], r.headers["location"]
    assert auth.get_session(other) is None
    assert client.get("/ajustes/cuenta").status_code == 200  # la actual sigue
    assert auth.check_password(USER, "nueva-contraseña-123")


def test_account_page_lists_and_revokes_sessions(client):
    auth = client.app.state.mc.auth
    uid = auth.get_user(USER).id
    auth.create_session(uid, "full", "10.0.0.9", "Firefox")
    page = client.get("/ajustes/cuenta").text
    assert "Esta sesión" in page and "10.0.0.9" in page
    other = [s for s in auth.list_sessions(uid) if s.ip == "10.0.0.9"][0]
    client.post(f"/ajustes/cuenta/sesiones/{other.id_hash}/cerrar")
    assert all(s.ip != "10.0.0.9" for s in auth.list_sessions(uid))


def test_cli_create_and_reset(tmp_path, monkeypatch, capsys):
    from app import cli
    monkeypatch.setenv("MULTICDN_DB", str(tmp_path / "cli.db"))
    monkeypatch.delenv("MULTICDN_SECRET_KEY", raising=False)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "contraseña-cli-123")
    assert cli.main(["crear-usuario", "Ana"]) == 0
    assert cli.main(["listar-usuarios"]) == 0
    assert "ana\tTOTP pendiente" in capsys.readouterr().out
    assert cli.main(["reiniciar-totp", "ana"]) == 0
    assert cli.main(["cambiar-password", "nadie"]) == 1


def test_polling_does_not_extend_session(client):
    from datetime import UTC, datetime, timedelta
    auth = client.app.state.mc.auth
    token = client._c.cookies.get("mcdn_session")
    old = (datetime.now(UTC) - timedelta(minutes=10)).isoformat(timespec="seconds")
    auth.conn.execute("UPDATE sessions SET last_seen=?", (old,))
    v = client.get("/api/estado").json()["version"]
    assert v and len(v) == 16
    assert auth.conn.execute("SELECT last_seen FROM sessions").fetchone()[0] == old  # no renovada
    client.get("/")
    assert auth.conn.execute("SELECT last_seen FROM sessions").fetchone()[0] != old  # navegar sí la renueva
    assert token
