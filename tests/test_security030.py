"""Login and panel hardening of 0.3.0: client IP behind proxies (ADR-004), code attempts inside
a session, `next` with control characters, the external heartbeat URL and the Gcore certificate name."""

import asyncio
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from starlette.requests import Request

from app import auth as auth_mod
from app import certs, gcore_setup, heartbeat, proxy
from app.auth import totp_at
from app.providers import gcore
from tests.conftest import PASSWORD, USER


def _code(client, offset=1):
    a = client.app.state.mc.auth
    return totp_at(a.totp_secret(a.get_user(USER).id), int(time.time()) // 30 + offset)


# ---------------------------------------------------------------- client IP and scheme (6a)

def _request(peer="198.51.100.1", **headers):
    raw = [(k.replace("_", "-").lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": raw, "client": (peer, 1234)})


def test_client_ip_ignores_forwarded_for_by_default(monkeypatch):
    monkeypatch.delenv("MULTICDN_TRUSTED_PROXIES", raising=False)
    assert proxy.client_ip(_request(x_forwarded_for="203.0.113.9")) == "198.51.100.1"


def test_client_ip_with_one_trusted_proxy_takes_the_right_most_entry(monkeypatch):
    monkeypatch.setenv("MULTICDN_TRUSTED_PROXIES", "1")
    assert proxy.client_ip(_request(x_forwarded_for="203.0.113.66, 203.0.113.9")) == "203.0.113.9"
    assert proxy.client_ip(_request(x_forwarded_for="[2001:db8::5]:4433")) == "2001:db8::5"
    assert proxy.client_ip(_request(x_forwarded_for="203.0.113.66, not-an-ip")) == "198.51.100.1"  # never the left one
    assert proxy.client_ip(_request(x_forwarded_for="evil\ninjected")) == "198.51.100.1"
    assert proxy.client_ip(_request()) == "198.51.100.1"


def test_fake_forwarded_for_still_gets_locked(anon):
    anon.app.state.mc.auth.create_user("daniel", PASSWORD)
    for i in range(5):  # different users, so only the IP key can lock
        anon.post("/login", data={"username": f"user{i}", "password": "mala-contraseña-1"},
                  headers={"X-Forwarded-For": f"203.0.113.{i}"})
    r = anon.post("/login", data={"username": "daniel", "password": PASSWORD}, headers={"X-Forwarded-For": "203.0.113.200"})
    assert "Demasiados intentos" in r.text
    summaries = " ".join(e.summary for e in anon.app.state.mc.events.list(limit=20))
    assert "203.0.113." not in summaries


def test_trusted_proxy_ip_is_recorded(make_client, monkeypatch):
    monkeypatch.setenv("MULTICDN_TRUSTED_PROXIES", "1")
    client = make_client()
    client.post("/logout")
    client._c.post("/login", data={"username": USER, "password": PASSWORD}, headers={"X-Forwarded-For": "203.0.113.7"})
    client._c.post("/login/codigo", data={"code": _code(client, 0)}, headers={"X-Forwarded-For": "203.0.113.7"})
    assert client.app.state.mc.events.list(limit=1)[0].summary.endswith("203.0.113.7")


def test_forwarded_proto_https_gives_https_redirects_and_secure_cookie(anon):
    a = anon.app.state.mc.auth
    uid = a.create_user("ana", PASSWORD)
    a.start_totp_enrollment(uid)
    a.enable_totp(uid)
    r = anon.post("/login", data={"username": "ana", "password": PASSWORD}, headers={"X-Forwarded-Proto": "https"},
                  follow_redirects=False)
    assert "secure" in r.headers["set-cookie"].lower()
    r = anon.get("/lang/es", headers={"X-Forwarded-Proto": "https"}, follow_redirects=False)
    assert "secure" in r.headers["set-cookie"].lower()
    r = anon.get("/lang/es", headers={"X-Forwarded-Proto": "gopher"}, follow_redirects=False)
    assert "secure" not in r.headers["set-cookie"].lower()


def test_forwarded_proto_https_in_url_for(client):
    r = client.post("/dominios", data={"name": "example.org", "server": "vps-1"}, headers={"X-Forwarded-Proto": "https"},
                    follow_redirects=False)
    assert r.headers["location"].startswith("https://testserver/")
    r = client.post("/dominios", data={"name": "example.info", "server": "vps-1"}, follow_redirects=False)
    assert r.headers["location"].startswith("http://testserver/")


# ---------------------------------------------------------------- code attempts in a session (6b)

def _assert_locked_out(client, r, token):
    assert r.status_code == 303 and r.headers["location"].startswith("/login?error=")
    assert client.app.state.mc.auth.get_session(token) is None
    assert 'mcdn_session=""' in r.headers.get("set-cookie", "") or "Max-Age=0" in r.headers.get("set-cookie", "")
    assert any("Acceso bloqueado" in e.summary for e in client.app.state.mc.events.list(limit=10))


def test_enrollment_code_attempts_are_limited(anon):
    anon.app.state.mc.auth.create_user("nuevo", PASSWORD)
    anon.post("/login", data={"username": "nuevo", "password": PASSWORD})
    token = anon.cookies.get("mcdn_session")
    for _ in range(4):
        r = anon.post("/login/alta", data={"code": "000000"}, follow_redirects=False)
        assert r.headers["location"].startswith("/login/alta?error=")
    r = anon.post("/login/alta", data={"code": "000000"}, follow_redirects=False)
    _assert_locked_out(anon, r, token)


@pytest.mark.parametrize("route", ["password", "recuperacion"])
def test_account_code_attempts_are_limited(client, route):
    token = client._c.cookies.get("mcdn_session")
    data = {"current": PASSWORD, "code": "000000", "new": "x" * 14, "new2": "x" * 14}
    for _ in range(4):
        r = client.post(f"/ajustes/cuenta/{route}", data=data, follow_redirects=False)
        assert "error=" in r.headers["location"]
    r = client.post(f"/ajustes/cuenta/{route}", data=data, follow_redirects=False)
    _assert_locked_out(client, r, token)


def test_correct_code_resets_the_counter(client):
    for _ in range(4):
        client.post("/ajustes/cuenta/recuperacion", data={"code": "000000"}, follow_redirects=False)
    r = client.post("/ajustes/cuenta/recuperacion", data={"code": _code(client, 1)}, follow_redirects=False)
    assert r.status_code == 200
    r = client.post("/ajustes/cuenta/recuperacion", data={"code": "000000"}, follow_redirects=False)
    assert "error=" in r.headers["location"]  # counting again from zero


def test_enroll_session_expires(anon, monkeypatch):
    anon.app.state.mc.auth.create_user("nuevo", PASSWORD)
    anon.post("/login", data={"username": "nuevo", "password": PASSWORD})
    assert anon.get("/login/alta").status_code == 200
    later = datetime.now(UTC) + auth_mod.PENDING_TIMEOUT + timedelta(seconds=5)
    monkeypatch.setattr(auth_mod, "_now", lambda: later)
    r = anon.get("/login/alta", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


# ---------------------------------------------------------------- next (6c)

def test_next_with_control_characters_goes_home(anon):
    anon.app.state.mc.auth.create_user("eve", PASSWORD)
    for evil in ("/\t/evil.example", "/\n/evil.example", "/\r/evil.example", "/x\x7f", "/\x00"):
        assert 'name="next" value="/"' in anon.get("/login", params={"next": evil}).text
    assert 'name="next" value="/historial"' in anon.get("/login", params={"next": "/historial"}).text


# ---------------------------------------------------------------- heartbeat URL (6d)

@pytest.mark.parametrize("url", [
    "https://hc.example.com/ping/abc", "https://hc.example.com:443/abc", "https://hc.example.com./abc"])
def test_heartbeat_url_accepted(url):
    assert heartbeat.valid_url(url)


@pytest.mark.parametrize("url", [
    "http://hc.example.com/abc", "https://192.0.2.1/abc", "https://[2001:db8::1]/abc", "https://localhost/abc",
    "https://box.local/abc", "https://metadata.internal/abc", "https://app.localhost/abc", "https://intranet/abc",
    "https://user:pw@hc.example.com/abc", "https://user@hc.example.com/abc", "https://hc.example.com:8443/abc",
    "https://hc.example.com/a b", "https://hc.example.com/a\tb", "https://hc.example.com/\x7f",
    "https://hc.example.com\\@192.0.2.1/", "https://127.1/abc", "https://0x7f.1/abc", "https://hc.example.com:abc/",
    "https://hc.example.com/" + "a" * 300, ""])
def test_heartbeat_url_rejected(url):
    assert not heartbeat.valid_url(url)


def _resolver(*ips):
    async def resolve(host):
        return list(ips)
    return resolve


def test_host_is_public(monkeypatch):
    run = asyncio.run
    for ips in (["127.0.0.1"], ["10.0.0.5"], ["169.254.169.254"], ["100.64.0.1"], ["::1"], ["fe80::1"],
                ["::ffff:127.0.0.1"], ["0.0.0.0"], ["240.0.0.1"], ["224.0.0.1"], ["192.0.2.1"], []):
        assert not run(heartbeat.host_is_public("hc.example.com", resolver=_resolver(*ips))), ips

    async def fails(host):
        raise OSError("no such host")
    assert not run(heartbeat.host_is_public("hc.example.com", resolver=fails))
    # Documentation ranges stand in for public addresses here (tests never use real ones).
    real = heartbeat.is_public_address
    doc = __import__("ipaddress").ip_network("203.0.113.0/24")
    monkeypatch.setattr(heartbeat, "is_public_address", lambda ip: ip in doc or real(ip))
    assert run(heartbeat.host_is_public("hc.example.com", resolver=_resolver("203.0.113.20")))
    assert not run(heartbeat.host_is_public("hc.example.com", ["203.0.113.20"], resolver=_resolver("203.0.113.20")))
    assert not run(heartbeat.host_is_public("hc.example.com", resolver=_resolver("203.0.113.20", "10.0.0.1")))


def test_heartbeat_save_checks_the_host_when_online(client, monkeypatch):
    calls = []

    async def not_public(host, origin_ips=(), resolver=None):
        calls.append(host)
        return False
    monkeypatch.setattr(heartbeat, "host_is_public", not_public)
    monkeypatch.delenv("MULTICDN_OFFLINE")
    r = client.post("/ajustes/notificaciones/latido", data={"heartbeat_url": "https://hc.example.com/abc"},
                    headers={"Origin": "http://testserver"}, follow_redirects=True)
    assert calls == ["hc.example.com"] and "no resuelve a una dirección pública" in r.text
    assert client.app.state.mc.secrets.get("heartbeat_url") is None


def test_beat_does_not_follow_redirects(client):
    state = client.app.state.mc
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://10.0.0.1/"})
    state.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)
    state.secrets.set("heartbeat_url", "https://hc.example.com/abc")
    b = asyncio.run(heartbeat.beat(state))
    assert seen == ["https://hc.example.com/abc" + ("" if b.ok else "/fail")] and b.result == "HTTP 302"


# ---------------------------------------------------------------- Gcore certificate name (8b)

def _cert(fullchain, not_after=datetime(2027, 2, 1, tzinfo=UTC)):
    return certs.IssuedCert(fullchain, "KEY", not_after, ["example.com"])


def test_certificate_name_includes_date_and_chain_hash():
    a, b = gcore_setup.certificate_name("example.com", _cert("CHAIN-A")), gcore_setup.certificate_name("example.com", _cert("CHAIN-B"))
    assert a.startswith("multicdn-example.com-20270201-") and len(a.rsplit("-", 1)[1]) == 8
    assert a != b and a == gcore_setup.certificate_name("example.com", _cert("CHAIN-A"))


def test_same_certificate_is_reused_and_a_new_one_uploaded(monkeypatch):
    stored, posts = [], []

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json=stored)
        body = __import__("json").loads(request.content)
        posts.append(body["name"])
        stored.append({"id": 100 + len(stored), "name": body["name"]})
        return httpx.Response(201, json=stored[-1])
    monkeypatch.setattr(gcore, "_client", lambda token: httpx.AsyncClient(
        base_url=gcore.API, transport=httpx.MockTransport(handler)))

    def upload(chain):
        cert = _cert(chain)
        return asyncio.run(gcore.upload_certificate("t", gcore_setup.certificate_name("example.com", cert), chain, "KEY"))
    first = upload("CHAIN-A")
    assert upload("CHAIN-A") == first and len(posts) == 1    # retried preparation: same certificate
    second = upload("CHAIN-B")                               # re-issued the same day: uploaded
    assert second != first and len(posts) == 2
