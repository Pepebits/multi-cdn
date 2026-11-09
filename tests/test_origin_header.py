"""Regla de Cloudflare que añade X-Origin-Auth y su estado en la ficha del dominio."""

import asyncio
import json

import httpx
import pytest

from app.providers import cloudflare as cf

REAL_CLIENT = httpx.AsyncClient


def fake_cf(monkeypatch, entry=None, status=200):
    """entry: ruleset de la fase (None = no existe). Registra las llamadas."""
    calls = []

    def handler(request):
        body = json.loads(request.content) if request.content else None
        calls.append((request.method, request.url.path, body))
        if status == 403:
            return httpx.Response(403, json={"success": False, "errors": [{"message": "Authentication error"}]})
        if request.method == "GET":
            if entry is None:
                return httpx.Response(404, json={"success": False, "errors": [{"message": "could not find entrypoint"}]})
            return httpx.Response(200, json={"success": True, "result": entry})
        return httpx.Response(200, json={"success": True, "result": {}})
    monkeypatch.setattr(cf.httpx, "AsyncClient", lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw))
    return calls


def run(coro):
    return asyncio.run(coro)


def test_creates_the_phase_ruleset_when_missing(monkeypatch):
    calls = fake_cf(monkeypatch)
    assert run(cf.ensure_origin_header("t", "z1", "s3cret")) == "creada"
    method, path, body = calls[-1]
    assert method == "PUT" and path.endswith("/phases/http_request_late_transform/entrypoint")
    assert body["rules"][0]["action_parameters"]["headers"]["X-Origin-Auth"] == {"operation": "set", "value": "s3cret"}


def test_adds_its_rule_without_touching_others_and_is_idempotent(monkeypatch):
    other = {"id": "r0", "ref": "otra", "expression": "true", "action": "rewrite"}
    calls = fake_cf(monkeypatch, {"id": "rs1", "rules": [other]})
    assert run(cf.ensure_origin_header("t", "z1", "s3cret")) == "creada"
    assert calls[-1][0] == "POST" and calls[-1][1].endswith("/rulesets/rs1/rules")
    mine = cf.origin_rule("s3cret") | {"id": "r1"}
    calls = fake_cf(monkeypatch, {"id": "rs1", "rules": [other, mine]})
    assert run(cf.ensure_origin_header("t", "z1", "s3cret")) == "sin cambios" and len(calls) == 1
    assert run(cf.ensure_origin_header("t", "z1", "nuevo")) == "actualizada"
    assert calls[-1][0] == "PATCH" and calls[-1][1].endswith("/rulesets/rs1/rules/r1")
    assert run(cf.origin_header_status("t", "z1", "s3cret")) == "aplicada"
    assert run(cf.origin_header_status("t", "z1", "nuevo")) == "distinta"


def test_permission_error_explains_what_the_token_needs(monkeypatch):
    fake_cf(monkeypatch, status=403)
    with pytest.raises(RuntimeError, match="Transform Rules · Editar"):
        run(cf.ensure_origin_header("t", "z1", "s3cret"))


def test_domain_page_tracks_what_each_cdn_has_applied(client, monkeypatch):
    from app import gcore_setup
    state = client.app.state.mc
    cid = state.creds.add("cloudflare", "CF", "cf-token-123456")
    state.store.set_credentials("example.com", cid, None)
    state.reload()
    page = client.get("/dominios/example.com").text
    assert "Cabecera secreta hacia el origen" in page and "Sin aplicar" in page and "Sin preparar" in page

    async def ok(token, zone, secret):
        return "creada"
    monkeypatch.setattr(cf, "ensure_origin_header", ok)
    r = client.post("/dominios/example.com/origen/cloudflare", follow_redirects=True)
    assert "Regla de Cloudflare creada" in r.text and "Al día" in r.text
    gcore_setup.rotate_origin_secret(state.secrets, "cloudflare")
    assert "Secreto antiguo" in client.get("/dominios/example.com").text
