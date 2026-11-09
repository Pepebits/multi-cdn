"""Hooks de certbot para el reto DNS-01 (sin el SDK de Cloudflare)."""

import json

import httpx
import pytest

from app import acme_hook

ZONES = [{"id": "z1", "name": "example.com", "name_servers": []}, {"id": "z2", "name": "sub.example.com", "name_servers": []}]


def fake_api(monkeypatch, txt_records=()):
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path, json.loads(request.content) if request.content else None))
        if request.url.path.endswith("/zones"):
            return httpx.Response(200, json={"success": True, "result": ZONES})
        if request.method == "GET":
            return httpx.Response(200, json={"success": True, "result": list(txt_records)})
        return httpx.Response(200, json={"success": True, "result": {}})
    monkeypatch.setenv("MULTICDN_ACME_CF_TOKEN", "t")
    monkeypatch.setattr(acme_hook, "_client", lambda: httpx.Client(base_url=acme_hook.API, transport=httpx.MockTransport(handler)))
    return calls


def test_record_name_and_most_specific_zone(monkeypatch):
    fake_api(monkeypatch)
    assert acme_hook.record_name("*.example.com") == "_acme-challenge.example.com"
    with acme_hook._client() as c:
        assert acme_hook.zone_for(c, "www.sub.example.com")["id"] == "z2"
        assert acme_hook.zone_for(c, "example.com")["id"] == "z1"
        with pytest.raises(SystemExit):
            acme_hook.zone_for(c, "otro.net")


def test_auth_creates_txt_and_waits_until_visible(monkeypatch):
    calls = fake_api(monkeypatch)
    monkeypatch.setattr(acme_hook, "_visible", lambda name, value, ns: True)
    monkeypatch.setattr(acme_hook.time, "sleep", lambda s: None)
    acme_hook.auth("www.example.com", "token-reto")
    method, path, body = calls[-1]
    assert method == "POST" and path.endswith("/zones/z1/dns_records")
    assert body["type"] == "TXT" and body["name"] == "_acme-challenge.www.example.com" and body["content"] == "token-reto"


def test_cleanup_deletes_only_its_own_value(monkeypatch):
    calls = fake_api(monkeypatch, [{"id": "r1", "content": '"token-reto"'}, {"id": "r2", "content": "otro-reto"}])
    acme_hook.cleanup("example.com", "token-reto")
    deletes = [p for m, p, _ in calls if m == "DELETE"]
    assert deletes == ["/client/v4/zones/z1/dns_records/r1"]


def test_main_requires_certbot_environment(monkeypatch):
    monkeypatch.delenv("CERTBOT_DOMAIN", raising=False)
    with pytest.raises(SystemExit, match="certbot runs it"):
        acme_hook.main(["x", "auth"])
