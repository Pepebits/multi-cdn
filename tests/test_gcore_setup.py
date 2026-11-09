import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from app import certs, gcore_setup
from app.providers import gcore


def test_resource_payload_is_safe_for_dynamic_sites():
    p = gcore.resource_payload("example.com", ["www.example.com"], 7, 9, "s3cr3t")
    o = p["options"]
    assert p["originProtocol"] == "HTTPS" and p["sslEnabled"] and p["sslData"] == 9 and p["originGroup"] == 7
    assert o["edge_cache_settings"] == {"enabled": True, "default": "0s"}  # sin cabeceras de caché: no cachear
    assert "value" not in o["edge_cache_settings"]
    assert o["forward_host_header"]["value"] is True and "hostHeader" not in o  # incompatibles entre sí
    assert o["sni"]["sni_type"] == "dynamic"
    assert o["staticRequestHeaders"]["value"] == {"X-Origin-Auth": "s3cr3t"}
    assert o["ignore_cookie"]["value"] is False


@pytest.fixture
def client(make_client):
    return make_client(ORIGIN_VPS1_IPV4="192.0.2.10")


def _fake_backends(monkeypatch, calls):
    async def account_cname(token): return "cl-test.gcorecdn.com"
    async def ensure_origin_group(token, name, ip): calls["origin"] = (name, ip); return 11
    async def upload_certificate(token, name, fc, pk): calls["ssl"] = name; return 22
    async def ensure_resource(token, payload): calls["resource"] = payload; return 33
    async def probe_edge(edge, host): return True, f"{host}: HTTP 200"
    async def issue(cert_name, hostnames, cf_token, log):
        calls["cert_names"] = hostnames
        return certs.IssuedCert("FULLCHAIN", "KEY", datetime.now(UTC) + timedelta(days=90), hostnames)
    for mod, fn in ((gcore, account_cname), (gcore, ensure_origin_group), (gcore, upload_certificate),
                    (gcore, ensure_resource), (gcore, probe_edge), (certs, issue)):
        monkeypatch.setattr(mod, fn.__name__, fn)


def test_prepare_requires_credentials(client):
    state = client.app.state.mc
    job = gcore_setup.Job("example.com")
    asyncio.run(gcore_setup.prepare_domain(state, "example.com", job))
    assert job.done and not job.ok
    assert "Gcore" in job.lines[-1][1]


def test_prepare_domain_end_to_end_skips_tunnels(client, monkeypatch):
    calls = {}
    _fake_backends(monkeypatch, calls)
    state = client.app.state.mc
    cf_id = state.creds.add("cloudflare", "CF", "cf-token-123456")
    gc_id = state.creds.add("gcore", "GC", "gc-token-123456")
    state.store.set_credentials("example.com", cf_id, gc_id)
    state.store.upsert_hostname("example.com", "dev.example.com", server="vps-1")
    state.store.set_cloudflare_record("dev.example.com", "rec-dev", "tunnel", "x.cfargotunnel.com")
    state.reload()
    job = gcore_setup.Job("example.com")
    asyncio.run(gcore_setup.prepare_domain(state, "example.com", job))
    assert job.ok, job.lines
    assert calls["origin"] == ("multicdn-vps-1", "192.0.2.10")
    assert calls["cert_names"] == ["example.com", "www.example.com"]  # el túnel no entra en el certificado
    assert calls["resource"]["cname"] == "example.com" and calls["resource"]["secondaryHostnames"] == ["www.example.com"]
    d = state.inventory.domains["example.com"]
    assert d.gcore_resource_id == 33 and d.gcore_ssl_id == 22
    targets = {h.name: h.gcore_target for h in d.hostnames}
    assert targets == {"example.com": "cl-test.gcorecdn.com", "www.example.com": "cl-test.gcorecdn.com", "dev.example.com": None}
    # el secreto de cabecera se genera una vez y se reutiliza
    secret = calls["resource"]["options"]["staticRequestHeaders"]["value"]["X-Origin-Auth"]
    assert len(secret) >= 32 and gcore_setup.origin_secret(state.secrets) == secret
    page = client.get("/dominios/example.com").text
    assert "Preparado" in page and "cl-test.gcorecdn.com" in page and secret not in page


def test_prepare_route_starts_job(client, monkeypatch):
    calls = {}
    _fake_backends(monkeypatch, calls)
    r = client.post("/dominios/example.com/gcore/preparar", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("#gcore")
    assert "example.com" in client.app.state.mc.jobs
