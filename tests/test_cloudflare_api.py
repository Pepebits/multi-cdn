"""The Cloudflare DNS writes and reads against a fake API: the exact PATCH a switch sends, the
origin guard running before any request, and reading records page by page."""

import asyncio
import functools
import json

import httpx
import pytest

from app.providers import cloudflare as cf

ORIGIN = "192.0.2.10"


@pytest.fixture
def api(monkeypatch):
    """Every httpx.AsyncClient the adapter opens talks to `handler`; requests are recorded."""
    state = {"requests": [], "answer": lambda request: httpx.Response(200, json={"success": True, "result": {}})}

    def handler(request):
        state["requests"].append(request)
        return state["answer"](request)
    monkeypatch.setattr(cf.httpx, "AsyncClient",
                        functools.partial(httpx.AsyncClient, transport=httpx.MockTransport(handler)))
    return state


def apply(change, dry_run=False, record_id="rec1"):
    dns = cf.CloudflareDNS("cf-token", {ORIGIN}, dry_run=dry_run)
    return asyncio.run(dns.apply("zone1", record_id, change))


def test_switch_to_gcore_sends_one_patch_with_an_unproxied_cname(api):
    assert apply(cf.plan_to_gcore("example.com", "cl-test.gcorecdn.com.")) == "aplicado"
    (request,) = api["requests"]
    assert request.method == "PATCH" and request.url.path == "/client/v4/zones/zone1/dns_records/rec1"
    assert request.headers["Authorization"] == "Bearer cf-token"
    assert json.loads(request.content) == {"type": "CNAME", "name": "example.com", "content": "cl-test.gcorecdn.com",
                                           "proxied": False, "ttl": 60}


def test_return_restores_the_proxied_a_record(api):
    apply(cf.plan_to_cloudflare("example.com", ORIGIN))
    body = json.loads(api["requests"][0].content)
    assert body["type"] == "A" and body["proxied"] is True and body["content"] == ORIGIN


def test_the_origin_guard_runs_before_any_request(api):
    exposed = cf.DnsChange("example.com", "A", ORIGIN, proxied=False, ttl=60)
    with pytest.raises(cf.OriginExposureError):
        apply(exposed)
    with pytest.raises(cf.OriginExposureError):
        apply(exposed, dry_run=True)  # not even simulated
    assert api["requests"] == []


def test_dry_run_and_missing_ids_send_nothing(api):
    change = cf.plan_to_gcore("example.com", "cl-test.gcorecdn.com")
    assert apply(change, dry_run=True) == "simulado"
    with pytest.raises(ValueError):
        apply(change, record_id=None)
    assert api["requests"] == []


def test_a_rejected_change_raises_with_cloudflare_errors(api):
    api["answer"] = lambda r: httpx.Response(400, json={"success": False, "errors": [{"code": 9005, "message": "bad"}]})
    with pytest.raises(RuntimeError, match="9005"):
        apply(cf.plan_to_gcore("example.com", "cl-test.gcorecdn.com"))


def test_web_records_are_read_page_by_page_without_keeping_the_origin_ip(api):
    pages = {
        "1": [{"id": "a", "name": "example.com", "type": "A", "content": ORIGIN, "proxied": True},
              {"id": "k", "name": "s1._domainkey.example.com", "type": "TXT", "content": "v=DKIM1"}],
        "2": [{"id": "w", "name": "www.example.com", "type": "CNAME", "content": "cl-test.gcorecdn.com", "proxied": False},
              {"id": "t", "name": "dev.example.com", "type": "CNAME", "content": "abc.cfargotunnel.com", "proxied": True}],
    }
    api["answer"] = lambda r: httpx.Response(200, json={
        "success": True, "result": pages[r.url.params["page"]], "result_info": {"total_pages": 2}})
    records = asyncio.run(cf.list_web_records("cf-token", "zone1"))
    by_name = {r["name"]: r for r in records}
    assert set(by_name) == {"example.com", "www.example.com", "dev.example.com"}
    assert by_name["example.com"]["origin_kind"] == "ip" and ORIGIN not in json.dumps(records)
    assert by_name["www.example.com"]["to_backup"] is True
    assert by_name["dev.example.com"]["origin_kind"] == "tunnel"
    assert [r.url.params["page"] for r in api["requests"]] == ["1", "2"]


def test_token_check_and_zone_list(api):
    api["answer"] = lambda r: httpx.Response(200, json={"success": True, "result": (
        {"status": "active"} if r.url.path.endswith("/verify") else
        [{"id": "z1", "name": "example.com", "status": "active", "extra": 1}])})
    assert asyncio.run(cf.verify_token("cf-token"))[0] is True
    assert asyncio.run(cf.list_zones("cf-token")) == [{"id": "z1", "name": "example.com", "status": "active"}]
    api["answer"] = lambda r: httpx.Response(403, json={"success": False, "errors": [{"message": "Invalid token"}]})
    assert asyncio.run(cf.verify_token("cf-token")) == (False, "Invalid token")
    with pytest.raises(RuntimeError, match="Invalid token"):
        asyncio.run(cf.list_zones("cf-token"))
