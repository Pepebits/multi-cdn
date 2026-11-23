"""The Gcore adapter against an in-memory fake of its API: the real HTTP requests (paths, bodies,
headers) that preparing, renewing and deleting a domain send, and how errors come back."""

import asyncio
import json
from datetime import UTC, datetime

import httpx
import pytest

from app.providers import gcore


class FakeGcore:
    """Just enough of api.gcore.com/cdn: origin groups, certificates, resources, statistics."""

    def __init__(self):
        self.groups: dict[int, dict] = {}
        self.certs: dict[int, dict] = {}
        self.resources: dict[int, dict] = {}
        self.calls: list[tuple[str, str, dict | None]] = []
        self.fail: dict[tuple[str, str], int] = {}  # (method, path) -> status to answer
        self.next_id = 100

    def _new_id(self) -> int:
        self.next_id += 1
        return self.next_id

    def handler(self, request: httpx.Request) -> httpx.Response:
        method, path = request.method, request.url.path
        body = json.loads(request.content) if request.content else None
        self.calls.append((method, path, body))
        assert request.headers["Authorization"] == "APIKey gc-token"
        if (method, path) in self.fail:
            return httpx.Response(self.fail[(method, path)], text="denied")
        parts = path.strip("/").split("/")  # cdn/<kind>[/<id>]
        kind = parts[1]
        if kind == "clients":
            return httpx.Response(200, json={"cname": "cl-test.gcorecdn.com.", "max_objects_count": 30})
        if kind == "statistics":
            return self._stats(parts[2], request)
        store = {"origin_groups": self.groups, "sslData": self.certs, "resources": self.resources}[kind]
        if len(parts) == 2:
            if method == "GET":
                return httpx.Response(200, json=list(store.values()))
            item = {"id": self._new_id(), **body}
            store[item["id"]] = item
            return httpx.Response(201, json=item)
        item_id = int(parts[2])
        if item_id not in store:
            return httpx.Response(404, json={"error": "not found"})
        if method == "GET":
            return httpx.Response(200, json=store[item_id])
        if method == "PUT":
            store[item_id] |= body
            return httpx.Response(200, json=store[item_id])
        if method == "DELETE":
            if kind == "resources" and store[item_id].get("active", True):
                return httpx.Response(400, json={"error": "deactivate the resource first"})
            del store[item_id]
            return httpx.Response(204)
        raise AssertionError(f"unexpected {method} {path}")

    def _stats(self, which: str, request: httpx.Request) -> httpx.Response:
        params = request.url.params
        if which == "aggregate":
            if params.get("group_by") == "resource":
                return httpx.Response(200, json={"resource": {"33": {"metrics": {"total_bytes": 700}}}})
            values = {"total_bytes": 1000, "sent_bytes": 900, "upstream_bytes": 100}
            return httpx.Response(200, json={"metrics": {params["metrics"]: values[params["metrics"]]}})
        day = int(datetime(2026, 11, 20, tzinfo=UTC).timestamp())
        return httpx.Response(200, json={"resource": {"33": {"metrics": {"total_bytes": [[day, 5], [day + 86400, None]]}}}})


@pytest.fixture
def api(monkeypatch):
    fake = FakeGcore()
    transport = httpx.MockTransport(fake.handler)
    monkeypatch.setattr(gcore, "_client", lambda token: httpx.AsyncClient(
        base_url=gcore.API, transport=transport, headers={"Authorization": f"APIKey {token}"}))
    return fake


def run(coro):
    return asyncio.run(coro)


def test_origin_group_is_created_once_then_updated(api):
    first = run(gcore.ensure_origin_group("gc-token", "multicdn-vps-1", "192.0.2.10"))
    again = run(gcore.ensure_origin_group("gc-token", "multicdn-vps-1", "192.0.2.20"))
    assert first == again and len(api.groups) == 1
    assert api.groups[first]["sources"] == [{"source": "192.0.2.20:443", "enabled": True, "backup": False}]
    assert [c[0] for c in api.calls] == ["GET", "POST", "GET", "PUT"]


def test_same_certificate_name_is_not_uploaded_twice(api):
    a = run(gcore.upload_certificate("gc-token", "example.com-2026-11-20-ab12", "FC", "KEY"))
    b = run(gcore.upload_certificate("gc-token", "example.com-2026-11-20-ab12", "FC", "KEY"))
    assert a == b and len(api.certs) == 1
    assert api.certs[a]["validate_root_ca"] is True and api.certs[a]["sslPrivateKey"] == "KEY"


def test_resource_is_created_then_updated_without_changing_its_cname(api):
    payload = gcore.resource_payload("example.com", ["www.example.com"], 11, 22, "s3cret")
    rid = run(gcore.ensure_resource("gc-token", payload))
    assert run(gcore.ensure_resource("gc-token", payload | {"sslData": 23})) == rid
    put = next(body for method, _path, body in api.calls if method == "PUT")
    assert "cname" not in put and put["sslData"] == 23
    options = api.resources[rid]["options"]
    assert options["staticRequestHeaders"]["value"] == {"X-Origin-Auth": "s3cret"}
    assert options["edge_cache_settings"]["default"] == "0s"  # nothing cached unless the origin asks


def test_status_and_account_values(api):
    rid = run(gcore.ensure_resource("gc-token", gcore.resource_payload("example.com", [], 11, 22, "s")))
    api.resources[rid]["status"] = "processed"
    assert run(gcore.resource_status("gc-token", rid)) == "processed"
    assert run(gcore.account_cname("gc-token")) == "cl-test.gcorecdn.com"  # trailing dot removed
    assert run(gcore.account_limits("gc-token")) == {"resources": 1, "max_resources": 30}


def test_delete_resource_deactivates_it_first_and_tolerates_404(api):
    rid = run(gcore.ensure_resource("gc-token", gcore.resource_payload("example.com", [], 11, 22, "s")))
    run(gcore.delete_resource("gc-token", rid))
    assert rid not in api.resources
    put = next(body for method, path, body in api.calls if method == "PUT" and path.endswith(str(rid)))
    assert put == {"originGroup": 11, "active": False}
    run(gcore.delete_certificate("gc-token", 999))  # already gone: not an error


def test_rejected_calls_raise_with_what_failed(api):
    api.fail[("GET", "/cdn/resources")] = 403
    with pytest.raises(RuntimeError, match="HTTP 403"):
        run(gcore.ensure_resource("gc-token", gcore.resource_payload("example.com", [], 11, 22, "s")))
    api.fail[("DELETE", "/cdn/sslData/5")] = 500
    with pytest.raises(RuntimeError, match="HTTP 500"):
        run(gcore.delete_certificate("gc-token", 5))


def test_traffic_totals_and_daily_series(api):
    start, end = datetime(2026, 11, 1, tzinfo=UTC), datetime(2026, 11, 22, tzinfo=UTC)
    assert run(gcore.traffic("gc-token", start, end)) == {
        "total_bytes": 1000, "sent_bytes": 900, "upstream_bytes": 100, "by_resource": {33: 700}}
    series = run(gcore.traffic_series("gc-token", start, end))
    assert series == {33: [(datetime(2026, 11, 20, tzinfo=UTC), 5), (datetime(2026, 11, 21, tzinfo=UTC), 0)]}
