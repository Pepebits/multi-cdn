"""What the engine checks before (and, since 0.3.6, while) serving from Gcore: public DNS
classification, the HTTPS probe of each Gcore edge and check_backup, without the network."""

import asyncio
import ipaddress
import ssl
from datetime import UTC, datetime

import dns.exception
import dns.resolver
import pytest

from app.engine import failover
from app.providers import gcore
from app.signals import dnscheck
from app.signals.hayahora import parse_feed

CF = [ipaddress.ip_network("104.16.0.0/13")]


# ---------------------------------------------------------------- public DNS

@pytest.mark.parametrize("ips, cname, expected", [
    ((), None, "unresolved"),
    (("192.0.2.10",), None, "origin"),                        # the origin IP: never allowed
    (("5.188.126.61",), "cl-test.gcorecdn.com.", "gcore"),
    (("104.16.1.1", "104.17.2.2"), None, "cloudflare"),
    (("104.16.1.1", "198.51.100.7"), None, "other"),         # only partly Cloudflare
])
def test_classify(ips, cname, expected):
    assert dnscheck.classify(ips, cname, CF, {"192.0.2.10"}) == expected


class Answer(list):
    def __init__(self, ips, canonical):
        super().__init__(type("R", (), {"address": ip})() for ip in ips)
        self.canonical_name = canonical


def test_resolve_reads_the_cname_and_reports_failures(monkeypatch):
    answers = {
        "www.example.com": Answer(["5.188.126.61"], "cl-test.gcorecdn.com."),
        "example.com": Answer(["104.16.1.1"], "example.com."),
    }

    async def fake_resolve(self, name, rdtype):
        if name == "gone.example.com":
            raise dns.resolver.NXDOMAIN
        if name == "slow.example.com":
            raise dns.exception.Timeout
        return answers[name]
    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)
    out = asyncio.run(dnscheck.resolve_all(["www.example.com", "example.com", "gone.example.com", "slow.example.com"],
                                           CF, set()))
    assert out["www.example.com"].provider == "gcore" and out["www.example.com"].cname == "cl-test.gcorecdn.com."
    assert out["example.com"].provider == "cloudflare" and out["example.com"].cname is None
    assert out["gone.example.com"].error == "no A record"
    assert out["slow.example.com"].provider == "unresolved" and out["slow.example.com"].error == "Timeout"


# ---------------------------------------------------------------- HTTPS probe of the Gcore edge

class FakeWriter:
    def __init__(self):
        self.sent = b""

    def get_extra_info(self, key):
        return {"notAfter": "Feb 18 12:00:00 2027 GMT"} if key == "peercert" else None

    def write(self, data):
        self.sent += data

    async def drain(self):
        pass

    def close(self):
        pass


class FakeReader:
    def __init__(self, status_line: bytes):
        self.status_line = status_line

    async def readline(self):
        return self.status_line


def edge(monkeypatch, behaviour: dict[str, object]):
    """getaddrinfo answers with the keys of `behaviour`; connecting to each IP returns the status
    line given (bytes) or raises the exception given."""
    tried = []

    async def getaddrinfo(self, host, port, **kw):
        return [(None, None, None, "", (ip, port)) for ip in behaviour]

    async def open_connection(ip, port, ssl=None, server_hostname=None):
        tried.append((ip, server_hostname))
        result = behaviour[ip]
        if isinstance(result, Exception):
            raise result
        writer = FakeWriter()
        return FakeReader(result), writer
    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(asyncio, "open_connection", open_connection)
    return tried


def test_probe_edge_ok_uses_the_real_hostname_as_sni(monkeypatch):
    tried = edge(monkeypatch, {"5.188.126.61": b"HTTP/1.1 200 OK\r\n"})
    ok, detail = asyncio.run(gcore.probe_edge("cl-test.gcorecdn.com", "example.com"))
    assert ok and "HTTP 200" in detail and "5.188.126.61" in detail
    assert tried == [("5.188.126.61", "example.com")]


def test_probe_edge_prefers_ipv4_and_falls_back(monkeypatch):
    tried = edge(monkeypatch, {"2001:db8::1": b"HTTP/1.1 200 OK\r\n", "5.188.126.61": ConnectionRefusedError(),
                               "5.188.126.62": b"HTTP/1.1 200 OK\r\n"})
    ok, _ = asyncio.run(gcore.probe_edge("cl-test.gcorecdn.com", "example.com"))
    assert ok and [ip for ip, _ in tried] == ["5.188.126.61", "5.188.126.62"]


CERT_ERROR = ssl.SSLCertVerificationError(1, "certificate verify failed")
CERT_ERROR.verify_message = "certificate has expired"  # set by the ssl module on a real handshake


@pytest.mark.parametrize("result, ok, words", [
    (b"HTTP/1.1 503 Service Unavailable\r\n", False, "HTTP 503"),
    (CERT_ERROR, False, "certificate has expired"),
    (ConnectionRefusedError(), False, "ConnectionRefusedError"),
])
def test_probe_edge_failures(monkeypatch, result, ok, words):
    edge(monkeypatch, {"5.188.126.61": result})
    got_ok, detail = asyncio.run(gcore.probe_edge("cl-test.gcorecdn.com", "example.com"))
    assert got_ok is ok and words in detail


def test_probe_all_edges_fails_if_any_point_of_presence_fails(monkeypatch):
    async def ipv4s(edge_host):
        return ["5.188.126.61", "5.188.126.62"]

    async def probe(ip, host, timeout=15):
        return (ip != "5.188.126.62"), f"{host} via {ip}"
    monkeypatch.setattr(gcore, "edge_ipv4s", ipv4s)
    monkeypatch.setattr(gcore, "probe_edge", probe)
    assert asyncio.run(gcore.probe_all_edges("cl-test.gcorecdn.com", "example.com")) == (False, "example.com via 5.188.126.62")


# ---------------------------------------------------------------- check_backup

@pytest.fixture
def ready(client, monkeypatch):
    """example.com prepared on Gcore; every check passes unless a test changes `result`."""
    state = client.app.state.mc
    gc = state.creds.add("gcore", "GC", "gc-token-123456")
    state.store.set_credentials("example.com", None, gc)
    state.store.set_gcore("example.com", 33, 22, datetime(2027, 2, 1, tzinfo=UTC).isoformat(),
                          "cl-test.gcorecdn.com", ["example.com", "www.example.com"])
    state.reload()
    result = {"status": "active", "ips": ["5.188.126.61"], "probe": (True, "ok")}

    async def status(token, rid):
        return result["status"]

    async def ipv4s(edge_host):
        return result["ips"]

    async def probe(edge_host, host, timeout=15):
        return result["probe"]
    monkeypatch.setattr(gcore, "resource_status", status)
    monkeypatch.setattr(gcore, "edge_ipv4s", ipv4s)
    monkeypatch.setattr(gcore, "probe_all_edges", probe)
    state.check = result
    return state


def check(state):
    return asyncio.run(failover.check_backup(state, "example.com"))


def test_check_backup_passes_when_everything_answers(ready):
    assert check(ready) is None


def test_check_backup_reasons(ready):
    ready.check["status"] = "processed"
    assert "processed" in check(ready)
    ready.check["status"] = "active"
    ready.check["ips"] = []
    assert "cl-test.gcorecdn.com" in check(ready)
    ready.check["ips"] = ["5.188.126.61"]
    ready.check["probe"] = (False, "example.com: HTTP 502 via Gcore")
    assert check(ready) == "example.com: HTTP 502 via Gcore"


def test_check_backup_refuses_a_blocked_edge(ready):
    ts = "2026-11-22 18:00:00Z"
    ready.feed = parse_feed({"lastUpdate": ts, "data": [{"ip": "5.188.126.61", "isp": "Movistar", "description": "Gcore",
                                                         "stateChanges": [{"timestamp": ts, "state": True}]}]})
    reason = check(ready)
    assert "5.188.126.61" in reason and "Movistar" in reason
