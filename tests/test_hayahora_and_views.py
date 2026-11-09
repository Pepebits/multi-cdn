from app.config import Domain, Hostname
from app.signals.dnscheck import Resolution, classify
from app.signals.hayahora import parse_feed
from app.views import build_domain

FEED = {
    "lastUpdate": "2026-11-07 20:42:25Z",
    "data": [
        {"ip": "188.114.96.5", "isp": "Movistar", "description": "Cloudflare",
         "stateChanges": [{"timestamp": "2026-11-07 17:15:00Z", "state": True},
                          {"timestamp": "2026-11-07 17:52:00Z", "state": False},
                          {"timestamp": "2026-11-07 20:28:00Z", "state": True}]},
        {"ip": "188.114.96.5", "isp": "DIGI", "description": "Cloudflare",
         "stateChanges": [{"timestamp": "2026-11-07 17:15:00Z", "state": True},
                          {"timestamp": "2026-11-07 17:52:00Z", "state": False}]},
        {"ip": "104.16.0.1", "isp": "Movistar", "description": "Cloudflare",
         "stateChanges": [{"timestamp": "2026-11-07 20:00:00Z", "state": True}]},
        {"ip": "104.16.0.1", "isp": "Orange", "description": "Cloudflare",
         "stateChanges": [{"timestamp": "2026-11-07 20:00:00Z", "state": True}]},
        {"ip": "104.16.0.1", "isp": "Vodafone", "description": "Cloudflare",
         "stateChanges": [{"timestamp": "2026-11-07 20:00:00Z", "state": True}]},
    ],
}


def test_parse_uses_latest_state():
    snap = parse_feed(FEED)
    assert snap.state("188.114.96.5", "Movistar").blocked is True
    assert snap.state("188.114.96.5", "DIGI").blocked is False
    assert snap.blocked_ips(min_isps=3) == 1


def test_classify():
    cf = []
    import ipaddress
    cf = [ipaddress.ip_network("188.114.96.0/20")]
    assert classify(("188.114.96.5",), None, cf, {"192.0.2.10"}) == "cloudflare"
    assert classify(("192.0.2.10",), None, cf, {"192.0.2.10"}) == "origin"
    assert classify(("92.223.1.1",), "x.a.gcdn.co.", cf, set()) == "gcore"
    assert classify(("92.223.1.1",), "cl-test0001.gcorecdn.com.", cf, set()) == "gcore"
    assert classify((), None, cf, set()) == "unresolved"


def test_domain_view_flags_origin_exposure_and_isp_rows():
    domain = Domain(priority="critical", policy="preventive",
                    hostnames=[Hostname(name="example.com", server="vps-1"),
                               Hostname(name="www.example.com", server="vps-1")])
    res = {
        "example.com": Resolution("example.com", ("192.0.2.10",), None, "origin"),
        "www.example.com": Resolution("www.example.com", ("188.114.96.5",), None, "cloudflare"),
    }
    view = build_domain("example.com", domain, res, parse_feed(FEED))
    assert view.status == "origin"
    assert any("expuesto" in a for a in view.alerts)
    rows = {r.name: r.state for r in view.isp_rows}
    assert rows["Movistar"] == "blocked"
    assert rows["Digi"] == "free"
    assert rows["Orange"] == "nodata"
    assert not view.gcore_ready


def test_tunnel_hostname_is_labelled_and_warned():
    domain = Domain(hostnames=[Hostname(name="example.com", server="vps-1", origin_kind="tunnel",
                                        tunnel_target="abc.cfargotunnel.com")])
    res = {"example.com": Resolution("example.com", ("104.21.62.57",), None, "cloudflare")}
    view = build_domain("example.com", domain, res, None)
    assert view.hosts[0].provider_label == "Cloudflare Tunnel"
    assert "Cloudflare Tunnel" in view.hosts[0].dns_text
    assert any("Tunnel" in a and "Gcore" in a for a in view.alerts)


def test_excluded_hostnames_do_not_make_status_mixed():
    domain = Domain(hostnames=[Hostname(name="example.com", server="vps-1"),
                               Hostname(name="www.example.com", server="vps-1", failover=False)])
    res = {"example.com": Resolution("example.com", ("92.223.1.1",), "cl-x.gcorecdn.com.", "gcore"),
           "www.example.com": Resolution("www.example.com", ("188.114.96.5",), None, "cloudflare")}
    view = build_domain("example.com", domain, res, None)
    assert view.status == "gcore"
