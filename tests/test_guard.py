import asyncio

import pytest

from app.providers.cloudflare import (
    CloudflareDNS,
    DnsChange,
    OriginExposureError,
    guard,
    plan_to_cloudflare,
    plan_to_gcore,
)

ORIGIN = {"192.0.2.10"}


def test_switch_to_gcore_is_allowed():
    guard(plan_to_gcore("example.com", "example-com.a.gcdn.co."), ORIGIN)


def test_restore_proxied_origin_is_allowed():
    guard(plan_to_cloudflare("example.com", "192.0.2.10"), ORIGIN)


@pytest.mark.parametrize(
    "change",
    [
        DnsChange("example.com", "A", "192.0.2.10", proxied=False, ttl=60),  # proxy off: origen expuesto
        DnsChange("example.com", "AAAA", "2001:db8::1", proxied=False, ttl=60),
        DnsChange("example.com", "A", "198.51.100.7", proxied=False, ttl=60),  # cualquier A sin proxy
        DnsChange("example.com", "CNAME", "192.0.2.10", proxied=False, ttl=60),
        DnsChange("example.com", "CNAME", "example-com.a.gcdn.co", proxied=True, ttl=1),
        DnsChange("example.com", "TXT", "hola", proxied=False, ttl=60),
    ],
)
def test_exposing_changes_are_rejected(change):
    with pytest.raises(OriginExposureError):
        guard(change, ORIGIN)


def test_guard_runs_even_in_dry_run():
    cf = CloudflareDNS(token=None, origin_ips=ORIGIN, dry_run=True)
    bad = DnsChange("example.com", "A", "192.0.2.10", proxied=False, ttl=60)
    with pytest.raises(OriginExposureError):
        asyncio.run(cf.apply("zone", "rec", bad))


def test_no_token_forces_dry_run():
    cf = CloudflareDNS(token=None, origin_ips=ORIGIN, dry_run=False)
    assert cf.dry_run
    assert asyncio.run(cf.apply(None, None, plan_to_gcore("example.com", "x.a.gcdn.co"))) == "simulado"


def test_tunnel_restore_is_allowed_only_proxied():
    from app.providers.cloudflare import plan_to_tunnel
    guard(plan_to_tunnel("example.com", "0b1c2d3e-aaaa-bbbb-cccc-111122223333.cfargotunnel.com"), ORIGIN)
    with pytest.raises(OriginExposureError):
        guard(DnsChange("example.com", "CNAME", "abc.cfargotunnel.com", proxied=False, ttl=60), ORIGIN)
    # restaurar un CNAME original con proxy está permitido
    guard(DnsChange("www.example.com", "CNAME", "example.com", proxied=True, ttl=1), ORIGIN)
    with pytest.raises(OriginExposureError):  # sin proxy solo hacia el CDN de respaldo
        guard(DnsChange("www.example.com", "CNAME", "origin.example.com", proxied=False, ttl=60), ORIGIN)
    with pytest.raises(OriginExposureError):  # al CDN de respaldo nunca con proxy
        guard(DnsChange("www.example.com", "CNAME", "cl-x.gcorecdn.com", proxied=True, ttl=1), ORIGIN)


def test_plan_restore_by_origin_kind():
    from app.config import Hostname
    from app.providers.cloudflare import plan_restore
    ip = plan_restore(Hostname(name="example.com", server="v", origin_kind="ip"), "192.0.2.10")
    assert (ip.type, ip.content, ip.proxied) == ("A", "192.0.2.10", True)
    tun = plan_restore(Hostname(name="dev.example.com", server="v", origin_kind="tunnel", tunnel_target="t.cfargotunnel.com"), None)
    assert (tun.type, tun.proxied) == ("CNAME", True)
    cn = plan_restore(Hostname(name="www.example.com", server="v", origin_kind="cname", cname_target="example.com"), None)
    assert (cn.content, cn.proxied) == ("example.com", True)
    with pytest.raises(ValueError):
        plan_restore(Hostname(name="www.example.com", server="v", origin_kind="cname"), None)
    for change in (ip, tun, cn):
        guard(change, {"192.0.2.10"})
