"""Resolución DNS pública de cada hostname para saber qué CDN lo sirve realmente."""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPV6_URL = "https://www.cloudflare.com/ips-v6"
GCORE_SUFFIXES = (".gcorecdn.com.", ".gcdn.co.", ".gcorelabs.net.")  # cuentas actuales: cl-xxxx.gcorecdn.com
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8"]


@dataclass(frozen=True)
class Resolution:
    hostname: str
    ips: tuple[str, ...]
    cname: str | None
    provider: str  # cloudflare | gcore | origin | other | unresolved
    error: str | None = None


async def fetch_cloudflare_ranges(client: httpx.AsyncClient) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for url in (CLOUDFLARE_IPV4_URL, CLOUDFLARE_IPV6_URL):
        r = await client.get(url, timeout=15)
        r.raise_for_status()
        nets += [ipaddress.ip_network(line.strip()) for line in r.text.splitlines() if line.strip()]
    return nets


def classify(ips: tuple[str, ...], cname: str | None, cf_ranges, origin_ips: set[str]) -> str:
    if not ips:
        return "unresolved"
    if origin_ips & set(ips):
        return "origin"
    if cname and cname.endswith(GCORE_SUFFIXES):
        return "gcore"
    if cf_ranges and all(any(ipaddress.ip_address(ip) in net for net in cf_ranges) for ip in ips):
        return "cloudflare"
    return "other"


async def resolve(hostname: str, cf_ranges, origin_ips: set[str]) -> Resolution:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = PUBLIC_RESOLVERS
    resolver.lifetime = 5
    try:
        answer = await resolver.resolve(hostname, "A")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return Resolution(hostname, (), None, "unresolved", "sin registro A")
    except dns.exception.DNSException as exc:
        return Resolution(hostname, (), None, "unresolved", type(exc).__name__)
    ips = tuple(sorted(r.address for r in answer))
    canonical = str(answer.canonical_name)
    cname = canonical if canonical.rstrip(".") != hostname.rstrip(".") else None
    return Resolution(hostname, ips, cname, classify(ips, cname, cf_ranges, origin_ips))


async def resolve_all(hostnames: list[str], cf_ranges, origin_ips: set[str]) -> dict[str, Resolution]:
    results = await asyncio.gather(*(resolve(h, cf_ranges, origin_ips) for h in hostnames))
    return {r.hostname: r for r in results}
