"""Hooks de certbot (--manual) para el reto DNS-01 con la API de Cloudflare.

certbot los ejecuta como `python -m app.acme_hook auth|cleanup`, con CERTBOT_DOMAIN y
CERTBOT_VALIDATION en el entorno. El token llega en MULTICDN_ACME_CF_TOKEN, en el entorno del
proceso: nunca se escribe en disco. Solo crea o borra registros TXT `_acme-challenge.<dominio>`.

Sustituye a certbot-dns-cloudflare, que arrastra el SDK de Cloudflare (~100 MB) para hacer
exactamente esto.
"""

from __future__ import annotations

import os
import sys
import time

import dns.exception
import dns.resolver
import httpx

API = "https://api.cloudflare.com/client/v4"
PROPAGATION_TIMEOUT = 120


def _client() -> httpx.Client:
    token = os.environ.get("MULTICDN_ACME_CF_TOKEN")
    if not token:
        sys.exit("acme_hook: MULTICDN_ACME_CF_TOKEN is missing")
    return httpx.Client(base_url=API, headers={"Authorization": f"Bearer {token}"}, timeout=20)


def _check(r: httpx.Response) -> dict:
    body = r.json()
    if not body.get("success"):
        msgs = "; ".join(e.get("message", "") for e in body.get("errors", [])) or f"HTTP {r.status_code}"
        sys.exit(f"acme_hook: Cloudflare rejected the request: {msgs}")
    return body


def zone_for(c: httpx.Client, domain: str) -> dict:
    """Zona de Cloudflare más específica que contiene el dominio."""
    zones = _check(c.get("/zones", params={"per_page": 50}))["result"]
    matches = [z for z in zones if domain == z["name"] or domain.endswith("." + z["name"])]
    if not matches:
        sys.exit(f"acme_hook: no zone of the token contains {domain}")
    return max(matches, key=lambda z: len(z["name"]))


def record_name(domain: str) -> str:
    return f"_acme-challenge.{domain.removeprefix('*.')}"


def _visible(name: str, value: str, nameservers: list[str]) -> bool:
    """¿Ven ya el TXT los servidores DNS de Cloudflare de la zona?"""
    resolver = dns.resolver.Resolver(configure=False)
    try:
        resolver.nameservers = [str(a) for ns in nameservers for a in dns.resolver.resolve(ns, "A")]
    except dns.exception.DNSException:
        return False
    resolver.lifetime = 5
    try:
        answer = resolver.resolve(name, "TXT")
    except dns.exception.DNSException:
        return False
    return any(value in b"".join(r.strings).decode() for r in answer)


def auth(domain: str, value: str) -> None:
    name = record_name(domain)
    with _client() as c:
        zone = zone_for(c, domain)
        _check(c.post(f"/zones/{zone['id']}/dns_records",
                      json={"type": "TXT", "name": name, "content": value, "ttl": 60,
                            "comment": "multi-cdn: ACME challenge, deleted when done"}))
    deadline = time.monotonic() + PROPAGATION_TIMEOUT
    while time.monotonic() < deadline:
        if _visible(name, value, zone.get("name_servers") or []):
            time.sleep(5)  # margen para el resto de servidores de la red de Cloudflare
            return
        time.sleep(5)
    sys.exit(f"acme_hook: the TXT of {name} is not visible on the zone's nameservers after {PROPAGATION_TIMEOUT} s")


def cleanup(domain: str, value: str) -> None:
    name = record_name(domain)
    with _client() as c:
        zone = zone_for(c, domain)
        records = _check(c.get(f"/zones/{zone['id']}/dns_records",
                               params={"type": "TXT", "name": name, "per_page": 50}))["result"]
        for r in records:
            if r.get("content", "").strip('"') == value:
                _check(c.delete(f"/zones/{zone['id']}/dns_records/{r['id']}"))


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("auth", "cleanup"):
        sys.exit("usage: python -m app.acme_hook auth|cleanup")
    domain, value = os.environ.get("CERTBOT_DOMAIN", ""), os.environ.get("CERTBOT_VALIDATION", "")
    if not domain or not value:
        sys.exit("acme_hook: CERTBOT_DOMAIN or CERTBOT_VALIDATION is missing (certbot runs it)")
    (auth if argv[1] == "auth" else cleanup)(domain, value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
