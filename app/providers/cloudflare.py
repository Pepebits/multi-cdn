"""Adaptador DNS de Cloudflare con la salvaguarda anti-exposición del origen (plan §4.1).

Regla: un hostname web solo puede quedar en uno de estos estados:
  1. A/AAAA proxied por Cloudflare.
  2. CNAME DNS Only hacia el CDN de respaldo.
Cualquier otra escritura se rechaza en código, también en modo simulación.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import httpx

from ..i18n import tn

API = "https://api.cloudflare.com/client/v4"
AUTO_TTL = 1
TUNNEL_SUFFIX = ".cfargotunnel.com"
BACKUP_CDN_SUFFIXES = (".gcorecdn.com", ".gcdn.co", ".gcorelabs.net")


def is_tunnel_target(content: str) -> bool:
    return content.rstrip(".").lower().endswith(TUNNEL_SUFFIX)


class OriginExposureError(RuntimeError):
    """El cambio publicaría la IP de origen en DNS público."""


@dataclass(frozen=True)
class DnsChange:
    hostname: str
    type: str  # A | AAAA | CNAME
    content: str
    proxied: bool
    ttl: int

    def describe(self) -> str:
        if self.proxied:
            return "Cloudflare proxied"
        return f"{self.type} → {self.content} · TTL {self.ttl}"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def guard(change: DnsChange, origin_ips: set[str]) -> None:
    if change.type in ("A", "AAAA"):
        if not change.proxied:
            raise OriginExposureError(tn(
                "{host}: an unproxied {type} record would publish an IP; only a DNS Only CNAME to a CDN "
                "is allowed", host=change.hostname, type=change.type))
        return
    if change.type == "CNAME":
        if _is_ip(change.content) or change.content in origin_ips:
            raise OriginExposureError(tn("{host}: the CNAME points to an IP", host=change.hostname))
        target = change.content.rstrip(".").lower()
        if not change.proxied and not target.endswith(BACKUP_CDN_SUFFIXES):
            # un CNAME sin proxy hacia cualquier otro nombre podría acabar resolviendo a la IP de origen
            raise OriginExposureError(tn("{host}: an unproxied CNAME can only point to the backup CDN",
                                         host=change.hostname))
        if change.proxied and target.endswith(BACKUP_CDN_SUFFIXES):
            raise OriginExposureError(tn("{host}: the CNAME to the backup CDN must be DNS Only", host=change.hostname))
        return
    raise OriginExposureError(tn("{host}: record type not allowed ({type})", host=change.hostname, type=change.type))


def plan_to_gcore(hostname: str, target: str) -> DnsChange:
    return DnsChange(hostname, "CNAME", target.rstrip("."), proxied=False, ttl=60)


def plan_to_tunnel(hostname: str, tunnel_target: str) -> DnsChange:
    """Vuelta a Cloudflare para hostnames servidos por Cloudflare Tunnel."""
    return DnsChange(hostname, "CNAME", tunnel_target.rstrip("."), proxied=True, ttl=AUTO_TTL)


def plan_restore(host, origin_ip: str | None) -> DnsChange:
    """Registro original con proxy de Cloudflare según el tipo de origen del hostname."""
    if host.origin_kind == "tunnel" and host.tunnel_target:
        return plan_to_tunnel(host.name, host.tunnel_target)
    if host.origin_kind == "cname":
        if not host.cname_target:
            raise ValueError(tn("{host}: its original CNAME is unknown; sync with Cloudflare first", host=host.name))
        return DnsChange(host.name, "CNAME", host.cname_target.rstrip("."), proxied=True, ttl=AUTO_TTL)
    if not origin_ip:
        raise ValueError(tn("{host}: the server's origin IP is missing to restore the A record", host=host.name))
    return plan_to_cloudflare(host.name, origin_ip)


def plan_to_cloudflare(hostname: str, origin_ip: str) -> DnsChange:
    rtype = "AAAA" if ipaddress.ip_address(origin_ip).version == 6 else "A"
    return DnsChange(hostname, rtype, origin_ip, proxied=True, ttl=AUTO_TTL)


class CloudflareDNS:
    def __init__(self, token: str | None, origin_ips: set[str], dry_run: bool = True):
        self.token = token
        self.origin_ips = origin_ips
        self.dry_run = dry_run or not token

    async def apply(self, zone_id: str | None, record_id: str | None, change: DnsChange) -> str:
        guard(change, self.origin_ips)
        if self.dry_run:
            return "simulado"
        if not zone_id or not record_id:
            raise ValueError(tn("{host}: zone_id or cloudflare_record_id is missing in the inventory", host=change.hostname))
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.patch(
                f"{API}/zones/{zone_id}/dns_records/{record_id}",
                headers={"Authorization": f"Bearer {self.token}"},
                json={
                    "type": change.type,
                    "name": change.hostname,
                    "content": change.content,
                    "proxied": change.proxied,
                    "ttl": change.ttl,
                },
            )
        body = r.json()
        if not body.get("success"):
            raise RuntimeError(tn("Cloudflare rejected the change: {errors}", errors=body.get("errors")))
        return "aplicado"


# ---------- Lectura de la cuenta (verificación e importación) ----------

def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def verify_token(token: str) -> tuple[bool, str]:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{API}/user/tokens/verify", headers=_headers(token))
    body = r.json()
    if body.get("success") and body.get("result", {}).get("status") == "active":
        return True, tn("Token valid and active")
    errors = "; ".join(e.get("message", "") for e in body.get("errors", [])) or f"HTTP {r.status_code}"
    return False, errors


async def list_zones(token: str) -> list[dict]:
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get(f"{API}/zones", headers=_headers(token), params={"per_page": 50})
    body = r.json()
    if not body.get("success"):
        raise RuntimeError(f"Cloudflare: {body.get('errors')}")
    return [{"id": z["id"], "name": z["name"], "status": z["status"]} for z in body["result"]]


async def list_web_records(token: str, zone_id: str) -> list[dict]:
    """Registros A/AAAA/CNAME de la zona: candidatos a hostnames web."""
    records: list[dict] = []
    async with httpx.AsyncClient(timeout=20) as client:
        page = 1
        while True:
            r = await client.get(f"{API}/zones/{zone_id}/dns_records", headers=_headers(token),
                                 params={"per_page": 100, "page": page})
            body = r.json()
            if not body.get("success"):
                raise RuntimeError(f"Cloudflare: {body.get('errors')}")
            for rec in body["result"]:
                # Solo hostnames web: fuera _domainkey, _acme-challenge y demás nombres de servicio
                if rec["type"] in ("A", "AAAA", "CNAME") and not any(lbl.startswith("_") for lbl in rec["name"].split(".")):
                    tunnel = rec["type"] == "CNAME" and is_tunnel_target(rec["content"])
                    records.append({
                        "id": rec["id"], "name": rec["name"], "type": rec["type"],
                        "proxied": rec.get("proxied", False),
                        "origin_kind": "tunnel" if tunnel else ("ip" if rec["type"] in ("A", "AAAA") else "cname"),
                        # el contenido de A/AAAA es la IP de origen: no se conserva
                        "tunnel_target": rec["content"] if tunnel else None,
                        "cname_target": rec["content"] if rec["type"] == "CNAME" and not tunnel else None,
                        # registro actual apuntando al CDN de respaldo (sin proxy)
                        "to_backup": rec["type"] == "CNAME" and not rec.get("proxied")
                        and rec["content"].rstrip(".").lower().endswith(BACKUP_CDN_SUFFIXES),
                    })
            info = body.get("result_info", {})
            if page >= info.get("total_pages", 1):
                break
            page += 1
    return sorted(records, key=lambda x: (len(x["name"]), x["name"]))


# ---------- Cabecera secreta hacia el origen (regla de transformación) ----------

ORIGIN_RULE_REF = "multicdn_origin_auth"
ORIGIN_HEADER = "X-Origin-Auth"
_PHASE = "http_request_late_transform"


def origin_rule(secret: str) -> dict:
    return {
        "ref": ORIGIN_RULE_REF,
        "description": "multi-cdn: secret header to the origin",
        "expression": "true",
        "action": "rewrite",
        "action_parameters": {"headers": {ORIGIN_HEADER: {"operation": "set", "value": secret}}},
        "enabled": True,
    }


def _cf_error(body: dict, status: int) -> str:
    msgs = "; ".join(e.get("message", "") for e in body.get("errors", [])) or f"HTTP {status}"
    if status == 403:
        msgs += " " + tn("(the token needs the Zone · Transform Rules · Edit permission)")
    return msgs


async def ensure_origin_header(token: str, zone_id: str, secret: str) -> str:
    """Crea o actualiza en la zona la regla que añade X-Origin-Auth a las peticiones hacia el origen.
    Solo toca su propia regla (por ref); las demás reglas de la zona no cambian.
    Devuelve «creada», «actualizada» o «sin cambios»."""
    rule = origin_rule(secret)
    base = f"{API}/zones/{zone_id}/rulesets"
    async with httpx.AsyncClient(timeout=20, headers=_headers(token)) as c:
        r = await c.get(f"{base}/phases/{_PHASE}/entrypoint")
        if r.status_code == 404:
            r = await c.put(f"{base}/phases/{_PHASE}/entrypoint", json={"rules": [rule]})
            if not r.json().get("success"):
                raise RuntimeError(tn("Cloudflare rejected the rule: {error}", error=_cf_error(r.json(), r.status_code)))
            return "creada"
        body = r.json()
        if not body.get("success"):
            raise RuntimeError(f"Cloudflare: {_cf_error(body, r.status_code)}")
        ruleset = body["result"]
        current = next((x for x in ruleset.get("rules", []) if x.get("ref") == ORIGIN_RULE_REF), None)
        if current is None:
            r = await c.post(f"{base}/{ruleset['id']}/rules", json=rule)
            outcome = "creada"
        else:
            same = (current.get("expression") == "true" and current.get("enabled", True)
                    and current.get("action_parameters") == rule["action_parameters"])
            if same:
                return "sin cambios"
            r = await c.patch(f"{base}/{ruleset['id']}/rules/{current['id']}", json=rule)
            outcome = "actualizada"
        if not r.json().get("success"):
            raise RuntimeError(tn("Cloudflare rejected the rule: {error}", error=_cf_error(r.json(), r.status_code)))
        return outcome


async def origin_header_status(token: str, zone_id: str, secret: str) -> str:
    """«aplicada», «distinta» (otro valor: hay que volver a aplicar) o «sin aplicar»."""
    async with httpx.AsyncClient(timeout=20, headers=_headers(token)) as c:
        r = await c.get(f"{API}/zones/{zone_id}/rulesets/phases/{_PHASE}/entrypoint")
    if r.status_code == 404:
        return "sin aplicar"
    body = r.json()
    if not body.get("success"):
        raise RuntimeError(f"Cloudflare: {_cf_error(body, r.status_code)}")
    current = next((x for x in body["result"].get("rules", []) if x.get("ref") == ORIGIN_RULE_REF), None)
    if current is None:
        return "sin aplicar"
    value = current.get("action_parameters", {}).get("headers", {}).get(ORIGIN_HEADER, {}).get("value")
    return "aplicada" if value == secret and current.get("enabled", True) else "distinta"
