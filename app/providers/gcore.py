"""Adaptador Gcore CDN: verificación, grupos de origen, certificados y recursos.

Referencia: https://docs.gcore.com/api-reference/cdn
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime

import httpx

API = "https://api.gcore.com"


def _client(token: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=API, timeout=30, headers={"Authorization": f"APIKey {token}"})


def _check(r: httpx.Response, what: str):
    if r.status_code >= 400:
        detail = r.text[:300].replace("\n", " ")
        raise RuntimeError(f"Gcore rechazó {what} (HTTP {r.status_code}): {detail}")
    return r.json() if r.content else None


def _items(body) -> list[dict]:
    return body if isinstance(body, list) else (body or {}).get("results", [])


async def verify_token(token: str) -> tuple[bool, str]:
    async with _client(token) as c:
        r = await c.get("/cdn/clients/me")
    if r.status_code == 200:
        return True, f"API key válida · destino DNS de la cuenta: {r.json().get('cname')}"
    if r.status_code in (401, 403):
        return False, f"Gcore rechazó la API key (HTTP {r.status_code})"
    return False, f"Respuesta inesperada de Gcore (HTTP {r.status_code})"


async def account_cname(token: str) -> str:
    async with _client(token) as c:
        body = _check(await c.get("/cdn/clients/me"), "la consulta de la cuenta")
    return body["cname"].rstrip(".")


async def ensure_origin_group(token: str, name: str, origin_ip: str) -> int:
    payload = {"name": name, "sources": [{"source": f"{origin_ip}:443", "enabled": True, "backup": False}]}
    async with _client(token) as c:
        groups = _items(_check(await c.get("/cdn/origin_groups"), "el listado de orígenes"))
        current = next((g for g in groups if g.get("name") == name), None)
        if current:
            _check(await c.put(f"/cdn/origin_groups/{current['id']}", json=payload), "la actualización del origen")
            return current["id"]
        return _check(await c.post("/cdn/origin_groups", json=payload), "la creación del origen")["id"]


async def upload_certificate(token: str, name: str, fullchain: str, privkey: str) -> int:
    async with _client(token) as c:
        existing = _items(_check(await c.get("/cdn/sslData"), "el listado de certificados"))
        same = next((s for s in existing if s.get("name") == name), None)
        if same:
            return same["id"]
        body = _check(await c.post("/cdn/sslData", json={
            "name": name, "sslCertificate": fullchain, "sslPrivateKey": privkey, "validate_root_ca": True,
        }), "la subida del certificado")
    return body["id"]


def resource_payload(primary: str, secondary: list[str], origin_group: int, ssl_id: int, secret_header: str) -> dict:
    return {
        "cname": primary,
        "secondaryHostnames": secondary,
        "originGroup": origin_group,
        "originProtocol": "HTTPS",
        "sslEnabled": True,
        "sslData": ssl_id,
        "active": True,
        "description": "multi-cdn: respaldo gestionado por el panel",
        "options": {
            # Sin cabeceras de caché del origen no se cachea nada (sitios dinámicos, sesiones).
            "edge_cache_settings": {"enabled": True, "default": "0s"},
            "ignore_cookie": {"enabled": True, "value": False},
            # Cada hostname llega al origen con su propio Host y SNI.
            "forward_host_header": {"enabled": True, "value": True},
            "sni": {"enabled": True, "sni_type": "dynamic", "custom_hostname": primary},
            "staticRequestHeaders": {"enabled": True, "value": {"X-Origin-Auth": secret_header}},
            "websockets": {"enabled": True, "value": True},
            "redirect_http_to_https": {"enabled": True, "value": True},
        },
    }


async def ensure_resource(token: str, payload: dict) -> int:
    async with _client(token) as c:
        resources = _items(_check(await c.get("/cdn/resources"), "el listado de recursos"))
        current = next((r for r in resources if r.get("cname") == payload["cname"]), None)
        if current:
            body = dict(payload)
            body.pop("cname")  # el CNAME principal no se cambia en una actualización
            _check(await c.put(f"/cdn/resources/{current['id']}", json=body), "la actualización del recurso")
            return current["id"]
        return _check(await c.post("/cdn/resources", json=payload), "la creación del recurso")["id"]


async def probe_edge(edge_host: str, hostname: str, timeout: float = 15) -> tuple[bool, str]:
    """GET https://hostname/ conectando a la IP de borde de Gcore (equivale a curl --resolve)."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(edge_host, 443, type=socket.SOCK_STREAM)
    # IPv4 primero: muchas redes no tienen salida IPv6 y el borde publica ambas
    ips = sorted({i[4][0] for i in infos}, key=lambda a: ":" in a)
    ctx = ssl.create_default_context()
    reader = writer = None
    last_exc: Exception | None = None
    for ip in ips:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=hostname), timeout)
            break
        except (ssl.SSLError, OSError, asyncio.TimeoutError) as exc:
            last_exc = exc
    try:
        if writer is None:
            raise last_exc or OSError("sin direcciones")
    except ssl.SSLCertVerificationError as exc:
        return False, f"{hostname}: certificado no válido en Gcore ({exc.verify_message})"
    except ssl.SSLError as exc:
        return False, f"{hostname}: error TLS en el borde de Gcore ({exc.reason or exc.strerror or exc}); si el recurso es nuevo, puede estar propagándose"
    except (OSError, asyncio.TimeoutError) as exc:
        return False, f"{hostname}: no conecta con el borde de Gcore ({type(exc).__name__})"
    cert = writer.get_extra_info("peercert") or {}
    writer.write(f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: multicdn-probe\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    status = (await asyncio.wait_for(reader.readline(), timeout)).decode(errors="replace").strip()
    writer.close()
    expires = cert.get("notAfter", "?")
    code = status.split(" ")[1] if len(status.split(" ")) > 1 else "?"
    ok = code.isdigit() and int(code) < 500
    return ok, f"{hostname}: HTTP {code} vía Gcore ({ip}), certificado válido hasta {expires}"


EDGE_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")


async def edge_ipv4s(edge_host: str) -> list[str]:
    """IPv4 del borde vistas desde varios resolvers: Gcore responde con IPs distintas según quién pregunte."""
    import dns.asyncresolver
    import dns.exception

    loop = asyncio.get_running_loop()
    ips: set[str] = set()
    try:
        ips |= {i[4][0] for i in await loop.getaddrinfo(edge_host, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)}
    except OSError:
        pass
    for ns in EDGE_RESOLVERS:
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers, resolver.lifetime = [ns], 5
        try:
            ips |= {r.address for r in await resolver.resolve(edge_host, "A")}
        except dns.exception.DNSException:
            pass
    return sorted(ips)


async def probe_all_edges(edge_host: str, hostname: str, timeout: float = 15) -> tuple[bool, str]:
    """Como probe_edge, pero contra cada IPv4 conocida del borde: un recurso recién creado
    puede servir ya en un punto de presencia y dar 503 en otro."""
    ips = await edge_ipv4s(edge_host)
    if not ips:
        return False, f"{hostname}: no se resuelve el borde de Gcore {edge_host}"
    for ip in ips:
        ok, detail = await probe_edge(ip, hostname, timeout)
        if not ok:
            return False, detail
    return True, f"{hostname}: responde vía Gcore en {', '.join(ips)}"


async def resource_status(token: str, resource_id: int) -> str:
    """«active» cuando el recurso ya está desplegado en todo el borde («processed» mientras se propaga)."""
    async with _client(token) as c:
        return _check(await c.get(f"/cdn/resources/{resource_id}"), "la lectura del recurso").get("status", "?")


async def traffic(token: str, start: datetime, end: datetime) -> dict:
    """Bytes del periodo: total (lo que se cuenta frente a la cuota), servido a usuarios y traído del
    origen, y el total por recurso. La API no admite varias métricas en una sola llamada."""
    params = {"from": start.strftime("%Y-%m-%dT%H:%M:%SZ"), "to": end.strftime("%Y-%m-%dT%H:%M:%SZ"), "service": "CDN"}
    out: dict = {}
    async with _client(token) as c:
        for metric in ("total_bytes", "sent_bytes", "upstream_bytes"):
            r = await c.get("/cdn/statistics/aggregate/stats", params=params | {"metrics": metric})
            body = _check(r, "la consulta de estadísticas") or {}
            out[metric] = int((body.get("metrics") or {}).get(metric) or 0)
        r = await c.get("/cdn/statistics/aggregate/stats", params=params | {"metrics": "total_bytes", "group_by": "resource"})
        body = _check(r, "la consulta de estadísticas por recurso") or {}
        out["by_resource"] = {int(rid): int(v["metrics"]["total_bytes"]) for rid, v in (body.get("resource") or {}).items()}
    return out


async def traffic_series(token: str, start: datetime, end: datetime) -> dict[int, list[tuple[datetime, int]]]:
    """Bytes totales por día y recurso."""
    params = {"from": start.strftime("%Y-%m-%dT%H:%M:%SZ"), "to": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
              "service": "CDN", "metrics": "total_bytes", "granularity": "1d", "group_by": "resource"}
    async with _client(token) as c:
        body = _check(await c.get("/cdn/statistics/series", params=params), "la serie de tráfico") or {}
    return {int(rid): [(datetime.fromtimestamp(ts, UTC), int(v or 0)) for ts, v in data["metrics"]["total_bytes"]]
            for rid, data in (body.get("resource") or {}).items()}


async def account_limits(token: str) -> dict:
    """Recursos CDN usados y máximo de la cuenta (30 en el plan gratuito)."""
    async with _client(token) as c:
        me = _check(await c.get("/cdn/clients/me"), "la consulta de la cuenta")
        resources = _items(_check(await c.get("/cdn/resources"), "el listado de recursos"))
    return {"resources": len(resources), "max_resources": me.get("max_objects_count")}


async def delete_resource(token: str, resource_id: int) -> None:
    """Gcore exige desactivar el recurso (PUT con active=false y su originGroup) antes de borrarlo."""
    async with _client(token) as c:
        res = _check(await c.get(f"/cdn/resources/{resource_id}"), "la lectura del recurso")
        if res.get("active", True):
            _check(await c.put(f"/cdn/resources/{resource_id}", json={"originGroup": res["originGroup"], "active": False}),
                   "la desactivación del recurso")
        r = await c.delete(f"/cdn/resources/{resource_id}")
        if r.status_code not in (200, 204, 404):
            _check(r, "el borrado del recurso")


async def delete_certificate(token: str, ssl_id: int) -> None:
    async with _client(token) as c:
        r = await c.delete(f"/cdn/sslData/{ssl_id}")
    if r.status_code not in (200, 204, 404):
        _check(r, "el borrado del certificado antiguo")
