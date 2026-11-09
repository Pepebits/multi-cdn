"""Carga y validación del inventario declarativo (YAML + variables de entorno)."""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import AliasChoices, BaseModel, Field, field_validator, model_validator

_ENV_REF = re.compile(r"\$\{([A-Z0-9_]+)\}")

Policy = Literal["preventive", "reactive", "manual"]
Priority = Literal["critical", "medium", "low"]
Backup = Literal["gcore", "fastly"]


def _expand(value: Any) -> Any:
    """Sustituye ${VAR} por su valor. Una referencia completa a una variable
    vacía o inexistente se convierte en None (dato aún no configurado)."""
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if not isinstance(value, str):
        return value
    whole = _ENV_REF.fullmatch(value.strip())
    if whole:
        return os.environ.get(whole.group(1)) or None
    return _ENV_REF.sub(lambda m: os.environ.get(m.group(1), ""), value)


_HOST = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")


def normalize_private_address(value: str | None) -> str | None:
    """Nombre de host o IP (v4/v6); vacío -> None."""
    if value is None or not value.strip():
        return None
    value = value.strip().lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if _HOST.match(value):
            return value
    raise ValueError(f"dirección privada no válida: {value!r} (nombre de host o IP)")


class Server(BaseModel):
    origin_ipv4: ipaddress.IPv4Address | None = None
    origin_ipv6: ipaddress.IPv6Address | None = None
    # Cómo llega el panel a este servidor por una red privada (Tailscale, WireGuard, NetBird o LAN):
    # nombre o IP. Solo hace falta si el panel corre en otro servidor (salud del origen y estado
    # de su firewall).
    private_address: str | None = Field(default=None, validation_alias=AliasChoices("private_address", "tailscale"))

    @field_validator("private_address")
    @classmethod
    def _check_private_address(cls, value: str | None) -> str | None:
        return normalize_private_address(value)

    @property
    def origin_ips(self) -> set[str]:
        return {str(ip) for ip in (self.origin_ipv4, self.origin_ipv6) if ip}


class Hostname(BaseModel):
    name: str
    server: str
    backups: list[Backup] = Field(default_factory=lambda: ["gcore"])
    gcore_target: str | None = None
    cloudflare_record_id: str | None = None
    origin_kind: str | None = None      # ip | tunnel | cname (según la API de Cloudflare)
    tunnel_target: str | None = None    # <uuid>.cfargotunnel.com, para restaurar el túnel
    cname_target: str | None = None     # destino original de un CNAME, para restaurarlo
    failover: bool = True               # False: se queda siempre en Cloudflare (p. ej. un www que solo redirige)


class Domain(BaseModel):
    zone_id: str | None = None
    cloudflare_credential: int | None = None
    gcore_credential: int | None = None
    gcore_resource_id: int | None = None
    gcore_ssl_id: int | None = None
    cert_not_after: str | None = None   # ISO, fin de validez del certificado subido a Gcore
    policy: Policy = "reactive"
    priority: Priority = "medium"
    hostnames: list[Hostname]


class Inventory(BaseModel):
    servers: dict[str, Server]
    domains: dict[str, Domain]

    @model_validator(mode="after")
    def _check_references(self) -> Inventory:
        for domain_name, domain in self.domains.items():
            for host in domain.hostnames:
                if host.server not in self.servers:
                    raise ValueError(f"{host.name}: servidor desconocido '{host.server}'")
                if host.name != domain_name and not host.name.endswith("." + domain_name):
                    raise ValueError(f"{host.name} no pertenece a la zona {domain_name}")
        return self

    @property
    def origin_ips(self) -> set[str]:
        return {ip for s in self.servers.values() for ip in s.origin_ips}

    def ordered_domains(self) -> list[tuple[str, Domain]]:
        rank = {"critical": 0, "medium": 1, "low": 2}
        return sorted(self.domains.items(), key=lambda kv: (rank[kv[1].priority], kv[0]))


def load_inventory(path: str | Path | None = None) -> Inventory:
    if path is None:
        path = os.environ.get("MULTICDN_INVENTORY", "inventory.yaml")
        if not Path(path).exists():
            path = "inventory.example.yaml"
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return Inventory.model_validate(_expand(raw))


def load_dotenv(path: str | Path | None = None) -> None:
    """Lector mínimo de .env (KEY=VALUE); no sobrescribe variables ya definidas.
    MULTICDN_DOTENV cambia el fichero; los tests lo apuntan a uno inexistente para no leer
    nunca el .env del desarrollador."""
    p = Path(path or os.environ.get("MULTICDN_DOTENV", ".env"))
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))
