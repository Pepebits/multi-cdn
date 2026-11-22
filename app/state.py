"""Estado compartido del controlador: lo que el panel y las tareas de fondo leen y escriben.

Una sola instancia vive en `app.state.mc`; las rutas la obtienen con `main._state(request)`.
"""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import httpx

from . import error_reporting
from .auth import AuthStore
from .config import Domain, Inventory
from .credentials import CredentialStore
from .db import EventStore
from .engine.failover import EngineStore
from .inventory_store import InventoryStore
from .providers.cloudflare import CloudflareDNS
from .secrets_store import SecretStore
from .signals import calendar as match_calendar
from .signals import hayahora
from .views import DomainView, build_all

if TYPE_CHECKING:  # solo para los tipos: importarlos de verdad crearía ciclos
    from .gcore_setup import Job
    from .gcore_usage import Usage
    from .heartbeat import Beat
    from .origin_health import OriginHealth
    from .signals.dnscheck import Resolution


@dataclass
class State:
    store: InventoryStore
    secrets: SecretStore
    creds: CredentialStore
    auth: AuthStore
    events: EventStore
    dry_run_env: bool
    inventory: Inventory = field(init=False)
    feed: hayahora.FeedSnapshot | None = None
    feed_error: str | None = None
    resolutions: dict[str, Resolution] = field(default_factory=dict)  # hostname -> DNS público
    dns_checked_at: datetime | None = None
    cf_ranges: list[ipaddress._BaseNetwork] = field(default_factory=list)  # rangos publicados por Cloudflare
    exposure_alerted: set[str] = field(default_factory=set)  # hostnames con el aviso de origen expuesto enviado
    client: httpx.AsyncClient | None = None
    cf_sync_at: datetime | None = None
    cf_sync_errors: dict[str, str] = field(default_factory=dict)  # dominio -> error
    cf_multi_records: dict[str, list[str]] = field(default_factory=dict)  # dominio -> hostnames con varios registros web
    jobs: dict[str, Job] = field(default_factory=dict)  # dominio -> Job de preparación en Gcore
    blocked_domains: set[str] = field(default_factory=set)  # dominios con sus IPs de Cloudflare bloqueadas
    block_clear_since: dict[str, datetime] = field(default_factory=dict)  # dominio bloqueado -> desde cuándo no lo parece
    cf_live: dict[str, dict[str, Any]] = field(default_factory=dict)  # hostname -> registro actual en Cloudflare (to_backup, target)
    calendar: match_calendar.Calendar | None = None
    calendar_error: str | None = None
    gcore_usage: dict[int, Usage] = field(default_factory=dict)  # id de credencial -> consumo
    stats_cache: dict[str, tuple[datetime, Any]] = field(default_factory=dict)  # clave -> (momento, valor)
    last_beat: Beat | None = None  # último aviso externo enviado
    origin_health: dict[str, OriginHealth] = field(default_factory=dict)  # servidor -> salud del origen
    engine: EngineStore = field(init=False)
    engine_ok_at: datetime | None = None  # último ciclo completo del motor sin errores
    feed_stale_alerted: bool = False
    engine_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    cf_ok_at: dict[str, datetime] = field(default_factory=dict)  # dominio -> última lectura correcta de Cloudflare
    feed_etag: str | None = None  # ETag of the last feed read (conditional GET)
    feed_mode: str | None = None  # "fast" | "idle": feed polling mode, to log only its changes

    def __post_init__(self) -> None:
        self.engine = EngineStore(self.store.conn)
        self.reload()
        # Los textos de error de los proveedores pierden la IP de origen antes de guardarse o avisarse.
        error_reporting.set_origin_ips(lambda: self.inventory.origin_ips)

    @property
    def http(self) -> httpx.AsyncClient:
        """The shared HTTP client; it exists only once the panel (or the CLI runbook) has started."""
        if self.client is None:
            raise RuntimeError("HTTP client not started")
        return self.client

    async def close_http(self) -> None:
        if self.client is not None:
            await self.client.aclose()

    def views(self) -> list[DomainView]:
        return build_all(self.inventory, self.resolutions, self.feed, self.engine.known_ips())

    def reload(self) -> None:
        self.inventory = self.store.load()

    @property
    def dry_run(self) -> bool:
        return self.dry_run_env

    def cloudflare_for(self, domain: Domain) -> CloudflareDNS:
        token = self.creds.secret(domain.cloudflare_credential)
        return CloudflareDNS(token, self.inventory.origin_ips, self.dry_run_env)
