"""Estado compartido del controlador: lo que el panel y las tareas de fondo leen y escriben.

Una sola instancia vive en `app.state.mc`; las rutas la obtienen con `main._state(request)`.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime

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
from .views import build_all


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
    resolutions: dict = field(default_factory=dict)
    dns_checked_at: datetime | None = None
    cf_ranges: list = field(default_factory=list)
    exposure_alerted: set = field(default_factory=set)
    client: httpx.AsyncClient | None = None
    cf_sync_at: datetime | None = None
    cf_sync_errors: dict = field(default_factory=dict)  # dominio -> error
    cf_multi_records: dict = field(default_factory=dict)  # dominio -> hostnames con varios registros web
    jobs: dict = field(default_factory=dict)  # dominio -> Job de preparación en Gcore
    blocked_domains: set = field(default_factory=set)  # dominios con sus IPs de Cloudflare bloqueadas
    block_clear_since: dict = field(default_factory=dict)  # dominio bloqueado -> desde cuándo no lo parece
    cf_live: dict = field(default_factory=dict)  # hostname -> registro actual en Cloudflare (to_backup, target)
    calendar: match_calendar.Calendar | None = None
    calendar_error: str | None = None
    gcore_usage: dict = field(default_factory=dict)  # credencial -> Usage
    stats_cache: dict = field(default_factory=dict)  # clave -> (momento, valor)
    last_beat: object | None = None  # último aviso externo enviado (heartbeat.Beat)
    origin_health: dict = field(default_factory=dict)  # servidor -> origin_health.OriginHealth
    engine: EngineStore = field(init=False)
    engine_ok_at: datetime | None = None  # último ciclo completo del motor sin errores
    feed_stale_alerted: bool = False
    engine_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    cf_ok_at: dict = field(default_factory=dict)  # dominio -> última lectura correcta de Cloudflare
    feed_etag: str | None = None  # ETag of the last feed read (conditional GET)
    feed_mode: str | None = None  # "fast" | "idle": feed polling mode, to log only its changes

    def __post_init__(self) -> None:
        self.engine = EngineStore(self.store.conn)
        self.reload()
        # Los textos de error de los proveedores pierden la IP de origen antes de guardarse o avisarse.
        error_reporting.set_origin_ips(lambda: self.inventory.origin_ips)

    def views(self):
        return build_all(self.inventory, self.resolutions, self.feed, self.engine.known_ips())

    def reload(self) -> None:
        self.inventory = self.store.load()

    @property
    def dry_run(self) -> bool:
        return self.dry_run_env

    def cloudflare_for(self, domain: Domain) -> CloudflareDNS:
        token = self.creds.secret(domain.cloudflare_credential)
        return CloudflareDNS(token, self.inventory.origin_ips, self.dry_run_env)
