"""Consumo de Gcore: tráfico del mes frente a la cuota gratuita y recursos usados.

Se cuenta el tráfico total (servido a usuarios + traído del origen), que es lo más
conservador. Avisa una vez por mes y cuenta al pasar del 70 %, 90 % y 100 %.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from .i18n import tn
from .providers import gcore

THRESHOLDS = (70, 90, 100)
GB = 1000**3  # los proveedores facturan en unidades decimales


@dataclass
class Usage:
    credential_id: int
    label: str
    month: str                     # AAAA-MM
    total: int = 0
    sent: int = 0
    upstream: int = 0
    by_resource: dict = field(default_factory=dict)
    resources: int | None = None
    max_resources: int | None = None
    quota_gb: int = 1000
    checked_at: datetime | None = None
    error: str | None = None

    @property
    def percent(self) -> float:
        return 100 * self.total / (self.quota_gb * GB) if self.quota_gb else 0.0


def human(n: int) -> str:
    for unit, size in (("TB", 1000**4), ("GB", GB), ("MB", 1000**2), ("KB", 1000)):
        if n >= size:
            return f"{n / size:.1f} {unit}".replace(".", ",")
    return f"{n} B"


def month_start(now: datetime) -> datetime:
    return now.astimezone(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)


async def refresh_usage(state, now: datetime | None = None) -> None:
    now = now or datetime.now(UTC)
    quota = state.events.get_setting("gcore_quota_gb")
    usage = {}
    for cred in state.creds.list("gcore"):
        u = Usage(cred.id, cred.label, f"{now:%Y-%m}", quota_gb=quota, checked_at=now)
        token = state.creds.secret(cred.id)
        try:
            if not token:
                raise RuntimeError(tn("the credential cannot be decrypted"))
            t = await gcore.traffic(token, month_start(now), now)
            u.total, u.sent, u.upstream, u.by_resource = t["total_bytes"], t["sent_bytes"], t["upstream_bytes"], t["by_resource"]
            limits = await gcore.account_limits(token)
            u.resources, u.max_resources = limits["resources"], limits["max_resources"]
        except (RuntimeError, httpx.HTTPError) as exc:
            u.error = str(exc) or type(exc).__name__
        usage[cred.id] = u
        if not u.error:
            _alert(state, u)
    state.gcore_usage = usage


def _alert(state, u: Usage) -> None:
    key = f"gcore_usage_alert:{u.credential_id}"
    last = state.events.get_value(key) or ""
    last_month, _, last_level = last.partition(":")
    sent_level = int(last_level) if last_month == u.month and last_level.isdigit() else 0
    level = max((t for t in THRESHOLDS if u.percent >= t), default=0)
    if level > sent_level:
        state.events.add(actor="auto", kind="alert",
                         summary=tn("Gcore traffic («{label}») at {percent} % of the monthly quota: {used} of {quota} GB",
                                    label=u.label, percent=f"{u.percent:.0f}", used=human(u.total), quota=u.quota_gb))
        state.events.set_value(key, f"{u.month}:{level}")
    if u.max_resources and u.resources is not None and u.resources >= u.max_resources - 2:
        rkey = f"gcore_resources_alert:{u.credential_id}"
        if state.events.get_value(rkey) != str(u.resources):
            state.events.add(actor="auto", kind="alert",
                             summary=tn("Gcore («{label}»): {used} of {max} CDN resources used", label=u.label,
                                        used=u.resources, max=u.max_resources))
            state.events.set_value(rkey, str(u.resources))
