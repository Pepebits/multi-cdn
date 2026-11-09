"""Construye lo que muestra el panel a partir del inventario, el DNS público y el feed."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .config import Domain, Inventory
from .i18n import N_, tr, trn
from .signals.dnscheck import Resolution
from .signals.hayahora import ISPS, FeedSnapshot

PRIORITY_LABEL = {"critical": N_("Critical"), "medium": N_("Medium"), "low": N_("Low")}
POLICY_LABEL = {"preventive": N_("preventive"), "reactive": N_("reactive"), "manual": N_("manual")}

# estado -> (texto, tono). El tono mapea a colores del DESIGN.md.
STATUS = {
    "cloudflare": ("Cloudflare", "ok"),
    "gcore": (N_("Gcore active"), "backup"),
    "origin": (N_("Origin exposed"), "danger"),
    "mixed": (N_("Mixed"), "warn"),
    "unknown": (N_("No data"), "neutral"),
}

PROVIDER_LABEL = {
    "cloudflare": "Cloudflare",
    "gcore": "Gcore",
    "origin": N_("Direct origin"),
    "other": N_("Other"),
    "unresolved": N_("Unresolved"),
}


class Alert(str):
    """Texto de un aviso del dominio; `level` (error | warn) da el tono en la plantilla."""

    level: str = "warn"

    def __new__(cls, text: str, level: str = "warn"):
        obj = super().__new__(cls, text)
        obj.level = level
        return obj


@dataclass
class HostView:
    name: str
    provider: str
    provider_label: str
    dns_text: str
    ips: tuple[str, ...]
    gcore_target: str | None
    origin_kind: str | None = None
    failover: bool = True


@dataclass
class IspRow:
    name: str
    state: str  # blocked | free | nodata
    since: datetime | None


@dataclass
class DomainView:
    name: str
    priority: str
    priority_label: str
    policy_label: str
    status: str
    status_label: str
    status_tone: str
    hosts: list[HostView]
    cf_ips: list[str]
    monitored_ips: list[str]
    isp_rows: list[IspRow]
    gcore_ready: bool
    alerts: list[str] = field(default_factory=list)
    gcore_resource_id: int | None = None

    @property
    def blocked_count(self) -> int:
        return sum(r.state == "blocked" for r in self.isp_rows)


def _dns_text(res: Resolution | None, provider: str) -> str:
    if res is None or provider == "unresolved":
        return tr("unresolved")
    if provider == "cloudflare":
        return "Cloudflare proxied"
    if res.cname:
        return f"CNAME → {res.cname.rstrip('.')}"
    if provider == "origin":
        return tr("A → origin IP (proxy off)")
    return "A → " + ", ".join(res.ips)


def build_domain(
    name: str, domain: Domain, resolutions: dict[str, Resolution], feed: FeedSnapshot | None,
    known_cf_ips: list[str] | tuple[str, ...] = (),
) -> DomainView:
    """known_cf_ips: últimas IPs de Cloudflare conocidas del dominio. Si ya está en Gcore, el DNS
    público no las muestra, pero hay que seguir mirando si siguen bloqueadas para saber cuándo volver."""
    hosts: list[HostView] = []
    cf_ips: set[str] = set()
    for h in domain.hostnames:
        res = resolutions.get(h.name)
        provider = res.provider if res else "unresolved"
        if provider == "cloudflare" and res:
            cf_ips.update(res.ips)
        tunnel = h.origin_kind == "tunnel"
        label = tr(PROVIDER_LABEL.get(provider, provider))
        dns_text = _dns_text(res, provider)
        if tunnel and provider == "cloudflare":
            label, dns_text = "Cloudflare Tunnel", "CNAME → Cloudflare Tunnel (proxied)"
        hosts.append(
            HostView(
                name=h.name,
                provider=provider,
                provider_label=label,
                dns_text=dns_text,
                ips=res.ips if res and provider == "cloudflare" else (),
                gcore_target=h.gcore_target,
                origin_kind=h.origin_kind,
                failover=h.failover,
            )
        )

    # El estado se calcula con los hostnames que conmutan; los excluidos (p. ej. un www de
    # redirección) se quedan en Cloudflare a propósito y no deben dar «Mixto».
    providers = {h.provider for h in hosts if h.failover} or {h.provider for h in hosts}
    if not resolutions:
        status = "unknown"
    elif "origin" in providers:
        status = "origin"
    elif providers == {"cloudflare"}:
        status = "cloudflare"
    elif providers == {"gcore"}:
        status = "gcore"
    elif providers <= {"unresolved"}:
        status = "unknown"
    else:
        status = "mixed"
    label, tone = STATUS[status]

    watched = cf_ips or set(known_cf_ips)
    monitored = sorted(ip for ip in watched if feed and feed.monitored(ip))
    rows: list[IspRow] = []
    for feed_name, display in ISPS.items():
        if not monitored or feed is None:
            rows.append(IspRow(display, "nodata", None))
            continue
        states = [s for ip in monitored if (s := feed.state(ip, feed_name))]
        blocked = [s for s in states if s.blocked]
        if blocked:
            rows.append(IspRow(display, "blocked", min(s.since for s in blocked if s.since)))
        elif states:
            rows.append(IspRow(display, "free", max(s.since for s in states if s.since)))
        else:
            rows.append(IspRow(display, "nodata", None))

    alerts = []
    for h in hosts:
        if h.provider == "origin":
            alerts.append(Alert(tr("{host} resolves to the origin IP: the server is exposed without a CDN.",
                                   host=h.name), "error"))
    tunneled = [h.name for h in hosts if h.origin_kind == "tunnel"]
    if tunneled:
        alerts.append(Alert(trn(
            "{hosts} is served through Cloudflare Tunnel: there is no origin IP Gcore can connect to. To use "
            "Gcore as backup, expose that origin by IP (with a firewall limited to Gcore and a secret header) "
            "or add a second connector.",
            "{hosts} are served through Cloudflare Tunnel: there is no origin IP Gcore can connect to. To use "
            "Gcore as backup, expose that origin by IP (with a firewall limited to Gcore and a secret header) "
            "or add a second connector.",
            len(tunneled), hosts=", ".join(tunneled))))
    if watched and not monitored:
        alerts.append(Alert(tr("Its Cloudflare IPs are not in the feed: there is no block data per ISP.")))

    return DomainView(
        name=name,
        priority=domain.priority,
        priority_label=tr(PRIORITY_LABEL[domain.priority]),
        policy_label=tr(POLICY_LABEL[domain.policy]),
        status=status,
        status_label=tr(label),
        status_tone=tone,
        hosts=hosts,
        cf_ips=sorted(cf_ips),
        monitored_ips=monitored,
        isp_rows=rows,
        gcore_ready=any(h.failover for h in domain.hostnames)
        and all(h.gcore_target for h in domain.hostnames if h.failover),
        alerts=alerts,
        gcore_resource_id=domain.gcore_resource_id,
    )


def build_all(inv: Inventory, resolutions, feed, known_cf_ips: dict | None = None) -> list[DomainView]:
    known = known_cf_ips or {}
    return [build_domain(n, d, resolutions, feed, known.get(n, ())) for n, d in inv.ordered_domains()]
