"""Emergency sheet: how to switch each domain by hand in the Cloudflare dashboard when neither the
panel nor the server's terminal can do it (the VPS is down, say).

Plain text, meant to be kept in a password manager. It never contains the origin IP: to restore
an A record it says where to find it. It only reads the inventory (no network).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from .config import Domain, Hostname, Inventory
from .i18n import N_

Translate = Callable[..., str]

PRIORITY = {"critical": N_("critical priority"), "medium": N_("medium priority"), "low": N_("low priority")}


def _restore(h: Hostname, t: Translate) -> str:
    if h.origin_kind == "tunnel" and h.tunnel_target:
        return t(N_("CNAME {host} → {target}, Proxied (orange cloud)"), host=h.name, target=h.tunnel_target.rstrip("."))
    if h.origin_kind == "cname" and h.cname_target:
        return t(N_("CNAME {host} → {target}, Proxied (orange cloud)"), host=h.name, target=h.cname_target.rstrip("."))
    return t(N_("A {host} → your origin IP (in your password manager, never here), Proxied (orange cloud)"), host=h.name)


def _domain(name: str, d: Domain, t: Translate) -> list[str]:
    out = [f"== {name} ({t(PRIORITY[d.priority])})", ""]
    switching = [h for h in d.hostnames if h.failover]
    if not d.gcore_resource_id or not switching or not all(h.gcore_target for h in switching):
        return out + [t(N_("Not prepared on Gcore: it cannot be moved by hand either. Prepare it from the panel.")), ""]
    first = switching[0]
    target = first.gcore_target.rstrip(".") if first.gcore_target else ""
    out += [
        t(N_("1. Check first that Gcore serves it (from any computer):")),
        f"   curl -sI --connect-to {first.name}:443:{target}:443 https://{first.name}/",
        "   " + t(N_("A status below 500 (200, 301, 302…) means it does.")),
        "",
        t(N_("2. Switch to Gcore: Cloudflare dashboard → {domain} → DNS → Records. For each hostname, delete its "
             "record and add:"), domain=name),
    ]
    out += [f"   - CNAME {h.name} → {(h.gcore_target or '').rstrip('.')}, " + t(N_("DNS only (grey cloud), TTL 1 min"))
            for h in switching]
    out += ["", t(N_("3. Back to Cloudflare, when the block is over: delete each CNAME and add again:"))]
    out += [f"   - {_restore(h, t)}" for h in switching]
    if stay := [h.name for h in d.hostnames if not h.failover]:
        out += ["", t(N_("Do not touch (they always stay on Cloudflare): {hosts}"), hosts=", ".join(stay))]
    return out + [""]


def sheet(inventory: Inventory, t: Translate, now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    lines = [
        t(N_("Multi-CDN emergency sheet · generated {time} UTC"), time=f"{now:%Y-%m-%d %H:%M}"),
        "",
        t(N_("For when neither the panel nor the server's terminal can switch (the server is down, say). If the "
             "terminal works, use it instead: it checks Gcore and never exposes the origin:")),
        "   docker compose exec panel python -m app.cli switch <domain> gcore",
        "",
        t(N_("Never set a record to your origin IP with the proxy off (grey cloud): it would publish the IP the "
             "CDNs are hiding.")),
        t(N_("When the panel is back it reads these records and takes over again; pause its automatic switching "
             "for a domain if you want it to stay where you left it.")),
        t(N_("Generate it again after adding domains or hostnames, or after preparing one on Gcore.")),
        "",
    ]
    for name, domain in inventory.ordered_domains():
        lines += _domain(name, domain, t)
    return "\n".join(lines).rstrip() + "\n"
