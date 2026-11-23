"""What is broken right now, for the "Open problems" strip on the overview.

One list built from every place the panel keeps a problem: the alerts with recovery
(``alert:<key>`` in the settings table, see alerts.py), the origin firewall, the stale feed,
origin health, origin exposure, the panel's own loops (heartbeat.liveness) and the external
heartbeat. Each item says how bad it is, since when (if known) and where to fix it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from . import alerts, heartbeat
from .i18n import tr, trn


@dataclass
class Problem:
    key: str
    severity: str           # error | warn
    text: str
    since: datetime | None
    href: str | None
    where: str | None       # label of the place where it is fixed


def _settings(tab: str) -> str:
    """"Settings → <tab>" with the labels of the settings tabs (marked in _macros.html)."""
    return f"{tr('Settings')} → {tr(tab)}"


def _domain_href(name: str | None, anchor: str = "") -> str | None:
    return f"/dominios/{name}{anchor}" if name else None


def _alert_items(state, now: datetime) -> list[Problem]:
    out = []
    for key, data in alerts.active(state).items():
        # Not alerted yet = still inside its grace period (a single failed read, say): not a problem yet.
        if not data.get("alerted"):
            continue
        since = data["since"]
        if key == "feed_down":
            out.append(Problem(key, "error", tr("The block feed cannot be read: automatic switching is blind"),
                               since, "/ajustes/cambio#feed", _settings("Automatic switching")))
        elif key.startswith("cf_read:"):
            cred_id = key.removeprefix("cf_read:")
            try:
                label = state.creds.get(int(cred_id)).label
            except ValueError:
                label = cred_id
            out.append(Problem(key, "error", tr('Cloudflare cannot be read with the credential "{label}": a switch '
                                                "would fail", label=label),
                               since, f"/ajustes/cuentas#cuenta-{cred_id}", _settings("Provider accounts")))
        elif key.startswith("auto_not_ready:"):
            from .engine import failover
            name = key.removeprefix("auto_not_ready:")
            cfg = state.inventory.domains.get(name)
            if cfg is None:
                continue
            reasons = failover.reasons_text(failover.readiness(state, cfg))  # as of now, not when it was alerted
            text = (tr("{domain}: automatic switching cannot act ({reasons})", domain=name, reasons=reasons) if reasons
                    else tr("{domain}: automatic switching cannot act", domain=name))
            codes = failover.readiness(state, cfg)
            anchor = "#gcore" if codes == ["not_prepared"] else "#config"
            out.append(Problem(key, "warn", text, since, _domain_href(name, anchor), name))
        elif key == "backup":
            out.append(Problem(key, "error", tr("The daily database backup is failing"), since,
                               "/ajustes/sistema", _settings("System")))
        elif key.startswith("gcore_ready:"):
            name = key.removeprefix("gcore_ready:")
            out.append(Problem(key, "error", tr("{domain}: Gcore could not serve it if it had to switch", domain=name),
                               since, _domain_href(name, "#gcore"), name))
        elif key.startswith("gcore_serving:"):
            name = key.removeprefix("gcore_serving:")
            out.append(Problem(key, "error", tr("{domain}: Gcore is not serving it while it is the active CDN",
                                                domain=name), since, _domain_href(name, "#gcore"), name))
        else:
            out.append(Problem(key, "warn", tr("Open problem: {key}", key=key), since, None, None))
    return out


def _firewall_item(state, now: datetime) -> Problem | None:
    from . import firewall_status
    status = firewall_status.read()
    problem = status.problem(now) if status else (state.events.get_value("firewall_problem") or None)
    if not problem:
        return None
    since = None
    if status and not status.error and status.last_ok:
        since = status.last_ok + firewall_status.MAX_AGE  # when it went out of date
    return Problem("firewall", "error", tr("Origin firewall: {problem}", problem=problem), since,
                   "/ajustes/servidores#firewall-titulo", _settings("Servers"))


def open_problems(state, now: datetime | None = None) -> list[Problem]:
    """Errors first, then warnings; within each, the oldest first."""
    now = now or datetime.now(UTC)
    items = _alert_items(state, now)

    if (fw := _firewall_item(state, now)) is not None:
        items.append(fw)

    if state.feed_stale_alerted and state.feed is not None:
        items.append(Problem("feed_stale", "warn", tr("The block feed answers with old data: automatic switching is "
                                                      "not deciding"),
                             state.feed.last_update, "/ajustes/cambio#feed", _settings("Automatic switching")))

    from .origin_health import FAILS_TO_ALERT, INTERVAL
    for health in state.origin_health.values():
        if not health.ok and health.fails >= FAILS_TO_ALERT:
            items.append(Problem(f"origin:{health.server}", "error",
                                 tr("Origin {server} is not responding ({detail})", server=health.server,
                                    detail=health.detail),
                                 health.checked_at - timedelta(seconds=INTERVAL * (health.fails - 1)),
                                 "/ajustes/servidores", _settings("Servers")))

    for hostname in sorted(state.exposure_alerted):
        res = state.resolutions.get(hostname)
        if res is None or res.provider != "origin":
            continue
        domain = next((n for n, d in state.inventory.domains.items() if any(h.name == hostname for h in d.hostnames)), None)
        items.append(Problem(f"exposed:{hostname}", "error",
                             tr("{hostname} resolves to the origin IP: the server is exposed", hostname=hostname),
                             None, _domain_href(domain), domain))

    grace = os.environ.get("MULTICDN_OFFLINE") == "1" or now - state.started_at < heartbeat.STARTUP_GRACE
    if not grace:
        for loop in heartbeat.liveness(state, now):
            items.append(Problem(f"loop:{loop}", "error",
                                 tr("The panel is not working well: {problem}", problem=tr(heartbeat.STALE_TEXT[loop])),
                                 None, None, None))

    beat = state.last_beat
    if beat is not None and beat.result != "ok":
        items.append(Problem("heartbeat", "warn", tr("The external heartbeat could not be delivered ({result})",
                                                     result=beat.result),
                             beat.at, "/ajustes/notificaciones", _settings("Notifications")))

    from .routes.common import RECOVERY_LOW, env_mismatches
    for user in state.auth.list_users():
        left = state.auth.recovery_left(user.id)
        if user.totp_enabled and left <= RECOVERY_LOW:
            items.append(Problem(f"recovery:{user.username}", "warn",
                                 trn("{user} has only {n} recovery code left", "{user} has only {n} recovery codes left",
                                     left, user=user.username),
                                 None, "/ajustes/cuenta#recuperacion", _settings("My account")))

    for m in env_mismatches(state):
        items.append(Problem(f"env:{m['env']}", "warn",
                             tr("{label}: config/secrets.env could not be updated; on the next restart its value will "
                                "replace the panel's", label=m["label"]),
                             None, "/ajustes/sistema#env", _settings("System")))
    from . import envfile
    view = envfile.view()
    if view.configured and not view.readable:
        items.append(Problem("secrets-file", "error",
                             tr("config/secrets.env cannot be read: the panel keeps its saved values and imports "
                                "nothing from it until it can"),
                             None, "/ajustes/sistema#env", _settings("System")))
    if view.unmanaged:
        items.append(Problem("secrets-unmanaged", "warn",
                             tr("config/secrets.env has variables the panel does not manage ({keys}): they are ignored; "
                                "move them to .env", keys=", ".join(view.unmanaged)),
                             None, "/ajustes/sistema#env", _settings("System")))
    if "MULTICDN_DRY_RUN" in view.unmanaged:
        items.append(Problem("secrets-dry-run", "error",
                             tr("MULTICDN_DRY_RUN is in config/secrets.env: the panel stays in dry run until that line "
                                "is removed (set it only in .env)"),
                             None, "/ajustes/sistema#env", _settings("System")))
    if view.invalid:
        items.append(Problem("secrets-invalid", "warn",
                             tr("config/secrets.env: the value of {keys} has line breaks or control characters and is "
                                "ignored", keys=", ".join(view.invalid)),
                             None, "/ajustes/sistema#env", _settings("System")))

    far = datetime.max.replace(tzinfo=UTC)
    items.sort(key=lambda p: (p.severity != "error", p.since or far))
    return items
