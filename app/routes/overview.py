"""Overview page, the auto-refresh state endpoint and the health check."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..engine import failover
from ..problems import open_problems
from ..state import State
from .common import (
    _common,
    _state,
    templates,
)

router = APIRouter()


# ---------------------------------------------------------------- Resumen

def getting_started(s: State, domains) -> list[dict]:
    """Setup checklist on the overview, in the order of deploy/README.md. The template holds
    the texts; this only says which steps are done."""
    sec = s.secrets
    return [
        {"key": "cloudflare", "done": bool(s.creds.list("cloudflare")), "href": "/ajustes/cuentas"},
        {"key": "gcore", "done": bool(s.creds.list("gcore")), "href": "/ajustes/cuentas"},
        {"key": "origin", "done": bool(s.inventory.origin_ips), "href": "/ajustes/servidores"},
        {"key": "domains", "done": any(d.cloudflare_credential for d in s.inventory.domains.values()),
         "href": "/dominios/importar"},
        {"key": "prepare", "done": any(d.gcore_ready for d in domains), "href": "/dominios"},
        {"key": "alerts", "done": bool((sec.get("telegram_token") and sec.get("telegram_chat_id"))
                                       or (sec.get("smtp_url") and sec.get("alert_email_to"))),
         "href": "/ajustes/notificaciones"},
        {"key": "live", "done": not s.dry_run, "href": "/ajustes/cambio#modo"},
    ]


@router.get("/", response_class=HTMLResponse)
async def resumen(request: Request):
    s = _state(request)
    domains = s.views()
    steps = getting_started(s, domains)
    return templates.TemplateResponse(request, "resumen.html", _common(
        request, "resumen",
        domains=domains,
        exposed=[d for d in domains if d.status == "origin"],
        changes={d.name: failover.change_indicator(s, d.name) for d in domains},
        autos={d.name: failover.describe(s, d.name) for d in domains},
        events=s.events.list(limit=5),
        origin_configured=bool(s.inventory.origin_ips),
        origin_health=list(s.origin_health.values()),
        gcore_configured=any(d.gcore_ready for d in domains),
        usage=list(s.gcore_usage.values()),
        match_now=s.calendar.active(datetime.now(UTC), failover.match_lead(s, "critical")) if s.calendar else None,
        match_next=s.calendar.upcoming(datetime.now(UTC)) if s.calendar else None,
        calendar_error=s.calendar_error,
        steps=steps if not all(st["done"] for st in steps) else None,
        calendar_loaded=s.calendar is not None,
        problems=open_problems(s),
    ))
