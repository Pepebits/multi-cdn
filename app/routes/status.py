"""Machine endpoints: the state fingerprint the panel polls for auto-refresh, and the health check."""

from __future__ import annotations

import os
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.responses import Response

from .. import heartbeat
from .common import _state, state_version

router = APIRouter()


@router.get("/api/estado")
async def api_estado(request: Request):
    s = _state(request)
    return {"version": state_version(s), "dns_checked_at": s.dns_checked_at,
            "feed": s.feed.last_update if s.feed else None}


@router.get("/healthz")
async def healthz(request: Request, response: Response):
    """Are the panel's own loops alive? (ADR-002). Third-party failures (feed, calendar, tokens)
    do not count. No free text in the body: it is public."""
    s = _state(request)
    now = datetime.now(UTC)
    grace = os.environ.get("MULTICDN_OFFLINE") == "1" or now - s.started_at < heartbeat.STARTUP_GRACE
    stale = [] if grace else heartbeat.liveness(s, now)
    if stale:
        response.status_code = 503
    return {"ok": not stale, "stale": stale, "feed": s.feed is not None, "dns_checked_at": s.dns_checked_at}
