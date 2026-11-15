"""Alert once when a problem appears and once when it is over (with how long it lasted).

The state lives in the settings table under ``alert:<key>`` as JSON
``{"since": iso, "alerted": bool, "fp": str}``, so it survives restarts and the recovery
message can say how long the problem lasted. Only the panel process calls this, never the CLI.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

PREFIX = "alert:"


def _events(state: Any):
    return state.events


def _load(state: Any, key: str) -> dict | None:
    raw = _events(state).get_value(PREFIX + key)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        data["since"] = datetime.fromisoformat(data["since"])
        return data
    except (ValueError, KeyError, TypeError):
        return None


def _save(state: Any, key: str, data: dict | None) -> None:
    if data is None:
        _events(state).conn.execute("DELETE FROM settings WHERE key = ?", (PREFIX + key,))
        _events(state).conn.commit()
        return
    _events(state).set_value(PREFIX + key, json.dumps(
        {"since": data["since"].isoformat(), "alerted": bool(data["alerted"]), "fp": data.get("fp", "")}))


def problem(state: Any, key: str, summary: str, *, domain: str | None = None,
            after: timedelta = timedelta(0), fingerprint: str = "", kind: str = "alert",
            now: datetime | None = None) -> bool:
    """Records that the problem is happening. Adds the event once it has lasted ``after``,
    and again only if ``fingerprint`` changes. Returns whether an event was added."""
    now = now or datetime.now(UTC)
    data = _load(state, key)
    if data is None:
        data = {"since": now, "alerted": False, "fp": fingerprint}
    elif data.get("fp", "") != fingerprint:
        data["fp"], data["alerted"] = fingerprint, False
    added = False
    if not data["alerted"] and now - data["since"] >= after:
        _events(state).add(actor="auto", kind=kind, domain=domain, summary=summary)
        data["alerted"] = added = True
    _save(state, key, data)
    return added


def clear(state: Any, key: str, summary: str | Callable[[timedelta], str] | None = None, *,
          domain: str | None = None, kind: str = "alert", now: datetime | None = None) -> timedelta | None:
    """The problem is over. Adds the recovery event (if it had been alerted and a summary is
    given) and returns how long it lasted; None if there was nothing open."""
    data = _load(state, key)
    if data is None:
        return None
    now = now or datetime.now(UTC)
    lasted = max(now - data["since"], timedelta(0))
    if data["alerted"] and summary is not None:
        text = summary(lasted) if callable(summary) else summary
        _events(state).add(actor="auto", kind=kind, domain=domain, summary=text)
    _save(state, key, None)
    return lasted


def active(state: Any, prefix: str = "") -> dict[str, dict]:
    """Open problems whose key starts with ``prefix``: key -> {"since", "alerted", "fp"}."""
    rows = _events(state).conn.execute(
        "SELECT key FROM settings WHERE key LIKE ? ESCAPE '\\'",
        (PREFIX + prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%",)).fetchall()
    out = {}
    for (full,) in rows:
        key = full[len(PREFIX):]
        data = _load(state, key)
        if data is not None:
            out[key] = data
    return out


def forget(state: Any, prefix: str) -> None:
    """Drops open problems silently (e.g. when a domain is deleted)."""
    for key in active(state, prefix):
        _save(state, key, None)


def minutes(lasted: timedelta) -> int:
    return max(1, round(lasted.total_seconds() / 60))
