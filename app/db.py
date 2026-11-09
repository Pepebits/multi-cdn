"""Historial de auditoría en SQLite."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .i18n import tr

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    domain TEXT,
    actor TEXT NOT NULL,          -- auto | <usuario>
    kind TEXT NOT NULL,           -- switch | alert | verify | error
    summary TEXT NOT NULL,
    transition TEXT,              -- p. ej. "CF → GCORE"
    dns_diff TEXT,                -- JSON [[hostname, antes, después], ...]
    signals TEXT,                 -- JSON [str, ...]
    simulated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts DESC);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

RETENTION_DEFAULTS = {"events_max_days": 180, "events_max_rows": 20000, "auto_switch": 1, "gcore_quota_gb": 1000}
RETENTION_LIMITS = {"events_max_days": (7, 3650), "events_max_rows": (500, 1_000_000), "auto_switch": (0, 1), "gcore_quota_gb": (1, 1_000_000)}


@dataclass
class Event:
    id: int
    ts: datetime
    domain: str | None
    actor: str
    kind: str
    summary: str
    transition: str | None
    dns_diff: list[list[str]]
    signals: list[str]
    simulated: bool


class EventStore:
    def __init__(self, path: str | Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("PRAGMA auto_vacuum=INCREMENTAL")  # solo afecta a bases nuevas
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.listeners: list = []  # p. ej. el Notifier

    def add(
        self,
        *,
        actor: str,
        kind: str,
        summary: str,
        domain: str | None = None,
        transition: str | None = None,
        dns_diff: list[list[str]] | None = None,
        signals: list[str] | None = None,
        simulated: bool = False,
    ) -> None:
        self.conn.execute(
            "INSERT INTO events (ts, domain, actor, kind, summary, transition, dns_diff, signals, simulated)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now(UTC).isoformat(timespec="seconds"),
                domain,
                actor,
                kind,
                summary,
                transition,
                json.dumps(dns_diff or []),
                json.dumps(signals or []),
                int(simulated),
            ),
        )
        self.conn.commit()
        event = {"actor": actor, "kind": kind, "summary": summary, "domain": domain, "transition": transition,
                 "dns_diff": dns_diff or [], "signals": signals or [], "simulated": simulated}
        for listener in self.listeners:
            try:
                listener(event)
            except Exception:  # un aviso fallido nunca debe impedir registrar el evento
                pass

    # ---------- ajustes y retención ----------
    def get_setting(self, key: str) -> int:
        row = self.conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return int(row[0]) if row else RETENTION_DEFAULTS[key]

    def set_setting(self, key: str, value: int) -> None:
        lo, hi = RETENTION_LIMITS[key]
        if not lo <= value <= hi:
            raise ValueError(tr("value out of range ({lo}–{hi})", lo=lo, hi=hi))
        self.conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                          (key, str(value)))
        self.conn.commit()

    # Valores libres del motor y los avisos (sin validación): p. ej. el último nivel de consumo avisado.
    def get_value(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_value(self, key: str, value: str) -> None:
        self.conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                          (key, value))
        self.conn.commit()

    def stats(self) -> dict:
        count, oldest = self.conn.execute("SELECT COUNT(*), MIN(ts) FROM events").fetchone()
        return {"count": count, "oldest": datetime.fromisoformat(oldest) if oldest else None}

    def prune(self) -> int:
        """Borra eventos más antiguos que el límite de días y, después, los que excedan el máximo."""
        days, max_rows = self.get_setting("events_max_days"), self.get_setting("events_max_rows")
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat(timespec="seconds")
        deleted = self.conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,)).rowcount
        deleted += self.conn.execute(
            "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY ts DESC, id DESC LIMIT ?)", (max_rows,)
        ).rowcount
        self.conn.commit()
        if deleted:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.conn.execute("PRAGMA incremental_vacuum")
        return deleted

    def list(self, domain: str | None = None, actor: str | None = None, limit: int = 100) -> list[Event]:
        sql = "SELECT * FROM events WHERE 1=1"
        args: list = []
        if domain:
            sql += " AND domain = ?"
            args.append(domain)
        if actor == "auto":
            sql += " AND actor = 'auto'"
        elif actor == "manual":
            sql += " AND actor != 'auto'"
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        args.append(limit)
        rows = self.conn.execute(sql, args).fetchall()
        return [
            Event(
                id=r[0],
                ts=datetime.fromisoformat(r[1]),
                domain=r[2],
                actor=r[3],
                kind=r[4],
                summary=r[5],
                transition=r[6],
                dns_diff=json.loads(r[7] or "[]"),
                signals=json.loads(r[8] or "[]"),
                simulated=bool(r[9]),
            )
            for r in rows
        ]
