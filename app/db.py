"""Historial de auditoría en SQLite."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .error_reporting import scrub_origin
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
    simulated INTEGER NOT NULL DEFAULT 0,
    code TEXT                     -- código estable para la lógica (ver event_codes); NULL si no hace falta
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts DESC);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

RETENTION_DEFAULTS = {"events_max_days": 180, "events_max_rows": 20000, "auto_switch": 1, "gcore_quota_gb": 1000, "feed_interval": 300}
RETENTION_LIMITS = {"events_max_days": (7, 3650), "events_max_rows": (500, 1_000_000), "auto_switch": (0, 1), "gcore_quota_gb": (1, 1_000_000), "feed_interval": (90, 300)}


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
    code: str | None = None


class EventStore:
    def __init__(self, path: str | Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("PRAGMA auto_vacuum=INCREMENTAL")  # solo afecta a bases nuevas
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        if "code" not in {r[1] for r in self.conn.execute("PRAGMA table_info(events)")}:
            self.conn.execute("ALTER TABLE events ADD COLUMN code TEXT")  # bases anteriores a 0.3.4
        self.listeners: list = []  # p. ej. el Notifier
        # Provider texts lose the origin IP before being stored or sent as alerts (ADR-003).
        self.scrubber = scrub_origin

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
        code: str | None = None,
    ) -> None:
        summary = self._scrub(summary)
        dns_diff = [[self._scrub(c) if isinstance(c, str) else c for c in row] for row in dns_diff or []]
        signals = [self._scrub(x) if isinstance(x, str) else x for x in signals or []]
        self.conn.execute(
            "INSERT INTO events (ts, domain, actor, kind, summary, transition, dns_diff, signals, simulated, code)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now(UTC).isoformat(timespec="seconds"),
                domain,
                actor,
                kind,
                summary,
                transition,
                json.dumps(dns_diff),
                json.dumps(signals),
                int(simulated),
                code,
            ),
        )
        self.conn.commit()
        event = {"actor": actor, "kind": kind, "summary": summary, "domain": domain, "transition": transition,
                 "dns_diff": dns_diff, "signals": signals, "simulated": simulated, "code": code}
        for listener in self.listeners:
            try:
                listener(event)
            except Exception:  # un aviso fallido nunca debe impedir registrar el evento
                pass

    def _scrub(self, text):
        return self.scrubber(text) if self.scrubber and text else text

    def scrub_history(self) -> int:
        """Applies the scrubber to what is already stored (events written before 0.3.0 and the
        engine's last error). Idempotent; run at every start. Returns the rows changed."""
        changed = []
        for row_id, summary, diff, signals in self.conn.execute("SELECT id, summary, dns_diff, signals FROM events"):
            new_summary = self._scrub(summary)
            new_diff = self._scrub_json(diff)
            new_signals = self._scrub_json(signals)
            if (new_summary, new_diff, new_signals) != (summary, diff, signals):
                changed.append((new_summary, new_diff, new_signals, row_id))
        self.conn.executemany("UPDATE events SET summary=?, dns_diff=?, signals=? WHERE id=?", changed)
        n = len(changed)
        if self.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='failover_state'").fetchone():
            rows = self.conn.execute("SELECT domain, last_error FROM failover_state WHERE last_error IS NOT NULL").fetchall()
            errors = [(new, domain) for domain, old in rows if (new := self._scrub(old)) != old]
            self.conn.executemany("UPDATE failover_state SET last_error=? WHERE domain=?", errors)
            n += len(errors)
        self.conn.commit()
        return n

    def _scrub_json(self, raw: str | None) -> str | None:
        """Scrubs the strings of a stored JSON list (dns_diff rows or signals), keeping it as is if unchanged."""
        if not raw:
            return raw
        try:
            value = json.loads(raw)
        except ValueError:
            return self._scrub(raw)

        def walk(v):
            if isinstance(v, str):
                return self._scrub(v)
            if isinstance(v, list):
                return [walk(x) for x in v]
            return v
        new = walk(value)
        return raw if new == value else json.dumps(new)

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

    def last_with_code(self, domain: str, codes: tuple[str, ...]) -> Event | None:
        """El evento más reciente del dominio con alguno de esos códigos (sin límite de antigüedad)."""
        marks = ", ".join("?" * len(codes))
        row = self.conn.execute(f"SELECT {self._COLUMNS} FROM events WHERE domain = ? AND code IN ({marks})"
                                " ORDER BY ts DESC, id DESC LIMIT 1", (domain, *codes)).fetchone()
        return self._event(row) if row else None

    _COLUMNS = "id, ts, domain, actor, kind, summary, transition, dns_diff, signals, simulated, code"

    @staticmethod
    def _event(r) -> Event:
        return Event(id=r[0], ts=datetime.fromisoformat(r[1]), domain=r[2], actor=r[3], kind=r[4], summary=r[5],
                     transition=r[6], dns_diff=json.loads(r[7] or "[]"), signals=json.loads(r[8] or "[]"),
                     simulated=bool(r[9]), code=r[10])

    def list(self, domain: str | None = None, actor: str | None = None, limit: int = 100) -> list[Event]:
        sql = f"SELECT {self._COLUMNS} FROM events WHERE 1=1"
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
        return [self._event(r) for r in self.conn.execute(sql, args).fetchall()]
