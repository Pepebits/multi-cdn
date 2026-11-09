"""Estado del firewall del origen, que escribe multicdn-firewall.sh en la carpeta de datos.

El panel no tiene privilegios en el host: lee el JSON que deja el script y, para pedir una
actualización inmediata (antes de pasar a Gcore), crea un fichero que vigila una unidad
.path de systemd.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

MAX_AGE = timedelta(hours=48)   # el temporizador va cada 24 h
WHILE_ON_BACKUP = timedelta(hours=1)  # con tráfico por Gcore, rangos de como mucho 1 h


def data_dir() -> Path:
    return Path(os.environ.get("MULTICDN_DB", "data/multicdn.db")).parent


@dataclass
class FirewallStatus:
    checked_at: datetime | None
    last_ok: datetime | None
    ipv4: int
    ipv6: int
    caddy: str
    error: str
    added: int = 0
    removed: int = 0

    def problem(self, now: datetime) -> str | None:
        if self.error:
            return f"la última actualización falló: {self.error}"
        if self.last_ok is None:
            return "todavía no se ha aplicado ninguna lista"
        if now - self.last_ok > MAX_AGE:
            return f"los rangos no se actualizan desde {self.last_ok:%d/%m %H:%M} UTC"
        return None


def _dt(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
    except ValueError:
        return None


def read() -> FirewallStatus | None:
    path = data_dir() / "firewall-status.json"
    try:
        raw = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return FirewallStatus(_dt(raw.get("checked_at")), _dt(raw.get("last_ok")), int(raw.get("ipv4") or 0),
                          int(raw.get("ipv6") or 0), str(raw.get("caddy") or ""), str(raw.get("error") or ""),
                          int(raw.get("added") or 0), int(raw.get("removed") or 0))


def changes(limit: int = 10) -> list[tuple[datetime, int, int]]:
    """Últimas actualizaciones aplicadas: (momento, rangos que entran, rangos que salen)."""
    try:
        lines = (data_dir() / "firewall-changes.log").read_text().splitlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            ts, added, removed = line.split()
            out.append((_dt(ts), int(added.lstrip("+")), int(removed.lstrip("-"))))
        except ValueError:
            continue
    return [c for c in out if c[0]]


def request_refresh() -> bool:
    """Pide al host que actualice ya los rangos. Sin el script instalado no hace nada útil."""
    try:
        (data_dir() / "firewall-refresh-request").write_text(datetime.now(UTC).isoformat())
        return True
    except OSError:
        return False


def check(state, now: datetime | None = None) -> None:
    """Avisa una vez cuando aparece un problema y otra cuando se resuelve."""
    now = now or datetime.now(UTC)
    status = read()
    if status is None:
        return  # el script no está instalado (p. ej. en local): nada que vigilar
    serving_backup = any(r.provider == "gcore" for r in state.resolutions.values())
    if serving_backup and (status.last_ok is None or now - status.last_ok > WHILE_ON_BACKUP) \
            and not (data_dir() / "firewall-refresh-request").exists():
        request_refresh()
    problem = status.problem(now)
    previous = state.events.get_value("firewall_problem") or ""
    if problem and problem != previous:
        state.events.add(actor="auto", kind="alert", summary=f"Firewall del origen: {problem}")
        state.events.set_value("firewall_problem", problem)
    elif not problem and previous:
        state.events.add(actor="auto", kind="alert", summary="Firewall del origen: rangos actualizados de nuevo")
        state.events.set_value("firewall_problem", "")
