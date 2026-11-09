"""Copia de seguridad de la base de datos (consistente aunque el panel esté escribiendo).

Las credenciales van cifradas dentro: sin MULTICDN_SECRET_KEY la copia no las expone.
Guarda las copias en data/backups y conserva las últimas KEEP.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

KEEP = 14


def db_path() -> Path:
    return Path(os.environ.get("MULTICDN_DB", "data/multicdn.db"))


def backup(dest: Path | None = None, keep: int = KEEP) -> Path:
    src = db_path()
    folder = src.parent / "backups"
    dest = dest or folder / f"multicdn-{datetime.now(UTC):%Y%m%d-%H%M%S}.db"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(src) as source, sqlite3.connect(dest) as target:
        source.backup(target)
    os.chmod(dest, 0o600)
    if dest.parent == folder:
        for old in sorted(folder.glob("multicdn-*.db"))[:-keep]:
            old.unlink()
    return dest
