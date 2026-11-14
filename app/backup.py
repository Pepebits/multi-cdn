"""Copia de seguridad de la base de datos (consistente aunque el panel esté escribiendo).

Las credenciales van cifradas dentro: sin MULTICDN_SECRET_KEY la copia no las expone.
Guarda las copias en data/backups y conserva las últimas KEEP.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

KEEP = 14


def db_path() -> Path:
    return Path(os.environ.get("MULTICDN_DB", "data/multicdn.db"))


SIDECARS = ("-wal", "-shm", "-journal")


def backup(dest: Path | None = None, keep: int = KEEP) -> Path:
    src = db_path()
    folder = src.parent / "backups"
    dest = dest or folder / f"multicdn-{datetime.now(UTC):%Y%m%d-%H%M%S}.db"
    dest.parent.mkdir(parents=True, exist_ok=True)
    # El fichero nace con 0600 antes de que SQLite escriba nada (los ficheros auxiliares que
    # crea SQLite heredan los permisos de la base de datos).
    os.close(os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600))
    os.chmod(dest, 0o600)  # si ya existía con otros permisos
    with closing(sqlite3.connect(src)) as source, closing(sqlite3.connect(dest)) as target:
        source.backup(target)
        # La copia hereda el modo WAL del original: una copia autónoma, sin -wal ni -shm.
        target.execute("PRAGMA journal_mode=DELETE")
    if dest.parent == folder:
        prune(folder, keep)
    return dest


def prune(folder: Path, keep: int = KEEP) -> None:
    """Conserva las últimas `keep` copias y borra sus ficheros auxiliares y los huérfanos."""
    copies = sorted(folder.glob("multicdn-*.db"))
    for old in copies[:-keep] if keep > 0 else copies:
        for f in (old, *(old.with_name(old.name + s) for s in SIDECARS)):
            f.unlink(missing_ok=True)
    for suffix in SIDECARS:
        for side in folder.glob(f"multicdn-*.db{suffix}"):
            if not side.with_name(side.name.removesuffix(suffix)).exists():
                side.unlink(missing_ok=True)
