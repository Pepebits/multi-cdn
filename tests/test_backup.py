import os
import sqlite3

from app import backup


def test_backup_is_consistent_and_rotated(tmp_path, monkeypatch):
    db = tmp_path / "data" / "multicdn.db"
    db.parent.mkdir()
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE t (x)")
        c.execute("INSERT INTO t VALUES (42)")
    monkeypatch.setenv("MULTICDN_DB", str(db))
    for i in range(4):
        (db.parent / "backups").mkdir(exist_ok=True)
        (db.parent / "backups" / f"multicdn-2026010{i}-000000.db").write_text("old")
    out = backup.backup(keep=3)
    assert sqlite3.connect(out).execute("SELECT x FROM t").fetchone() == (42,)
    assert oct(out.stat().st_mode)[-3:] == "600"
    assert len(list((db.parent / "backups").glob("*.db"))) == 3 and out.exists()


def test_backup_is_standalone_private_and_prunes_sidecars(tmp_path, monkeypatch):
    db = tmp_path / "data" / "multicdn.db"
    db.parent.mkdir()
    keep_open = sqlite3.connect(db)
    keep_open.execute("PRAGMA journal_mode=WAL")
    keep_open.execute("CREATE TABLE t (x)")
    keep_open.execute("INSERT INTO t VALUES (7)")
    keep_open.commit()
    monkeypatch.setenv("MULTICDN_DB", str(db))
    folder = db.parent / "backups"
    folder.mkdir()
    for i in range(3):
        for suffix in ("", "-wal", "-shm"):
            (folder / f"multicdn-2026010{i}-000000.db{suffix}").write_text("old")
    (folder / "multicdn-20251231-000000.db-wal").write_text("orphan")
    (folder / "other.txt").write_text("untouched")

    created = []
    real_connect = sqlite3.connect

    def spy(path, *a, **kw):  # permisos del fichero en el momento en que SQLite lo abre
        if str(path).startswith(str(folder)):
            created.append(oct(os.stat(path).st_mode)[-3:])
        return real_connect(path, *a, **kw)

    monkeypatch.setattr(backup.sqlite3, "connect", spy)
    out = backup.backup(keep=2)
    keep_open.close()
    assert created == ["600"]
    assert real_connect(out).execute("PRAGMA journal_mode").fetchone() == ("delete",)
    assert real_connect(out).execute("SELECT x FROM t").fetchone() == (7,)
    names = sorted(p.name for p in folder.iterdir())
    assert names == ["multicdn-20260102-000000.db", "multicdn-20260102-000000.db-shm",
                     "multicdn-20260102-000000.db-wal", out.name, "other.txt"]
