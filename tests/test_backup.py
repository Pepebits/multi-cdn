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


def test_a_good_copy_passes_verify_and_a_damaged_one_does_not(client, tmp_path):
    """The panel's real database (via the client) copied and checked; then a broken copy."""
    from app.backup import backup, verify
    good = backup(tmp_path / "good.db")
    assert verify(good) is None
    damaged = tmp_path / "damaged.db"
    damaged.write_bytes(good.read_bytes()[:4096] + b"\0" * 4096)  # truncated and zeroed
    assert verify(damaged) is not None
    empty = tmp_path / "empty.db"
    sqlite3.connect(empty).execute("CREATE TABLE x (a)").connection.close()
    assert "missing tables" in verify(empty)


def test_daily_backup_alerts_when_the_copy_fails_and_when_it_works_again(client, monkeypatch):
    import asyncio
    from app import backup as backup_mod
    from app import tasks
    state = client.app.state.mc
    real_backup = backup_mod.backup
    monkeypatch.setattr(backup_mod, "backup", lambda: (_ for _ in ()).throw(OSError(28, "No space left on device")))
    asyncio.run(tasks.daily_backup(state))
    errors = [e.summary for e in state.events.list(limit=5) if e.kind == "error"]
    assert errors == ["Ha fallado la copia diaria de la base de datos: OSError: [Errno 28] No space left on device"]
    monkeypatch.setattr(backup_mod, "backup", real_backup)  # only this: undo() would also drop the client's env
    asyncio.run(tasks.daily_backup(state))
    assert state.events.list(limit=1)[0].summary == "La copia diaria de la base de datos vuelve a funcionar"


def test_cli_backup_checks_the_copy(client, tmp_path, capsys):
    from app import cli
    assert cli.main(["backup", str(tmp_path / "copy.db")]) == 0
    assert "comprobada" in capsys.readouterr().out
