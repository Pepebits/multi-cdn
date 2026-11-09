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
