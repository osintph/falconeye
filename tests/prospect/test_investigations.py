"""
Tests for write_investigation() and the dossier retention sweep.

v3.39.0: the Company tab no longer stores anything derived from the caller's
IP (the unsalted SHA-256 it used to keep was never read), and dossiers older
than PROSPECT_RETENTION_DAYS are deleted by sweep_expired(), which the sweep
timer runs every 15 minutes. These run against a real SQLite file in tmp_path.
"""
import json
import os
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import pytest

from app.prospect import investigations as inv


@pytest.fixture()
def store(tmp_path, monkeypatch):
    db = tmp_path / "falconeye.db"
    monkeypatch.setattr(inv, "_DB_PATH", str(db))
    monkeypatch.setattr(inv, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(inv, "_PROSPECT_DIR", tmp_path / "prospect")
    inv._init_table()
    return tmp_path


def _rows(store):
    conn = sqlite3.connect(str(store / "falconeye.db"))
    try:
        return conn.execute("SELECT * FROM prospect_investigations").fetchall()
    finally:
        conn.close()


def _iso(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def test_write_investigation_returns_uuid_and_writes_the_dossier(store):
    dossier = {"domain": "stripe.com", "sections": {"about_domain": {"title": "x"}}, "errors": []}
    inv_id = inv.write_investigation("stripe.com", _iso(0), dossier)
    assert re.match(r"^[0-9a-f-]{36}$", inv_id)
    path = store / "prospect" / f"{inv_id}.json"
    assert json.loads(path.read_text()) == dossier
    (row,) = _rows(store)
    assert row[0] == inv_id and row[1] == "stripe.com" and row[3] == f"prospect/{inv_id}.json"


def test_no_ip_derived_value_is_stored(store):
    """The table has no IP column at all, and the function takes no IP."""
    conn = sqlite3.connect(str(store / "falconeye.db"))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(prospect_investigations)")]
    conn.close()
    assert "ip_hash" not in cols
    import inspect
    assert "client_ip" not in inspect.signature(inv.write_investigation).parameters


def test_an_unmigrated_database_gets_an_empty_ip_column(store):
    """Before the 3.39.0 release action drops the NOT NULL column, a write must
    still succeed and must not put an IP hash in it."""
    db = str(store / "falconeye.db")
    conn = sqlite3.connect(db)
    conn.execute("DROP TABLE prospect_investigations")
    conn.execute("CREATE TABLE prospect_investigations (investigation_id TEXT PRIMARY KEY, "
                 "domain TEXT NOT NULL, generated_at TEXT NOT NULL, dossier_json_path TEXT NOT NULL, "
                 "ip_hash TEXT NOT NULL)")
    conn.commit()
    conn.close()
    inv.write_investigation("example.com", _iso(0), {})
    (row,) = _rows(store)
    assert row[4] == ""


def test_write_survives_a_db_error(store, monkeypatch):
    def boom(*a, **k):
        raise sqlite3.OperationalError("disk full")
    monkeypatch.setattr(inv.sqlite3, "connect", boom)
    inv_id = inv.write_investigation("crash.com", _iso(0), {})
    assert re.match(r"^[0-9a-f-]{36}$", inv_id)


def test_sweep_deletes_only_dossiers_older_than_the_retention(store):
    old = inv.write_investigation("old.example", _iso(31), {"a": 1})
    new = inv.write_investigation("new.example", _iso(1), {"b": 2})
    out = inv.sweep_expired(30)
    assert out == {"rows": 1, "files": 1}
    ids = [r[0] for r in _rows(store)]
    assert ids == [new]
    assert not (store / "prospect" / f"{old}.json").exists()
    assert (store / "prospect" / f"{new}.json").exists()


def test_sweep_uses_the_configured_default(store, monkeypatch):
    monkeypatch.setattr(inv.config, "PROSPECT_RETENTION_DAYS", 5)
    inv.write_investigation("six.example", _iso(6), {})
    inv.write_investigation("four.example", _iso(4), {})
    assert inv.sweep_expired()["rows"] == 1


def test_sweep_removes_orphan_files_past_the_cutoff(store):
    d = store / "prospect"
    d.mkdir(exist_ok=True)
    orphan = d / "orphan.json"
    orphan.write_text("{}")
    past = time.time() - 40 * 86400
    os.utime(orphan, (past, past))
    fresh = d / "fresh.json"
    fresh.write_text("{}")
    out = inv.sweep_expired(30)
    assert out["files"] == 1
    assert not orphan.exists() and fresh.exists()


def test_retention_default_is_30_days():
    from app import config
    assert config.PROSPECT_RETENTION_DAYS == 30
