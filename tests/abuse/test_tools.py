"""Tests for the operator rate-limit reset CLI (app/abuse/tools.py)."""
import sqlite3

import pytest

from app.abuse import tools


def _seed(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE abuse_compose_rate_limit (client_ip TEXT, ts INTEGER)")
    conn.execute("CREATE TABLE abuse_send_rate_limit (scope TEXT, ts INTEGER)")
    conn.execute("CREATE TABLE username_rate_limit (scope TEXT, ts INTEGER)")
    conn.executemany("INSERT INTO abuse_compose_rate_limit VALUES (?, ?)",
                     [("1.2.3.4", 1), ("1.2.3.4", 2), ("9.9.9.9", 3)])
    conn.executemany("INSERT INTO abuse_send_rate_limit VALUES (?, ?)",
                     [("ip:1.2.3.4", 1), ("global", 2), ("recipient:x@y.com", 3)])
    conn.executemany("INSERT INTO username_rate_limit VALUES (?, ?)",
                     [("ip:1.2.3.4", 1), ("global", 2)])
    conn.commit()
    conn.close()


def test_reset_specific_endpoint(tmp_path):
    db = str(tmp_path / "t.db")
    _seed(db)
    assert tools.reset_rate_limit("1.2.3.4", ["compose"], db_path=db) == 2
    conn = sqlite3.connect(db)
    remaining = conn.execute("SELECT COUNT(*) FROM abuse_compose_rate_limit").fetchone()[0]
    conn.close()
    assert remaining == 1  # 9.9.9.9's row is untouched


def test_reset_all_only_touches_ip_scoped_rows(tmp_path):
    db = str(tmp_path / "t.db")
    _seed(db)
    # compose(2) + send ip:(1) + username ip:(1); the 6 other registry tables are
    # absent from this fixture DB and are skipped.
    assert tools.reset_rate_limit("1.2.3.4", list(tools.RATE_LIMIT_TABLES), db_path=db) == 4
    conn = sqlite3.connect(db)
    # 'global' + 'recipient:' rows in send survive; 'global' in username survives
    assert conn.execute("SELECT COUNT(*) FROM abuse_send_rate_limit").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM username_rate_limit").fetchone()[0] == 1
    conn.close()


def test_dry_run_deletes_nothing(tmp_path):
    db = str(tmp_path / "t.db")
    _seed(db)
    assert tools.reset_rate_limit("1.2.3.4", ["compose"], dry_run=True, db_path=db) == 2
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM abuse_compose_rate_limit").fetchone()[0] == 3
    conn.close()


def test_parser_rejects_unknown_endpoint():
    with pytest.raises(SystemExit):
        tools.build_parser().parse_args(["reset-rate-limit", "--ip", "1.2.3.4", "--endpoint", "bogus"])


def test_parser_requires_ip():
    with pytest.raises(SystemExit):
        tools.build_parser().parse_args(["reset-rate-limit"])
