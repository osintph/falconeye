"""
SQLite rate-limit persistence for the Username Enumeration tab.

Self-initializes its table at import (the pattern the abuse tab established, and
which v3.7.1 hardened after ip_intel's missing self-init 500'd on a fresh DB).
DB path is resolved from FALCONEYE_DB on every connect so tests can point it at
a temp file regardless of import order.
"""
import logging
import os
import sqlite3
import time

from app.config import DB_PATH as _DB_DEFAULT

log = logging.getLogger("falconeye.username")

_CLEANUP_AGE_SECONDS = 48 * 3600


def _db_path() -> str:
    return os.getenv("FALCONEYE_DB", _DB_DEFAULT)


def _connect() -> sqlite3.Connection:
    return sqlite3.connect(_db_path())


def init_tables() -> None:
    conn = _connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS username_rate_limit (
              scope TEXT NOT NULL,
              ts INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_username_rl_scope_ts ON username_rate_limit(scope, ts)"
        )
        conn.commit()
    finally:
        conn.close()


try:
    init_tables()
except Exception as exc:  # pragma: no cover - only when DB path is unwritable at import
    log.warning("username: deferred table init (DB not ready at import): %s", exc)


# A rate limiter must fail closed: if the count can't be read, report a count
# above any real cap so the caller's `>=` check blocks the request, rather than
# silently letting scans through (or raising an unhandled 500) on a DB hiccup.
_FAIL_CLOSED_COUNT = 10**9


def count_recent(scope: str, window_seconds: int) -> int:
    cutoff = int(time.time()) - window_seconds
    conn = None
    try:
        conn = _connect()
        row = conn.execute(
            "SELECT COUNT(*) FROM username_rate_limit WHERE scope = ? AND ts > ?",
            (scope, cutoff),
        ).fetchone()
        return row[0] if row else 0
    except Exception as exc:
        log.error("username rate-limit read failed (failing closed): %s", exc)
        return _FAIL_CLOSED_COUNT
    finally:
        if conn is not None:
            conn.close()


def record_event(scope: str) -> None:
    now = int(time.time())
    conn = _connect()
    try:
        conn.execute("INSERT INTO username_rate_limit (scope, ts) VALUES (?, ?)", (scope, now))
        conn.execute("DELETE FROM username_rate_limit WHERE ts < ?", (now - _CLEANUP_AGE_SECONDS,))
        conn.commit()
    except Exception as exc:
        log.error("username rate-limit write failed: %s", exc)
    finally:
        conn.close()
