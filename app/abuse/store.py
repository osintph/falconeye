"""
SQLite persistence for the abuse-reporting feature.

Holds the RDAP abuse-contact cache, the three per-endpoint rate-limit tables,
and the append-only send audit log. Tables self-initialize at import time,
mirroring the pattern used by the other routers (see routers/dork_generator.py).

The DB path is resolved dynamically from FALCONEYE_DB on every connect so the
same code works against the live SQLite file in production and a throwaway
temp file under pytest, without depending on import order.
"""
import json
import logging
import os
import sqlite3
import time

from app.config import DB_PATH as _DB_DEFAULT

log = logging.getLogger("falconeye.abuse")

CONTACT_CACHE_TTL_SECONDS = 24 * 3600
_CLEANUP_AGE_SECONDS = 48 * 3600


def _db_path() -> str:
    return os.getenv("FALCONEYE_DB", _DB_DEFAULT)


def _connect() -> sqlite3.Connection:
    return sqlite3.connect(_db_path())


def init_tables() -> None:
    """Create all abuse-reporting tables if absent. Idempotent."""
    conn = _connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS abuse_contact_cache (
              target TEXT NOT NULL,
              target_type TEXT NOT NULL,
              abuse_email TEXT,
              network_name TEXT,
              raw_json TEXT,
              cached_at INTEGER NOT NULL,
              PRIMARY KEY (target, target_type)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_abuse_contact_cached_at ON abuse_contact_cache(cached_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_abuse_contact_email ON abuse_contact_cache(abuse_email)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS abuse_lookup_rate_limit (
              client_ip TEXT NOT NULL,
              ts INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_abuse_lookup_rl_ip_ts ON abuse_lookup_rate_limit(client_ip, ts)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS abuse_compose_rate_limit (
              client_ip TEXT NOT NULL,
              ts INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_abuse_compose_rl_ip_ts ON abuse_compose_rate_limit(client_ip, ts)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS abuse_send_rate_limit (
              scope TEXT NOT NULL,
              ts INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_abuse_send_rl_scope_ts ON abuse_send_rate_limit(scope, ts)"
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS abuse_send_audit (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts INTEGER NOT NULL,
              client_ip TEXT NOT NULL,
              recipient_email TEXT NOT NULL,
              target TEXT NOT NULL,
              target_type TEXT NOT NULL,
              category TEXT NOT NULL,
              subject TEXT NOT NULL,
              mailgun_message_id TEXT,
              success INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_abuse_send_audit_ts ON abuse_send_audit(ts)"
        )
        conn.commit()
    finally:
        conn.close()


try:
    init_tables()
except Exception as exc:  # pragma: no cover - only trips when DB path is unwritable at import
    log.warning("abuse: deferred table init (DB not ready at import): %s", exc)


# ---------- contact cache ----------

def get_cached_contact(target: str, target_type: str) -> dict | None:
    """Return a cached lookup result within the 24h TTL, or None."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT raw_json, cached_at FROM abuse_contact_cache WHERE target = ? AND target_type = ?",
            (target, target_type),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    raw_json, cached_at = row
    if (time.time() - cached_at) > CONTACT_CACHE_TTL_SECONDS:
        return None
    try:
        data = json.loads(raw_json)
    except (ValueError, TypeError):
        return None
    data["cache_hit"] = True
    return data


def store_cached_contact(target: str, target_type: str, abuse_email, network_name, result: dict) -> None:
    conn = _connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO abuse_contact_cache "
            "(target, target_type, abuse_email, network_name, raw_json, cached_at) VALUES (?, ?, ?, ?, ?, ?)",
            (target, target_type, abuse_email, network_name, json.dumps(result), int(time.time())),
        )
        conn.commit()
    except Exception as exc:
        log.error("abuse_contact_cache write failed for %s/%s: %s", target, target_type, exc)
    finally:
        conn.close()


def recipient_seen_in_cache(email: str) -> bool:
    """True if *email* was returned as an abuse contact by some prior RDAP lookup.

    Gate for the send endpoint: never send to an address the tool did not itself
    resolve, even with valid admin auth. TTL is intentionally ignored here — an
    address that was ever a legitimate RDAP-derived contact stays sendable.
    """
    if not email:
        return False
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM abuse_contact_cache WHERE abuse_email = ? COLLATE NOCASE "
            "AND abuse_email IS NOT NULL AND abuse_email != '' LIMIT 1",
            (email.strip(),),
        ).fetchone()
    finally:
        conn.close()
    return row is not None


# ---------- rate limits ----------
# `table` and `column` are always internal literals (never user input), so the
# f-string interpolation below is safe from injection.

_RL_TABLES = {
    "abuse_lookup_rate_limit": "client_ip",
    "abuse_compose_rate_limit": "client_ip",
    "abuse_send_rate_limit": "scope",
}


def count_recent(table: str, column: str, value: str, window_seconds: int) -> int:
    assert table in _RL_TABLES and _RL_TABLES[table] == column
    cutoff = int(time.time()) - window_seconds
    conn = _connect()
    try:
        row = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE {column} = ? AND ts > ?",
            (value, cutoff),
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row else 0


def record_event(table: str, column: str, value: str) -> None:
    assert table in _RL_TABLES and _RL_TABLES[table] == column
    now = int(time.time())
    conn = _connect()
    try:
        conn.execute(f"INSERT INTO {table} ({column}, ts) VALUES (?, ?)", (value, now))
        conn.execute(f"DELETE FROM {table} WHERE ts < ?", (now - _CLEANUP_AGE_SECONDS,))
        conn.commit()
    except Exception as exc:
        log.error("rate-limit write failed on %s: %s", table, exc)
    finally:
        conn.close()


# ---------- audit ----------

def record_audit(client_ip, recipient_email, target, target_type, category, subject,
                 mailgun_message_id, success: bool) -> None:
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO abuse_send_audit "
            "(ts, client_ip, recipient_email, target, target_type, category, subject, mailgun_message_id, success) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (int(time.time()), client_ip, recipient_email, target, target_type,
             category, subject, mailgun_message_id, 1 if success else 0),
        )
        conn.commit()
    except Exception as exc:
        log.error("abuse_send_audit write failed: %s", exc)
    finally:
        conn.close()
