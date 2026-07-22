"""
SQLite persistence for the Breach Check tab (HIBP integration).

Self-initializes its tables at import, mirroring every other tab (username,
abuse, telegram) so a fresh (non-migrated) DB never 500s. DB path is resolved
from FALCONEYE_DB on every connect so tests can point it at a temp file
regardless of import order.

One generic cache table (`breach_cache`) backs every HIBP cache kind (email
breach+paste results, per-breach metadata, domain results, the bulk breach
list, the latest-breach pointer, the data-classes list) — the caller supplies
the TTL, so a single get/set pair covers the 24h/12h/6h/1h/indefinite tiers
the spec calls for. `ttl_seconds=None` means "never expires" (breach metadata
and the data-classes list don't change).

Privacy: emails are NEVER stored in plaintext. `email_cache_key` returns
SHA-256(normalized email); the raw address never reaches this module.
"""
import hashlib
import json
import logging
import os
import sqlite3
import time

from app.config import DB_PATH as _DB_DEFAULT

log = logging.getLogger("falconeye.breach")

_CLEANUP_AGE_SECONDS = 48 * 3600

ALL_BREACHES_KEY = "misc:all_breaches"
LATEST_BREACH_KEY = "misc:latest_breach"
DATACLASSES_KEY = "misc:dataclasses"


def _db_path() -> str:
    return os.getenv("FALCONEYE_DB", _DB_DEFAULT)


def _connect() -> sqlite3.Connection:
    return sqlite3.connect(_db_path())


def init_tables() -> None:
    conn = _connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS breach_cache (
              cache_key TEXT PRIMARY KEY,
              payload_json TEXT NOT NULL,
              cached_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS breach_rate_limit (
              scope TEXT NOT NULL,
              ts INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_breach_rl_scope_ts ON breach_rate_limit(scope, ts)"
        )
        conn.commit()
    finally:
        conn.close()


try:
    init_tables()
except Exception as exc:  # pragma: no cover - only when DB path is unwritable at import
    log.warning("breach: deferred table init (DB not ready at import): %s", exc)


# ---------- cache key helpers ----------

def email_cache_key(email: str) -> str:
    """SHA-256 of the normalized email. The raw address is never persisted."""
    normalized = (email or "").strip().lower()
    return "email:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def domain_cache_key(domain: str) -> str:
    return "domain:" + (domain or "").strip().lower()


def meta_cache_key(name: str) -> str:
    return "meta:" + (name or "").strip()


# ---------- generic cache ----------

def get_cached(cache_key: str, ttl_seconds: int | None) -> dict | None:
    """Return the cached payload if present and (when ttl_seconds is set) fresh."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT payload_json, cached_at FROM breach_cache WHERE cache_key = ?", (cache_key,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    payload_json, cached_at = row
    if ttl_seconds is not None and (time.time() - cached_at) > ttl_seconds:
        return None
    try:
        return json.loads(payload_json)
    except (ValueError, TypeError):
        return None


def store_cached(cache_key: str, payload: dict) -> None:
    conn = _connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO breach_cache (cache_key, payload_json, cached_at) VALUES (?, ?, ?)",
            (cache_key, json.dumps(payload), int(time.time())),
        )
        conn.commit()
    except Exception as exc:
        log.error("breach_cache write failed for key prefix %s: %s", cache_key.split(":", 1)[0], exc)
    finally:
        conn.close()


# ---------- rate limiting (fail closed) ----------

_FAIL_CLOSED_COUNT = 10**9


def count_recent(scope: str, window_seconds: int) -> int:
    cutoff = int(time.time()) - window_seconds
    conn = None
    try:
        conn = _connect()
        row = conn.execute(
            "SELECT COUNT(*) FROM breach_rate_limit WHERE scope = ? AND ts > ?",
            (scope, cutoff),
        ).fetchone()
        return row[0] if row else 0
    except Exception as exc:
        log.error("breach rate-limit read failed (failing closed): %s", exc)
        return _FAIL_CLOSED_COUNT
    finally:
        if conn is not None:
            conn.close()


def record_event(scope: str) -> None:
    now = int(time.time())
    conn = _connect()
    try:
        conn.execute("INSERT INTO breach_rate_limit (scope, ts) VALUES (?, ?)", (scope, now))
        conn.execute("DELETE FROM breach_rate_limit WHERE ts < ?", (now - _CLEANUP_AGE_SECONDS,))
        conn.commit()
    except Exception as exc:
        log.error("breach rate-limit write failed: %s", exc)
    finally:
        conn.close()
