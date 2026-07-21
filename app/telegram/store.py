"""
Cache for the Telegram Intelligence tab, self-initializing at import like every
other tab (username, abuse, ip_intel) so a fresh (non-migrated) DB never 500s.
Keyed by normalized identifier, not "channel" — the old telegram_cache table
was channel-only; this is a new table since the schema and key semantics
changed (any entity type, tiered result shape). The old table is left in place,
unused and harmless.
"""
import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta

from app.config import DB_PATH

log = logging.getLogger("falconeye.telegram")

CACHE_TTL_HOURS = 6


def _connect() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def init_tables() -> None:
    conn = _connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS telegram_lookup_cache (
                identifier TEXT PRIMARY KEY,
                response_json TEXT,
                fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_telegram_lookup_fetched ON telegram_lookup_cache(fetched_at)"
        )
        conn.commit()
    finally:
        conn.close()


try:
    init_tables()
except Exception as exc:  # pragma: no cover - only when DB path is unwritable at import
    log.warning("telegram: deferred table init (DB not ready at import): %s", exc)


def get_cached(identifier: str) -> dict | None:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT response_json, fetched_at FROM telegram_lookup_cache WHERE identifier = ?", (identifier,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    fetched = datetime.fromisoformat(row[1])
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - fetched > timedelta(hours=CACHE_TTL_HOURS):
        return None
    data = json.loads(row[0])
    data["cache_hit"] = True
    data["fetched_at"] = row[1]
    return data


def store_cache(identifier: str, response: dict) -> None:
    conn = _connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO telegram_lookup_cache (identifier, response_json, fetched_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
            (identifier, json.dumps(response)),
        )
        conn.commit()
    finally:
        conn.close()
