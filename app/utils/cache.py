"""Shared single-blob SQLite cache with TTL.

Replaces the copy-pasted get/store cache helpers whose entries share the shape
`(<key> TEXT PRIMARY KEY, response_json TEXT, fetched_at DATETIME DEFAULT
CURRENT_TIMESTAMP)`: the LLM router caches (dork_generator, script_decoder,
email_header) and the reputation caches (ip_intel, threat_pulse). Each table
keeps its existing name and key-column name, so no production DB migration is
needed.

TTL is enforced in SQL against the stored `fetched_at` (written via
CURRENT_TIMESTAMP, i.e. UTC), which is equivalent to the previous Python-side
`datetime.now(utc) - fetched > ttl` checks. On a hit the returned dict carries
`cache_hit=True` and the raw `fetched_at`, matching prior behavior.

Not a fit (left on their own helpers, by design): domain_intel (multi-column
cache, not a single JSON blob) and asn_intel (caches raw upstream data and does
NOT inject cache_hit/fetched_at). Identifiers are interpolated into SQL so they
are validated first; all call sites pass hardcoded constants.
"""
import json
import logging
import re
import sqlite3

from app.config import DB_PATH

log = logging.getLogger("falconeye.cache")

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _ident(name: str) -> str:
    if not _IDENT.match(name):
        raise ValueError(f"unsafe SQL identifier: {name!r}")
    return name


def init_table(table: str, key_col: str = "cache_key") -> None:
    """Create the cache table if absent (idempotent)."""
    _ident(table)
    _ident(key_col)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS {table} ("
            f"{key_col} TEXT PRIMARY KEY, response_json TEXT, "
            "fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
        )
        conn.commit()
    finally:
        conn.close()


def get(table: str, key: str, ttl_hours: float, key_col: str = "cache_key",
        conn: sqlite3.Connection | None = None) -> dict | None:
    """Return the cached dict (with cache_hit/fetched_at) if a fresh row exists,
    else None. Pass an existing request-scoped `conn` to reuse it; otherwise a
    short-lived connection is opened and closed.
    """
    _ident(table)
    _ident(key_col)
    own = conn is None
    if own:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            f"SELECT response_json, fetched_at FROM {table} "
            f"WHERE {key_col} = ? AND fetched_at > datetime('now', ?)",
            (key, f"-{ttl_hours} hours"),
        ).fetchone()
    finally:
        if own:
            conn.close()
    if not row:
        return None
    response_json = row["response_json"]
    fetched_at = row["fetched_at"]
    data = json.loads(response_json)
    data["cache_hit"] = True
    data["fetched_at"] = fetched_at
    return data


def set(table: str, key: str, response: dict, key_col: str = "cache_key",
        conn: sqlite3.Connection | None = None) -> None:
    """Upsert a response blob, stamping fetched_at = CURRENT_TIMESTAMP."""
    _ident(table)
    _ident(key_col)
    own = conn is None
    if own:
        conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            f"INSERT OR REPLACE INTO {table} ({key_col}, response_json, fetched_at) "
            "VALUES (?, ?, CURRENT_TIMESTAMP)",
            (key, json.dumps(response)),
        )
        conn.commit()
    finally:
        if own:
            conn.close()
