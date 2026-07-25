"""Shared per-IP SQLite daily rate limiter.

Replaces the byte-identical `_init_rl`/`_check_rate_limit`/`_record_call` that were
copy-pasted into dork_generator, qr_analyzer, url_expander, and script_decoder.
Every table keeps its existing name and schema — `(source_ip TEXT, called_at
DATETIME DEFAULT CURRENT_TIMESTAMP)` — so no production DB migration is needed.

Table/column names are interpolated into SQL (SQLite can't parameterize
identifiers), so they are validated as plain identifiers first; all call sites
pass hardcoded constants regardless.
"""
import logging
import re
import sqlite3

from app.config import DB_PATH

log = logging.getLogger("falconeye.rate_limit")

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _ident(name: str) -> str:
    if not _IDENT.match(name):
        raise ValueError(f"unsafe SQL identifier: {name!r}")
    return name


def init_table(table: str) -> None:
    """Create the rate-limit table + its index if absent (idempotent)."""
    _ident(table)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS {table} ("
            "source_ip TEXT NOT NULL, called_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
        )
        conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_ip ON {table}(source_ip, called_at)")
        conn.commit()
    finally:
        conn.close()


def check(table: str, source_ip: str, limit: int, window_hours: int = 24) -> tuple[bool, int]:
    """Return (allowed, calls_used_in_window). Does not record the call."""
    _ident(table)
    conn = sqlite3.connect(DB_PATH)
    try:
        count = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE source_ip = ? AND called_at > datetime('now', ?)",
            (source_ip, f"-{window_hours} hours"),
        ).fetchone()[0]
    finally:
        conn.close()
    return (count < limit, count)


def record(table: str, source_ip: str, retain_hours: int = 48) -> None:
    """Record one call and prune rows older than the retention window.

    Swallows DB errors (logged) — a rate-limiter write failing must not 500 the
    request it is protecting, matching the original per-router behavior.
    """
    _ident(table)
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(f"INSERT INTO {table} (source_ip) VALUES (?)", (source_ip,))
        conn.execute(f"DELETE FROM {table} WHERE called_at < datetime('now', ?)", (f"-{retain_hours} hours",))
        conn.commit()
        conn.close()
    except Exception as exc:
        log.error("rate_limit.record failed for %s/%s: %s", table, source_ip, exc)
