"""
Domain age lookup for the phishing scanner.

Query strategy:
  1. RDAP via rdap.org — structured JSON, no API key, preferred.
  2. whois fallback — covers registrars without RDAP support.
  3. Failure — returns {"found": False, "error": "..."}.

Results cached 24 hours in domain_age_cache. The registration date never
changes, so 24h is conservatively short; the cache stores created_at and
age_days is recalculated at read time so it stays current across cache hits.
"""

import json
import logging
import re
import sqlite3
import subprocess
from datetime import datetime, timezone
from typing import Optional

import httpx

from app.utils.safe_fetch import safe_fetch, SafeFetchError

log = logging.getLogger(__name__)

_RDAP_BASE = "https://rdap.org/domain/"
_CACHE_TTL_HOURS = 24

# whois field names to try in order, case-insensitive
_WHOIS_DATE_KEYS = [
    "Creation Date",
    "Created Date",
    "Registered On",
    "Registration Time",
    "created",
    "Registered",
]

_EMPTY: dict = {
    "found": False,
    "created_at": "",
    "age_days": -1,
    "source": "",
    "error": None,
}


# ---------------------------------------------------------------------------
# Table bootstrap (lazy — also in db_init.py for fresh installs)
# ---------------------------------------------------------------------------

def _ensure_table(db: sqlite3.Connection) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS domain_age_cache (
            domain      TEXT PRIMARY KEY,
            created_at  TEXT NOT NULL,
            age_days    INTEGER NOT NULL,
            source      TEXT NOT NULL,
            checked_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.commit()


# ---------------------------------------------------------------------------
# Date parsing
# ---------------------------------------------------------------------------

def _parse_date(raw: str) -> Optional[datetime]:
    """Parse common RDAP / whois date strings into a UTC-aware datetime."""
    raw = raw.strip()
    # Replace trailing Z with UTC offset so fromisoformat handles it
    raw = re.sub(r"Z$", "+00:00", raw)
    # Normalise space separator to T
    raw = re.sub(r"^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2})", r"\1T\2", raw)
    # Strip sub-second precision
    raw = re.sub(r"\.\d+", "", raw)
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _age_days(created: datetime) -> int:
    now = datetime.now(timezone.utc)
    delta = now - created
    return max(0, delta.days)


# ---------------------------------------------------------------------------
# RDAP lookup
# ---------------------------------------------------------------------------

async def _rdap_lookup(domain: str) -> Optional[datetime]:
    """Return the registration datetime from RDAP, or None if not found."""
    try:
        resp = await safe_fetch(f"{_RDAP_BASE}{domain}", timeout=8.0)
    except SafeFetchError as exc:
        log.debug("RDAP safe_fetch blocked for %s: %s", domain, exc)
        return None
    except Exception:
        log.debug("RDAP fetch failed for %s", domain, exc_info=True)
        return None

    if resp.get("status") != 200:
        return None

    try:
        body = resp.get("body", "")
        data = json.loads(body) if isinstance(body, str) else body
        events = data.get("events", [])
    except Exception:
        return None

    target_actions = {"registration", "registrar registration"}
    for event in events:
        if event.get("eventAction", "").lower() in target_actions:
            date_str = event.get("eventDate", "")
            if date_str:
                return _parse_date(date_str)

    return None


# ---------------------------------------------------------------------------
# whois fallback
# ---------------------------------------------------------------------------

def _whois_lookup(domain: str) -> Optional[datetime]:
    """Return the registration datetime from whois output, or None.

    Collects ALL candidate dates matching creation-event field names and
    returns the most recent. This handles whois outputs that include a TLD
    registry section (with a decades-old 'created:' line) before the
    registrar section (with the actual domain registration date). The newest
    date wins because the domain registration is always more recent than any
    TLD/root zone creation event.
    """
    try:
        proc = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=12,
        )
        output = proc.stdout
    except Exception:
        log.debug("whois subprocess failed for %s", domain, exc_info=True)
        return None

    candidates: list[datetime] = []
    for line in output.splitlines():
        for key in _WHOIS_DATE_KEYS:
            # Match "Key: value" case-insensitively, allow leading whitespace
            m = re.match(rf"^\s*{re.escape(key)}\s*:\s*(.+)$", line, re.IGNORECASE)
            if m:
                dt = _parse_date(m.group(1))
                if dt:
                    candidates.append(dt)
                break  # only one key can match a given line

    if not candidates:
        return None

    # Return the most recent date — the actual domain registration is always
    # newer than any TLD or root-zone creation event that may appear earlier
    # in multi-section whois output.
    return max(candidates)


# ---------------------------------------------------------------------------
# Cache read/write
# ---------------------------------------------------------------------------

def _cache_get(db: sqlite3.Connection, domain: str) -> Optional[dict]:
    try:
        row = db.execute(
            """
            SELECT created_at, source
            FROM domain_age_cache
            WHERE domain = ?
              AND (julianday('now') - julianday(checked_at)) * 24 < ?
            """,
            (domain, _CACHE_TTL_HOURS),
        ).fetchone()
    except Exception:
        return None

    if not row:
        return None

    created = _parse_date(row["created_at"] if hasattr(row, "keys") else row[0])
    source = row["source"] if hasattr(row, "keys") else row[1]
    if not created:
        return None

    return {
        "found": True,
        "created_at": created.isoformat(),
        "age_days": _age_days(created),
        "source": f"{source} (cached)",
        "error": None,
    }


def _cache_put(db: sqlite3.Connection, domain: str, created_at: str, age_days: int, source: str) -> None:
    try:
        db.execute(
            """
            INSERT INTO domain_age_cache (domain, created_at, age_days, source, checked_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(domain) DO UPDATE SET
                created_at = excluded.created_at,
                age_days   = excluded.age_days,
                source     = excluded.source,
                checked_at = excluded.checked_at
            """,
            (domain, created_at, age_days, source),
        )
        db.commit()
    except Exception:
        log.debug("domain_age_cache write failed for %s", domain, exc_info=True)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def check_domain_age(domain: str, db: Optional[sqlite3.Connection] = None) -> dict:
    """
    Return domain age information for `domain`.

    Returns {"found", "created_at", "age_days", "source", "error"}.
    age_days is -1 when found is False.
    Never raises.
    """
    if not domain:
        return {**_EMPTY, "error": "empty domain"}

    if db is not None:
        try:
            _ensure_table(db)
        except Exception:
            pass
        cached = _cache_get(db, domain)
        if cached:
            return cached

    # Strategy 1: RDAP
    created = await _rdap_lookup(domain)
    source = "rdap"

    # Strategy 2: whois fallback
    if created is None:
        created = _whois_lookup(domain)
        source = "whois"

    if created is None:
        return {**_EMPTY, "error": "registration date not found via RDAP or whois"}

    days = _age_days(created)
    created_str = created.isoformat()

    result = {
        "found": True,
        "created_at": created_str,
        "age_days": days,
        "source": source,
        "error": None,
    }

    if db is not None:
        _cache_put(db, domain, created_str, days, source)

    return result
