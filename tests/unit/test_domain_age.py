"""
Unit tests for app/utils/domain_age.py

All HTTP calls are mocked via safe_fetch; subprocess.run is mocked for whois.
The DB tests use an in-memory SQLite connection.
"""

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from app.utils.domain_age import (
    check_domain_age,
    _parse_date,
    _age_days,
    _ensure_table,
    _whois_lookup,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db() -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    _ensure_table(db)
    return db


def _rdap_resp(events: list) -> dict:
    body = json.dumps({"events": events})
    return {"status": 200, "headers": {}, "body": body, "url_final": ""}


def _whois_proc(output: str):
    m = MagicMock()
    m.stdout = output
    m.returncode = 0
    return m


# ---------------------------------------------------------------------------
# _parse_date
# ---------------------------------------------------------------------------

def test_parse_date_iso_z():
    dt = _parse_date("2026-06-30T18:52:11Z")
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 6
    assert dt.day == 30


def test_parse_date_iso_offset():
    dt = _parse_date("2026-06-30T18:52:11+08:00")
    assert dt is not None
    assert dt.year == 2026


def test_parse_date_date_only():
    dt = _parse_date("2026-06-30")
    assert dt is not None
    assert dt.day == 30


def test_parse_date_with_space():
    dt = _parse_date("2026-06-30 18:52:11")
    assert dt is not None


def test_parse_date_invalid_returns_none():
    assert _parse_date("not-a-date") is None
    assert _parse_date("") is None


# ---------------------------------------------------------------------------
# RDAP parsing
# ---------------------------------------------------------------------------

def test_rdap_parsing_returns_creation_date():
    events = [
        {"eventAction": "registration", "eventDate": "2026-06-30T18:52:11Z"},
        {"eventAction": "last changed", "eventDate": "2026-07-03T10:00:00Z"},
    ]

    async def run():
        with patch(
            "app.utils.domain_age.safe_fetch",
            new=AsyncMock(return_value=_rdap_resp(events)),
        ):
            result = await check_domain_age("gobpi.cc")
        assert result["found"] is True
        assert "2026-06-30" in result["created_at"]
        assert result["age_days"] >= 0
        assert result["source"] == "rdap"
    asyncio.run(run())


def test_rdap_registrar_registration_action_accepted():
    events = [
        {"eventAction": "registrar registration", "eventDate": "2026-06-30T00:00:00Z"},
    ]

    async def run():
        with patch(
            "app.utils.domain_age.safe_fetch",
            new=AsyncMock(return_value=_rdap_resp(events)),
        ):
            result = await check_domain_age("example.cc")
        assert result["found"] is True
        assert result["source"] == "rdap"
    asyncio.run(run())


def test_rdap_missing_events_falls_back_to_whois():
    whois_out = "Creation Date: 2026-06-30T18:52:11Z\nUpdated Date: 2026-07-03T10:00:00Z\n"

    async def run():
        with patch(
            "app.utils.domain_age.safe_fetch",
            new=AsyncMock(return_value=_rdap_resp([])),  # empty events
        ):
            with patch("subprocess.run", return_value=_whois_proc(whois_out)):
                result = await check_domain_age("gobpi.cc")
        assert result["found"] is True
        assert result["source"] == "whois"
        assert "2026-06-30" in result["created_at"]
    asyncio.run(run())


def test_rdap_404_falls_back_to_whois():
    whois_out = "Creation Date: 2026-05-01T00:00:00Z\n"
    rdap_404 = {"status": 404, "headers": {}, "body": "", "url_final": ""}

    async def run():
        with patch(
            "app.utils.domain_age.safe_fetch",
            new=AsyncMock(return_value=rdap_404),
        ):
            with patch("subprocess.run", return_value=_whois_proc(whois_out)):
                result = await check_domain_age("example.cc")
        assert result["found"] is True
        assert result["source"] == "whois"
    asyncio.run(run())


# ---------------------------------------------------------------------------
# whois parsing
# ---------------------------------------------------------------------------

def test_whois_parsing_creation_date():
    whois_out = (
        "Registrar: Some Registrar\n"
        "Creation Date: 2026-06-30T18:52:11Z\n"
        "Expiry Date: 2027-06-30T18:52:11Z\n"
    )
    dt = _whois_lookup.__wrapped__("gobpi.cc") if hasattr(_whois_lookup, "__wrapped__") else None
    # Test via check_domain_age with mocked RDAP (no events) and real whois mock
    async def run():
        with patch("app.utils.domain_age.safe_fetch", new=AsyncMock(return_value=_rdap_resp([]))):
            with patch("subprocess.run", return_value=_whois_proc(whois_out)):
                result = await check_domain_age("gobpi.cc")
        assert result["found"] is True
        assert "2026-06-30" in result["created_at"]
        assert result["source"] == "whois"
    asyncio.run(run())


def test_whois_parsing_registered_on():
    whois_out = (
        "Domain Name: EXAMPLE.PH\n"
        "Registered On: 2025-01-15\n"
    )
    async def run():
        with patch("app.utils.domain_age.safe_fetch", new=AsyncMock(return_value=_rdap_resp([]))):
            with patch("subprocess.run", return_value=_whois_proc(whois_out)):
                result = await check_domain_age("example.ph")
        assert result["found"] is True
        assert "2025-01-15" in result["created_at"]
    asyncio.run(run())


def test_whois_parsing_created_date():
    whois_out = "Created Date: 2024-03-10T00:00:00Z\n"
    async def run():
        with patch("app.utils.domain_age.safe_fetch", new=AsyncMock(return_value=_rdap_resp([]))):
            with patch("subprocess.run", return_value=_whois_proc(whois_out)):
                result = await check_domain_age("example.com")
        assert result["found"] is True
    asyncio.run(run())


def test_whois_leading_whitespace_handled():
    whois_out = "   Creation Date: 2026-06-30T18:52:11Z\n"
    async def run():
        with patch("app.utils.domain_age.safe_fetch", new=AsyncMock(return_value=_rdap_resp([]))):
            with patch("subprocess.run", return_value=_whois_proc(whois_out)):
                result = await check_domain_age("gobpi.cc")
        assert result["found"] is True
    asyncio.run(run())


# ---------------------------------------------------------------------------
# Cache behaviour
# ---------------------------------------------------------------------------

def test_cache_hit_bypasses_lookup():
    db = _make_db()
    # Pre-seed cache
    old_date = "2020-01-01T00:00:00+00:00"
    db.execute(
        "INSERT INTO domain_age_cache (domain, created_at, age_days, source, checked_at) VALUES (?,?,?,?,CURRENT_TIMESTAMP)",
        ("cached.example.com", old_date, 1000, "rdap"),
    )
    db.commit()

    async def run():
        with patch("app.utils.domain_age.safe_fetch", new=AsyncMock()) as mock_fetch:
            result = await check_domain_age("cached.example.com", db)
        mock_fetch.assert_not_called()
        assert result["found"] is True
        assert result["source"] == "rdap (cached)"
        assert result["age_days"] >= 1000
    asyncio.run(run())


def test_cache_miss_calls_upstream():
    db = _make_db()
    events = [{"eventAction": "registration", "eventDate": "2026-06-01T00:00:00Z"}]

    async def run():
        with patch(
            "app.utils.domain_age.safe_fetch",
            new=AsyncMock(return_value=_rdap_resp(events)),
        ) as mock_fetch:
            result = await check_domain_age("uncached.example.com", db)
        mock_fetch.assert_called_once()
        assert result["found"] is True
    asyncio.run(run())


def test_cache_write_on_miss():
    db = _make_db()
    events = [{"eventAction": "registration", "eventDate": "2026-06-01T00:00:00Z"}]

    async def run():
        with patch("app.utils.domain_age.safe_fetch", new=AsyncMock(return_value=_rdap_resp(events))):
            await check_domain_age("newdomain.example.com", db)
        row = db.execute(
            "SELECT domain FROM domain_age_cache WHERE domain = ?",
            ("newdomain.example.com",),
        ).fetchone()
        assert row is not None
    asyncio.run(run())


def test_stale_cache_calls_upstream():
    db = _make_db()
    # Insert a row with checked_at 48 hours ago
    db.execute(
        "INSERT INTO domain_age_cache (domain, created_at, age_days, source, checked_at) "
        "VALUES (?,?,?,?, datetime('now', '-48 hours'))",
        ("stale.example.com", "2020-01-01T00:00:00+00:00", 1000, "rdap"),
    )
    db.commit()
    events = [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}]

    async def run():
        with patch(
            "app.utils.domain_age.safe_fetch",
            new=AsyncMock(return_value=_rdap_resp(events)),
        ) as mock_fetch:
            result = await check_domain_age("stale.example.com", db)
        mock_fetch.assert_called_once()
        assert "(cached)" not in result["source"]
    asyncio.run(run())


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------

def test_lookup_failure_returns_found_false():
    from app.utils.safe_fetch import SafeFetchError

    async def run():
        with patch(
            "app.utils.domain_age.safe_fetch",
            new=AsyncMock(side_effect=SafeFetchError("blocked")),
        ):
            with patch("subprocess.run", side_effect=Exception("whois unavailable")):
                result = await check_domain_age("evil.internal")
        assert result["found"] is False
        assert result["error"] is not None
    asyncio.run(run())


def test_empty_domain_returns_found_false():
    async def run():
        result = await check_domain_age("")
        assert result["found"] is False
    asyncio.run(run())


def test_no_db_parameter_still_works():
    events = [{"eventAction": "registration", "eventDate": "2026-01-01T00:00:00Z"}]
    async def run():
        with patch("app.utils.domain_age.safe_fetch", new=AsyncMock(return_value=_rdap_resp(events))):
            result = await check_domain_age("nodomain.example.com")
        assert result["found"] is True
        assert result["source"] == "rdap"
    asyncio.run(run())
