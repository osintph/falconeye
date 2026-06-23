from __future__ import annotations

import json
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, call

import pytest
import requests

from falconeye.db import get_connection, init_db
from falconeye.ingest.shodan_enrich import (
    _BACKOFF_SEQUENCE,
    _DAILY_CAP,
    _STALENESS_HOURS,
    _extract_ipv4,
    _fetch_internetdb,
    _is_stale,
    run_shodan_enrich,
)


# ---------------------------------------------------------------------------
# _extract_ipv4
# ---------------------------------------------------------------------------

def test_extract_ipv4_from_ip_ioc():
    assert _extract_ipv4("202.90.136.5", "ip") == "202.90.136.5"


def test_extract_ipv4_from_url_ioc():
    assert _extract_ipv4("http://202.90.136.5/payload", "url") == "202.90.136.5"


def test_extract_ipv4_ignores_ipv6():
    assert _extract_ipv4("2001:4400::1", "ip") is None


def test_extract_ipv4_ignores_domain_url():
    assert _extract_ipv4("http://evil.ph/malware", "url") is None


def test_extract_ipv4_ignores_unknown_type():
    assert _extract_ipv4("202.90.136.5", "domain") is None


def test_extract_ipv4_invalid():
    assert _extract_ipv4("not-an-ip", "ip") is None


# ---------------------------------------------------------------------------
# _fetch_internetdb
# ---------------------------------------------------------------------------

def _mock_session(responses: list) -> MagicMock:
    """Build a session mock whose .get() returns responses in sequence."""
    session = MagicMock()
    session.get.side_effect = [
        MagicMock(status_code=code, json=MagicMock(return_value=body))
        for code, body in responses
    ]
    return session


def test_fetch_success():
    body = {"ports": [80, 443], "cpes": [], "hostnames": [], "tags": [], "vulns": []}
    session = _mock_session([(200, body)])
    result = _fetch_internetdb("1.2.3.4", session)
    assert result == body


def test_fetch_404_returns_empty_dict():
    session = _mock_session([(404, {})])
    result = _fetch_internetdb("1.2.3.4", session)
    assert result == {}


def test_fetch_429_backoff_then_success():
    body = {"ports": [22], "cpes": [], "hostnames": [], "tags": [], "vulns": []}
    session = _mock_session([(429, {}), (429, {}), (200, body)])
    with patch("falconeye.ingest.shodan_enrich.time.sleep") as mock_sleep:
        result = _fetch_internetdb("1.2.3.4", session)
    assert result == body
    assert mock_sleep.call_count == 2
    assert mock_sleep.call_args_list[0] == call(5.0)
    assert mock_sleep.call_args_list[1] == call(10.0)


def test_fetch_429_exhausts_backoff_returns_none():
    # All attempts return 429 — should bail after exhausting sequence
    n = len(_BACKOFF_SEQUENCE) + 1  # initial + one per backoff step
    session = _mock_session([(429, {})] * n)
    with patch("falconeye.ingest.shodan_enrich.time.sleep"):
        result = _fetch_internetdb("1.2.3.4", session)
    assert result is None


def test_fetch_network_error_returns_none():
    session = MagicMock()
    session.get.side_effect = requests.RequestException("timeout")
    result = _fetch_internetdb("1.2.3.4", session)
    assert result is None


def test_fetch_unexpected_status_returns_none():
    session = _mock_session([(503, {})])
    result = _fetch_internetdb("1.2.3.4", session)
    assert result is None


# ---------------------------------------------------------------------------
# _is_stale
# ---------------------------------------------------------------------------

@pytest.fixture
def enriched_db(tmp_path):
    db = tmp_path / "test.db"
    init_db(db)
    return db


def test_is_stale_no_row(enriched_db):
    conn = get_connection(enriched_db)
    assert _is_stale(conn, "1.2.3.4") is True
    conn.close()


def test_is_stale_fresh_row(enriched_db):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = get_connection(enriched_db)
    conn.execute(
        "INSERT INTO ip_enrichments (ip_address, fetched_at, source_url) VALUES (?, ?, ?)",
        ("1.2.3.4", now, "https://internetdb.shodan.io/1.2.3.4"),
    )
    conn.commit()
    assert _is_stale(conn, "1.2.3.4") is False
    conn.close()


def test_is_stale_old_row(enriched_db):
    old = (datetime.now(timezone.utc) - timedelta(hours=_STALENESS_HOURS + 1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    conn = get_connection(enriched_db)
    conn.execute(
        "INSERT INTO ip_enrichments (ip_address, fetched_at, source_url) VALUES (?, ?, ?)",
        ("1.2.3.4", old, "https://internetdb.shodan.io/1.2.3.4"),
    )
    conn.commit()
    assert _is_stale(conn, "1.2.3.4") is True
    conn.close()


# ---------------------------------------------------------------------------
# run_shodan_enrich (integration)
# ---------------------------------------------------------------------------

@pytest.fixture
def db_with_ph_ioc(tmp_path):
    db = tmp_path / "test.db"
    init_db(db)
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO iocs (ioc_type, ioc_value, source, source_id, fetched_at) "
        "VALUES ('url', 'http://202.90.136.10/payload', 'urlhaus', 'u1', '2026-06-23T00:00:00Z')"
    )
    ioc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO sieve_matches (record_type, record_id, match_criterion, matched_value, matched_at) "
        "VALUES ('ioc', ?, 'asn', '202.90.136.0/24', '2026-06-23T00:00:00Z')",
        (ioc_id,),
    )
    conn.commit()
    conn.close()
    return db


def test_run_enriches_ph_ip(db_with_ph_ioc):
    body = {"ports": [80, 443], "cpes": ["cpe:2.3:h:mikrotik:rb941"], "hostnames": [],
            "tags": ["router"], "vulns": ["CVE-2024-1234"]}
    with patch("falconeye.ingest.shodan_enrich.requests.Session") as MockSession:
        instance = MockSession.return_value
        instance.get.return_value = MagicMock(status_code=200, json=MagicMock(return_value=body))
        enriched, skipped = run_shodan_enrich(db_with_ph_ioc)

    assert enriched == 1
    assert skipped == 0
    conn = get_connection(db_with_ph_ioc)
    row = conn.execute("SELECT * FROM ip_enrichments WHERE ip_address='202.90.136.10'").fetchone()
    conn.close()
    assert row is not None
    assert json.loads(row["ports"]) == [80, 443]
    assert json.loads(row["tags"]) == ["router"]


def test_run_skips_fresh_ip(db_with_ph_ioc):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = get_connection(db_with_ph_ioc)
    conn.execute(
        "INSERT INTO ip_enrichments (ip_address, ports, cpes, hostnames, tags, vulns, fetched_at, source_url) "
        "VALUES ('202.90.136.10', '[]', '[]', '[]', '[]', '[]', ?, 'https://internetdb.shodan.io/202.90.136.10')",
        (now,),
    )
    conn.commit()
    conn.close()

    with patch("falconeye.ingest.shodan_enrich.requests.Session") as MockSession:
        enriched, skipped = run_shodan_enrich(db_with_ph_ioc)

    assert enriched == 0
    assert skipped == 1


def test_run_daily_cap_aborts(db_with_ph_ioc):
    # Pre-fill daily count at cap
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = get_connection(db_with_ph_ioc)
    # Insert _DAILY_CAP rows with today's timestamp but different IPs
    conn.executemany(
        "INSERT INTO ip_enrichments (ip_address, fetched_at, source_url) VALUES (?, ?, ?)",
        [(f"10.0.{i // 256}.{i % 256}", now, "x") for i in range(_DAILY_CAP)],
    )
    conn.commit()
    conn.close()

    with patch("falconeye.ingest.shodan_enrich.requests.Session") as MockSession:
        enriched, skipped = run_shodan_enrich(db_with_ph_ioc)

    assert enriched == 0
    assert skipped == 0
    MockSession.return_value.get.assert_not_called()


def test_run_handles_404_gracefully(db_with_ph_ioc):
    with patch("falconeye.ingest.shodan_enrich.requests.Session") as MockSession:
        instance = MockSession.return_value
        instance.get.return_value = MagicMock(status_code=404)
        enriched, skipped = run_shodan_enrich(db_with_ph_ioc)

    # 404 means no data — still writes a record with empty lists
    assert enriched == 1
    conn = get_connection(db_with_ph_ioc)
    row = conn.execute("SELECT ports FROM ip_enrichments WHERE ip_address='202.90.136.10'").fetchone()
    conn.close()
    assert json.loads(row["ports"]) == []
