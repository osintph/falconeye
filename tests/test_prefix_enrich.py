"""Tests for falconeye.ingest.prefix_enrich."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from falconeye.db import get_connection, init_db
from falconeye.ingest.prefix_enrich import enrich, _origin_asn, _asn_holder


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path):
    p = tmp_path / "test.db"
    init_db(p)
    conn = get_connection(p)
    conn.execute(
        "INSERT INTO ph_prefixes (prefix, prefix_type, fetched_at) "
        "VALUES ('1.2.3.0/24', 'ipv4', '2020-01-01T00:00:00Z')"
    )
    conn.commit()
    conn.close()
    return p


def _routing_response(asn: int = 9299) -> dict:
    return {
        "data": {
            "visibility": {
                "v4": {
                    "origins": [f"AS{asn}"],
                    "ris_peers_seeing": 100,
                }
            }
        }
    }


def _overview_response(holder: str = "PLDT Inc.") -> dict:
    return {
        "data": {
            "holder": holder,
            "resource": "AS9299",
        }
    }


# ---------------------------------------------------------------------------
# Unit: helper parsers
# ---------------------------------------------------------------------------

def test_origin_asn_parses_v4():
    data = _routing_response(9299)
    assert _origin_asn(data, "1.2.3.0/24") == 9299


def test_origin_asn_parses_v6_fallback():
    data = {
        "data": {
            "visibility": {
                "v6": {"origins": ["AS4648"]}
            }
        }
    }
    assert _origin_asn(data, "2001:db8::/32") == 4648


def test_origin_asn_empty_returns_none():
    data = {"data": {"visibility": {"v4": {"origins": []}}}}
    assert _origin_asn(data, "1.2.3.0/24") is None


def test_origin_asn_missing_visibility_returns_none():
    assert _origin_asn({}, "1.2.3.0/24") is None


def test_asn_holder_parses_name():
    data = _overview_response("Globe Telecoms")
    assert _asn_holder(data) == "Globe Telecoms"


def test_asn_holder_missing_returns_none():
    assert _asn_holder({}) is None


# ---------------------------------------------------------------------------
# Integration: enrich()
# ---------------------------------------------------------------------------

def test_enrich_updates_prefix_asn(db):
    with patch("falconeye.ingest.prefix_enrich._fetch",
               side_effect=[_routing_response(9299), _overview_response("PLDT")]), \
         patch("falconeye.ingest.prefix_enrich.time.sleep"):
        updated, errors = enrich(db)

    assert updated == 1
    assert errors == 0

    conn = get_connection(db)
    row = conn.execute("SELECT asn FROM ph_prefixes WHERE prefix='1.2.3.0/24'").fetchone()
    conn.close()
    assert row["asn"] == 9299


def test_enrich_upserts_asn_into_ph_asns(db):
    with patch("falconeye.ingest.prefix_enrich._fetch",
               side_effect=[_routing_response(9299), _overview_response("PLDT Inc.")]), \
         patch("falconeye.ingest.prefix_enrich.time.sleep"):
        enrich(db)

    conn = get_connection(db)
    row = conn.execute("SELECT name FROM ph_asns WHERE asn=9299").fetchone()
    conn.close()
    assert row is not None
    assert row["name"] == "PLDT Inc."


def test_enrich_leaves_asn_null_when_not_announced(db):
    """Prefixes not in BGP keep asn=NULL but get fetched_at updated."""
    no_origin = {"data": {"visibility": {"v4": {"origins": []}}}}
    with patch("falconeye.ingest.prefix_enrich._fetch", return_value=no_origin), \
         patch("falconeye.ingest.prefix_enrich.time.sleep"):
        updated, errors = enrich(db)

    assert updated == 0
    assert errors == 0

    conn = get_connection(db)
    row = conn.execute("SELECT asn, fetched_at FROM ph_prefixes WHERE prefix='1.2.3.0/24'").fetchone()
    conn.close()
    assert row["asn"] is None
    assert row["fetched_at"] != "2020-01-01T00:00:00Z"  # updated


def test_enrich_handles_network_error(db):
    with patch("falconeye.ingest.prefix_enrich._fetch", return_value=None), \
         patch("falconeye.ingest.prefix_enrich.time.sleep"):
        updated, errors = enrich(db)

    assert updated == 0
    assert errors == 1


def test_enrich_aborts_after_three_429s(tmp_path):
    """Three consecutive 429s abort the cycle; remaining prefixes are skipped."""
    p = tmp_path / "test.db"
    init_db(p)
    conn = get_connection(p)
    for i in range(5):
        conn.execute(
            "INSERT INTO ph_prefixes (prefix, prefix_type, fetched_at) "
            "VALUES (?, 'ipv4', '2020-01-01T00:00:00Z')",
            (f"10.0.{i}.0/24",),
        )
    conn.commit()
    conn.close()

    fetch_calls = []

    def fake_fetch(url, params, state):
        fetch_calls.append(params)
        state["consecutive_429s"] += 1
        if state["consecutive_429s"] >= 3:
            return None  # signals abort
        return None

    with patch("falconeye.ingest.prefix_enrich._fetch", side_effect=fake_fetch), \
         patch("falconeye.ingest.prefix_enrich.time.sleep"):
        enrich(p)

    # Should have aborted well before all 5 prefixes
    assert len(fetch_calls) <= 5


def test_enrich_skips_fresh_prefixes(tmp_path):
    """Prefixes with recent fetched_at and populated asn are not reprocessed."""
    p = tmp_path / "fresh.db"
    init_db(p)
    conn = get_connection(p)
    conn.execute(
        "INSERT INTO ph_prefixes (prefix, prefix_type, asn, fetched_at) "
        "VALUES ('5.6.7.0/24', 'ipv4', 9299, '2099-01-01T00:00:00Z')"
    )
    conn.commit()
    conn.close()

    fetch_calls = []
    with patch("falconeye.ingest.prefix_enrich._fetch",
               side_effect=lambda *a, **kw: fetch_calls.append(a) or {}), \
         patch("falconeye.ingest.prefix_enrich.time.sleep"):
        updated, errors = enrich(p)

    assert updated == 0
    assert errors == 0
    assert len(fetch_calls) == 0
