"""
Ransomware Watch: tab-level time range selector (v3.19.0 brief).

Covers the range-bucketing added to store.py/routes.py: the true
MIN(discovered) lower bound (never hardcoded), that each of the 5 range
windows (30d/90d/12mo/ytd/all) excludes/includes victims correctly, that the
"all" bucket is byte-identical in coverage to the pre-v3.19.0 all-time
queries (no accidental exclusions), and that every range-aware endpoint
response carries data_start/as_of_date/ranges even in the cold-start case.
"""
import os

os.environ.setdefault("RANSOMWARE_DB", "/tmp/falconeye_ransomware_ranges_test.db")
os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.ransomware import store

NOW_ISO = datetime.now(timezone.utc).isoformat()


@pytest.fixture(autouse=True)
def _clean_state():
    store.init_tables()
    conn = store._connect()
    try:
        for table in ("victims", "groups", "mirrors", "press", "watchlist_hits", "collector_runs"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
    finally:
        conn.close()
    yield


def _client():
    from app.main import app
    return TestClient(app)


def _seed_victim(conn, *, group, victim, country, discovered, sector="Manufacturing"):
    store.upsert_victim(
        conn, group_name=group, victim_name=victim, country=country, sector=sector,
        discovered=discovered, attackdate=None, infostealer=None, permalink=None,
        first_seen_via="collector", now_iso=NOW_ISO,
    )


def _mark_collected(conn, *phases):
    for phase in phases:
        store.record_run(conn, phase=phase, source="ransomware_live", status="ok", detail=None,
                          started_at=NOW_ISO, finished_at=NOW_ISO)
    conn.commit()


# ---------- 1. min_discovered_date ----------

def test_min_discovered_date_empty_db_returns_none():
    conn = store._connect()
    try:
        assert store.min_discovered_date(conn) is None
    finally:
        conn.close()


def test_min_discovered_date_is_the_true_earliest_row_not_a_constant():
    conn = store._connect()
    try:
        _seed_victim(conn, group="g1", victim="Old One", country="PH", discovered="2019-11-02T00:00:00Z")
        _seed_victim(conn, group="g2", victim="Newer One", country="SG", discovered="2024-01-01T00:00:00Z")
        conn.commit()
        assert store.min_discovered_date(conn) == "2019-11-02"
    finally:
        conn.close()


# ---------- 2. range windows exclude/include correctly ----------

def test_narrow_range_excludes_old_victim_all_bucket_includes_it():
    conn = store._connect()
    try:
        today = datetime.now(timezone.utc).date().isoformat()
        _seed_victim(conn, group="g1", victim="Ancient", country="PH", discovered="2020-01-01T00:00:00Z")
        _seed_victim(conn, group="g2", victim="Fresh", country="SG", discovered=today + "T00:00:00Z")
        conn.commit()

        in_range = store.victims_stats_in_range(conn, "2020-06-01", today)
        assert in_range["victims"] == 1  # only "Fresh"

        full = store.victims_stats_in_range(conn, "2020-01-01", today)
        assert full["victims"] == 2  # both
    finally:
        conn.close()


def test_active_groups_counts_distinct_groups_with_a_victim_in_range():
    conn = store._connect()
    try:
        today = datetime.now(timezone.utc).date().isoformat()
        _seed_victim(conn, group="alpha", victim="V1", country="PH", discovered=today + "T00:00:00Z")
        _seed_victim(conn, group="alpha", victim="V2", country="SG", discovered=today + "T00:00:00Z")
        _seed_victim(conn, group="beta", victim="V3", country="TH", discovered=today + "T00:00:00Z")
        conn.commit()
        stats = store.victims_stats_in_range(conn, today, today)
        assert stats["active_groups"] == 2  # alpha, beta - not 3 (V1/V2 share a group)
        assert stats["countries_hit"] == 3
    finally:
        conn.close()


def test_map_counts_in_range_excludes_out_of_window_country():
    conn = store._connect()
    try:
        today = datetime.now(timezone.utc).date().isoformat()
        _seed_victim(conn, group="g1", victim="V1", country="US", discovered="2020-01-01T00:00:00Z")
        _seed_victim(conn, group="g2", victim="V2", country="DE", discovered=today + "T00:00:00Z")
        conn.commit()
        rows = store.map_counts_in_range(conn, today, today)
        countries = {r["country"] for r in rows}
        assert countries == {"DE"}
    finally:
        conn.close()


def test_ph_sea_counts_and_trend_scoped_to_range():
    conn = store._connect()
    try:
        today = datetime.now(timezone.utc).date().isoformat()
        _seed_victim(conn, group="g1", victim="Old PH", country="PH", discovered="2020-05-05T00:00:00Z")
        _seed_victim(conn, group="g2", victim="New PH", country="PH", discovered=today + "T00:00:00Z")
        conn.commit()

        narrow = store.ph_sea_counts_in_range(conn, today, today)
        ph_count = next(c for c in narrow if c["country"] == "PH")["count"]
        assert ph_count == 1

        full = store.ph_sea_counts_in_range(conn, "2020-01-01", today)
        ph_count_full = next(c for c in full if c["country"] == "PH")["count"]
        assert ph_count_full == 2

        trend_narrow = store.ph_sea_monthly_trend_in_range(conn, today, today)
        assert all(t["month"] == today[:7] for t in trend_narrow)
    finally:
        conn.close()


# ---------- 3. "all" bucket matches pre-v3.19.0 all-time coverage exactly ----------

def test_all_bucket_covers_every_row_regardless_of_age():
    conn = store._connect()
    try:
        _seed_victim(conn, group="g1", victim="V1", country="PH", discovered="2018-01-01T00:00:00Z")
        _seed_victim(conn, group="g2", victim="V2", country="SG", discovered="2026-07-24T00:00:00Z")
        conn.commit()
        data_start = store.min_discovered_date(conn)
        today = datetime.now(timezone.utc).date().isoformat()
        stats = store.victims_stats_in_range(conn, data_start, today)
        assert stats["victims"] == 2
    finally:
        conn.close()


# ---------- 4. route-level response shape ----------

def test_pulse_response_has_data_start_and_five_ranges():
    conn = store._connect()
    try:
        _seed_victim(conn, group="g1", victim="V1", country="PH", discovered="2022-03-15T00:00:00Z")
        _mark_collected(conn, "victims_stats")
    finally:
        conn.close()
    r = _client().get("/api/ransomware/pulse")
    data = r.json()
    assert data["data_start"] == "2022-03-15"
    assert set(data["ranges"].keys()) == {"30d", "90d", "12mo", "ytd", "all"}
    for key, bucket in data["ranges"].items():
        assert "start" in bucket and "end" in bucket and "victims" in bucket


def test_map_ph_sea_latest_watchlist_all_carry_ranges_and_data_start():
    conn = store._connect()
    try:
        _seed_victim(conn, group="g1", victim="V1", country="PH", discovered="2023-06-01T00:00:00Z")
        store.record_watchlist_hit(conn, term="Petron", tier=1, match_type="notes", matched_name="Petron",
                                    group_name="g1", discovered="2023-06-01T00:00:00Z", now_iso=NOW_ISO)
        _mark_collected(conn, "victims_stats", "watchlist")
    finally:
        conn.close()
    client = _client()
    for path in ["/api/ransomware/map", "/api/ransomware/ph-sea", "/api/ransomware/latest", "/api/ransomware/watchlist"]:
        data = client.get(path).json()
        assert data["data_start"] == "2023-06-01", path
        assert set(data["ranges"].keys()) == {"30d", "90d", "12mo", "ytd", "all"}, path


def test_cold_start_ranges_endpoints_degrade_gracefully():
    client = _client()
    for path in ["/api/ransomware/pulse", "/api/ransomware/map", "/api/ransomware/ph-sea",
                 "/api/ransomware/latest", "/api/ransomware/watchlist"]:
        data = client.get(path).json()
        assert data["state"] == "not_yet_collected", path
        assert data["data_start"] is None, path
        assert data["ranges"] == {}, path
