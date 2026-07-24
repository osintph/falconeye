"""
Ransomware Watch: country filter + company search (v3.17.0 brief, Part 5).

Both features are guarded exceptions to the v3.16.0 "collector-only, never an
upstream call from a request-serving path" rule - this file specifically
exercises those guards: standing-scope countries never go upstream, TTL
caching on the country path, always-upstream-with-cache-as-degraded-fallback
on search, dedup against collector rows, and that neither the search string
nor the API key ever land in a persisted table or a log line.

HTTP calls are faked with httpx.MockTransport (already a dependency) at the
app.ransomware.live layer directly (unit tests for extraction/HTTP handling)
or by monkeypatching live.fetch_country_live/fetch_search_live wholesale
(route-level tests, where what's under test is the caching/rate-limit/dedup
logic in routes.py, not HTTP handling).
"""
import os

os.environ.setdefault("RANSOMWARE_DB", "/tmp/falconeye_ransomware_search_test.db")
os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import asyncio
import json
import logging

import httpx
import pytest
from fastapi.testclient import TestClient

from app.ransomware import live, store

TEST_KEY = "sk-test-ransomware-live-DO-NOT-LEAK-9f3a7c21"


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    monkeypatch.setattr(live, "RANSOMWARE_LIVE_API_KEY", TEST_KEY, raising=False)
    store.init_tables()
    conn = store._connect()
    try:
        for table in (
            "victims", "groups", "mirrors", "press", "watchlist_hits", "collector_runs",
            "country_coverage", "ransomware_country_ondemand_rate_limit", "ransomware_search_rate_limit",
        ):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
    finally:
        conn.close()
    live._search_cache.clear()  # process-global in-memory cache leaks across tests otherwise
    yield


def _all_db_text() -> str:
    conn = store._connect()
    try:
        chunks = []
        for table in (
            "victims", "country_coverage", "ransomware_country_ondemand_rate_limit", "ransomware_search_rate_limit",
        ):
            rows = conn.execute(f"SELECT * FROM {table}").fetchall()
            chunks.append(json.dumps([dict(r) for r in rows]))
        return "\n".join(chunks)
    finally:
        conn.close()


def _client():
    from app.main import app
    return TestClient(app)


def _fake_async(retval):
    async def _f(*a, **kw):
        return retval
    return _f


def _counting_fake(retval):
    calls = {"n": 0}
    async def _f(*a, **kw):
        calls["n"] += 1
        return retval
    return _f, calls


PRO_VICTIM = {
    "group": "lockbit", "victim": "Acme DE GmbH", "country": "DE", "activity": "Manufacturing",
    "discovered": "2026-07-20T00:00:00Z", "attackdate": None, "infostealer": None,
    "permalink": "https://www.ransomware.live/id/abc123",
}


# ---------- 1. standing scope never triggers upstream ----------

def test_standing_scope_country_never_triggers_upstream_call(monkeypatch):
    def _boom(*a, **kw):
        raise AssertionError("fetch_country_live must never be called for a standing-scope country")
    monkeypatch.setattr(live, "fetch_country_live", _boom)

    resp = _client().get("/api/ransomware/country/PH")
    assert resp.status_code == 200
    assert resp.json()["coverage_state"] == "standing_scope"


# ---------- 2. out-of-scope country: one call, then cache within TTL ----------

def test_out_of_scope_country_one_call_then_cached(monkeypatch):
    fake, calls = _counting_fake(([PRO_VICTIM], "ok"))
    monkeypatch.setattr(live, "fetch_country_live", fake)

    r1 = _client().get("/api/ransomware/country/DE")
    assert r1.status_code == 200
    assert r1.json()["coverage_state"] == "fetched_now"
    assert calls["n"] == 1

    r2 = _client().get("/api/ransomware/country/DE")
    assert r2.status_code == 200
    assert r2.json()["coverage_state"] == "cached"
    assert calls["n"] == 1  # no second upstream call within TTL


# ---------- 3. coverage distinguishes never-fetched from fetched-and-empty ----------

def test_coverage_distinguishes_never_fetched_from_fetched_empty(monkeypatch):
    # Never fetched, upstream also unreachable -> honest "not yet queried".
    monkeypatch.setattr(live, "fetch_country_live", _fake_async((None, "unavailable")))
    r1 = _client().get("/api/ransomware/country/FR")
    assert r1.status_code == 200
    body1 = r1.json()
    assert body1["coverage_state"] == "not_yet_queried"
    assert body1["victims"] == []

    # Fetched, zero results -> distinct state, not conflated with "never checked".
    monkeypatch.setattr(live, "fetch_country_live", _fake_async(([], "ok")))
    r2 = _client().get("/api/ransomware/country/AQ")
    assert r2.status_code == 200
    body2 = r2.json()
    assert body2["coverage_state"] == "fetched_now"
    assert body2["victim_count"] == 0
    assert body2["victims"] == []
    assert body2["coverage_state"] != body1["coverage_state"]


# ---------- 4. on-demand writes source='on_demand' without touching collector rows ----------

def test_on_demand_fetch_does_not_overwrite_collector_stamped_rows(monkeypatch):
    conn = store._connect()
    try:
        store.upsert_country_coverage(conn, country="PH", victim_count=80, source="collector", now_iso="2026-07-01T00:00:00Z")
        conn.commit()
    finally:
        conn.close()

    monkeypatch.setattr(live, "fetch_country_live", _fake_async(([PRO_VICTIM], "ok")))
    resp = _client().get("/api/ransomware/country/DE")
    assert resp.status_code == 200
    assert resp.json()["source"] == "on_demand"

    conn = store._connect()
    try:
        ph_row = conn.execute("SELECT source, victim_count FROM country_coverage WHERE country='PH'").fetchone()
        de_row = conn.execute("SELECT source FROM country_coverage WHERE country='DE'").fetchone()
    finally:
        conn.close()
    assert ph_row["source"] == "collector"
    assert ph_row["victim_count"] == 80  # untouched
    assert de_row["source"] == "on_demand"


# ---------- 5. search under 3 chars rejected before any outbound call ----------

def test_search_under_three_chars_rejected_before_outbound_call(monkeypatch):
    def _boom(*a, **kw):
        raise AssertionError("fetch_search_live must never be called for a sub-3-char query")
    monkeypatch.setattr(live, "fetch_search_live", _boom)

    resp = _client().get("/api/ransomware/search?q=ab")
    assert resp.status_code == 400


# ---------- 6. identical queries within cache TTL -> one upstream call ----------

def test_identical_search_within_ttl_produces_one_upstream_call(monkeypatch):
    fake, calls = _counting_fake(([PRO_VICTIM], "ok"))
    monkeypatch.setattr(live, "fetch_search_live", fake)

    r1 = _client().get("/api/ransomware/search?q=Acme DE")
    r2 = _client().get("/api/ransomware/search?q=  acme   de  ")  # same after normalize (lowercase, whitespace-collapsed)
    assert r1.status_code == 200 and r2.status_code == 200
    assert calls["n"] == 1
    assert r2.json()["cache_hit"] is True


# ---------- 7. search write-back deduplicates against collector rows ----------

def test_search_writeback_deduplicates_against_collector_rows():
    conn = store._connect()
    try:
        vid = store.upsert_victim(
            conn, group_name="lockbit", victim_name="Acme DE GmbH", country="DE", sector="Manufacturing",
            discovered="2026-07-20T00:00:00Z", attackdate=None, infostealer=None, permalink=None,
            first_seen_via="collector", now_iso="2026-07-19T00:00:00Z",
        )
        conn.commit()
    finally:
        conn.close()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(live, "fetch_search_live", _fake_async(([PRO_VICTIM], "ok")))
        resp = _client().get("/api/ransomware/search?q=Acme DE GmbH")
    assert resp.status_code == 200

    conn = store._connect()
    try:
        count = conn.execute("SELECT COUNT(*) FROM victims WHERE id = ?", (vid,)).fetchone()[0]
        row = conn.execute("SELECT first_seen_via FROM victims WHERE id = ?", (vid,)).fetchone()
    finally:
        conn.close()
    assert count == 1  # no duplicate row
    assert row["first_seen_via"] == "collector"  # not overwritten to 'search'


# ---------- 8. zero-result wording ----------

def test_zero_result_response_wording(monkeypatch):
    monkeypatch.setattr(live, "fetch_search_live", _fake_async(([], "ok")))
    resp = _client().get("/api/ransomware/search?q=zzznonexistentxyz")
    assert resp.status_code == 200
    note = resp.json()["zero_result_note"] or ""
    assert "tracked leak sites" in note.lower()
    for banned in ("clean", "unaffected", "not breached", "not affected"):
        assert banned not in note.lower()


# ---------- 9. PRO 401 on search: labelled local fallback, not a 500 ----------

def test_search_401_serves_labelled_local_fallback(monkeypatch):
    conn = store._connect()
    try:
        store.upsert_victim(
            conn, group_name="lockbit", victim_name="Fallback Findable Corp", country="US", sector="Tech",
            discovered="2026-07-20T00:00:00Z", attackdate=None, infostealer=None, permalink=None,
            first_seen_via="collector", now_iso="2026-07-19T00:00:00Z",
        )
        conn.commit()
    finally:
        conn.close()

    monkeypatch.setattr(live, "fetch_search_live", _fake_async((None, "unavailable")))
    resp = _client().get("/api/ransomware/search?q=Fallback Findable")
    assert resp.status_code == 200
    body = resp.json()
    assert body["degraded"] is True
    assert body["degraded_note"]
    names = [v["victim_name"] for v in body["victims"]]
    assert "Fallback Findable Corp" in names


# ---------- 10. PRO 401 on country: cache or not-queried, not a 500 ----------

def test_country_401_serves_cache_or_not_queried_state(monkeypatch):
    # No prior coverage -> not_yet_queried, not a 500.
    monkeypatch.setattr(live, "fetch_country_live", _fake_async((None, "unavailable")))
    r1 = _client().get("/api/ransomware/country/BR")
    assert r1.status_code == 200
    assert r1.json()["coverage_state"] == "not_yet_queried"

    # Prior coverage exists -> serves it, labelled unavailable, not a 500.
    conn = store._connect()
    try:
        store.upsert_victim(
            conn, group_name="qilin", victim_name="Brasil Corp", country="BR", sector="Retail",
            discovered="2026-07-01T00:00:00Z", attackdate=None, infostealer=None, permalink=None,
            first_seen_via="on_demand", now_iso="2026-07-01T00:00:00Z",
        )
        store.upsert_country_coverage(conn, country="BR", victim_count=1, source="on_demand", now_iso="2026-07-01T00:00:00Z")
        conn.commit()
    finally:
        conn.close()

    r2 = _client().get("/api/ransomware/country/BR")
    assert r2.status_code == 200
    body2 = r2.json()
    assert body2["coverage_state"] == "cached"
    assert body2["upstream_status"] == "unavailable"
    assert len(body2["victims"]) == 1


# ---------- 11. search string never persisted, in any table or log line ----------

def test_search_string_absent_from_every_persisted_table_and_log(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    secret_query = "zzzTOPSECRETSEARCHTERMzzz do not persist"
    monkeypatch.setattr(live, "fetch_search_live", _fake_async(([PRO_VICTIM], "ok")))

    resp = _client().get("/api/ransomware/search?q=" + secret_query)
    assert resp.status_code == 200

    assert secret_query not in _all_db_text()
    assert secret_query not in caplog.text


# ---------- 12. API key absent from every response and log line under failure paths ----------

def test_api_key_absent_under_all_failure_paths(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)

    # Layer 1: exercise live.py's own HTTP handling against a real 401
    # response (via MockTransport, no network) - the key never leaves this
    # function except in the outbound request header, which caplog can't see.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    async def _scenario():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0) as c:
            result_country = await live.fetch_country_live("DE", client=c)
            result_search = await live.fetch_search_live("somequery", client=c)
        return result_country, result_search

    (victims_c, status_c), (victims_s, status_s) = asyncio.run(_scenario())
    assert victims_c is None and status_c == "unavailable"
    assert victims_s is None and status_s == "unavailable"
    assert TEST_KEY not in caplog.text

    # Layer 2: the route layer under the same failure, end to end.
    monkeypatch.setattr(live, "fetch_country_live", _fake_async((None, "unavailable")))
    monkeypatch.setattr(live, "fetch_search_live", _fake_async((None, "unavailable")))
    resp1 = _client().get("/api/ransomware/country/BR")
    resp2 = _client().get("/api/ransomware/search?q=somequery")
    assert resp1.status_code == 200 and resp2.status_code == 200
    assert TEST_KEY not in json.dumps(resp1.json())
    assert TEST_KEY not in json.dumps(resp2.json())
    assert TEST_KEY not in caplog.text
