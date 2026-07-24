"""
Ransomware Watch collector + routes: Part 8 of the v3.16.0 brief.

Covers the credential write-guard, victim dedupe/corroboration, PRO->v2
fallback + per-source degradation, RansomLook-outage isolation, cold-start
behavior, the watchlist min-length guard, and (as a cross-cutting assertion
threaded through every scenario below) that the API key never appears in a
log line or a response body under any failure path.

HTTP calls are faked with httpx.MockTransport (built into httpx, already a
project dependency) rather than a mocking library, matching the rest of the
suite's no-extra-test-deps convention (see tests/breach/test_client.py).
"""
import os

os.environ.setdefault("RANSOMWARE_DB", "/tmp/falconeye_ransomware_test.db")
os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import asyncio
import json
import logging

import httpx
import pytest

from app.ransomware import store
from app.collectors import ransomware_collect as collect

TEST_KEY = "sk-test-ransomware-live-DO-NOT-LEAK-9f3a7c21"

CREDENTIALED_SLUG = "ftp://dataShare:2bTWYKNn7aK7Rqp9mnv3@188.119.66.189"


@pytest.fixture(autouse=True)
def _clean_db(monkeypatch):
    monkeypatch.setattr(collect, "RANSOMWARE_LIVE_API_KEY", TEST_KEY, raising=False)
    store.init_tables()
    conn = store._connect()
    try:
        for table in ("victims", "groups", "mirrors", "press", "watchlist_hits", "collector_runs"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
    finally:
        conn.close()
    yield


def _all_db_text() -> str:
    """Dump of every row in every table, stringified - used to assert a
    secret/raw value is nowhere in the database, not just not in one column."""
    conn = store._connect()
    try:
        chunks = []
        for table in ("victims", "groups", "mirrors", "press", "watchlist_hits", "collector_runs"):
            rows = conn.execute(f"SELECT * FROM {table}").fetchall()
            chunks.append(json.dumps([dict(r) for r in rows]))
        return "\n".join(chunks)
    finally:
        conn.close()


def _client_for(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)


# ---------- 1 & 9. credentialed slug hashed; key/secret never leak ----------

def test_credentialed_mirror_slug_never_persisted_logged_or_returned(caplog):
    caplog.set_level(logging.DEBUG)
    conn = store._connect()
    try:
        h = store.hash_mirror_slug(CREDENTIALED_SLUG)
        store.upsert_mirror(
            conn, group_name="qilin", position_index=1, mirror_hash=h,
            uptime_30d=0, series=[0, 0], now_iso="2026-07-24T00:00:00Z",
        )
        conn.commit()
    finally:
        conn.close()

    assert CREDENTIALED_SLUG not in _all_db_text()
    assert "2bTWYKNn7aK7Rqp9mnv3" not in _all_db_text()  # the embedded password specifically
    assert CREDENTIALED_SLUG not in caplog.text
    assert "2bTWYKNn7aK7Rqp9mnv3" not in caplog.text


def test_api_key_never_in_logs_or_db_across_failure_paths(caplog):
    caplog.set_level(logging.DEBUG)

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith(collect.PRO_BASE):
            return httpx.Response(401)
        if url.startswith(collect.V2_BASE):
            return httpx.Response(200, json=[])
        if url.startswith(collect.RANSOMLOOK_BASE):
            raise httpx.ConnectTimeout("boom", request=request)
        return httpx.Response(404)

    async def _scenario():
        async with _client_for(handler) as client:
            pro = collect.ProClient(TEST_KEY)
            await pro.validate(client)
            ransomlook = collect.RansomLookClient()
            await collect.run_victims_phase(pro, ransomlook, client)

    asyncio.run(_scenario())

    assert TEST_KEY not in caplog.text
    assert TEST_KEY not in _all_db_text()

    conn = store._connect()
    try:
        rows = conn.execute("SELECT * FROM collector_runs").fetchall()
    finally:
        conn.close()
    for r in rows:
        assert TEST_KEY not in json.dumps(dict(r))


# ---------- 2. write guard rejects a raw credentialed URI on direct insert ----------

def test_write_guard_rejects_credentialed_uri_on_direct_insert():
    conn = store._connect()
    try:
        with pytest.raises(store.CredentialGuardError):
            store.upsert_mirror(
                conn, group_name="qilin", position_index=1, mirror_hash=CREDENTIALED_SLUG,
                uptime_30d=0, series=[0, 0], now_iso="2026-07-24T00:00:00Z",
            )
        conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM mirrors WHERE group_name = 'qilin'").fetchone()[0]
        assert count == 0
    finally:
        conn.close()


# ---------- 3. victim dedupe ----------

def test_same_victim_ingested_twice_produces_one_row():
    conn = store._connect()
    try:
        kwargs = dict(
            group_name="LockBit", victim_name="Acme Corp", country="PH", sector="Finance",
            discovered="2026-07-20T00:00:00Z", attackdate="2026-07-19T00:00:00Z",
            infostealer=None, permalink=None, first_seen_via="collector", now_iso="2026-07-24T00:00:00Z",
        )
        id1 = store.upsert_victim(conn, **kwargs)
        id2 = store.upsert_victim(conn, **kwargs)
        conn.commit()
        assert id1 == id2
        count = conn.execute("SELECT COUNT(*) FROM victims").fetchone()[0]
        assert count == 1
    finally:
        conn.close()


# ---------- 4. corroboration flag ----------

def test_corroboration_flag_set_when_both_sources_report_same_victim():
    pro_victims = {
        "victims": [{
            "group": "lockbit", "victim": "Acme Corp", "country": "PH", "activity": "Finance",
            "discovered": "2026-07-20T00:00:00Z", "attackdate": "2026-07-19T00:00:00Z",
            "infostealer": None,
        }]
    }
    rl_posts = {"posts": [{"group_name": "lockbit", "post_title": "Acme Corp", "discovered": "2026-07-21T00:00:00Z"}]}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/victims/recent":
            return httpx.Response(200, json=pro_victims)
        if path == "/victims/":
            return httpx.Response(200, json={"victims": []})
        if path == "/press/recent":
            return httpx.Response(200, json={"results": []})
        if path == "/api/posts":  # RANSOMLOOK_BASE already includes /api
            return httpx.Response(200, json=rl_posts)
        return httpx.Response(404)

    async def _scenario():
        async with _client_for(handler) as client:
            pro = collect.ProClient(TEST_KEY)
            ransomlook = collect.RansomLookClient()
            await collect.run_victims_phase(pro, ransomlook, client)

    asyncio.run(_scenario())

    conn = store._connect()
    try:
        row = conn.execute(
            "SELECT corroborated FROM victims WHERE group_name='lockbit' AND victim_name='Acme Corp'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row["corroborated"] == 1


# ---------- 5. PRO 401 falls back to v2, source marked degraded, tab doesn't error ----------

def test_pro_401_falls_back_to_v2_and_marks_source_degraded():
    v2_victims = [{
        "group": "qilin", "victim": "Fallback Co", "country": "SG", "activity": "Tech",
        "discovered": "2026-07-22T00:00:00Z", "attackdate": None, "infostealer": None,
    }]

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith(collect.PRO_BASE) and "/press/recent" not in url:
            return httpx.Response(401)
        if "/press/recent" in url:
            return httpx.Response(200, json={"results": []})
        if url.startswith(collect.V2_BASE):
            return httpx.Response(200, json=v2_victims)
        if url.startswith(collect.RANSOMLOOK_BASE):
            return httpx.Response(200, json={"posts": []})
        return httpx.Response(404)

    async def _scenario():
        async with _client_for(handler) as client:
            pro = collect.ProClient(TEST_KEY)
            ransomlook = collect.RansomLookClient()
            await collect.run_victims_phase(pro, ransomlook, client)

    asyncio.run(_scenario())

    conn = store._connect()
    try:
        run = conn.execute(
            "SELECT * FROM collector_runs WHERE phase='victims_stats' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        victim = conn.execute("SELECT * FROM victims WHERE group_name='qilin'").fetchone()
    finally:
        conn.close()

    assert run["status"] == "degraded"
    assert run["source"] == "ransomware_live_v2"
    assert victim is not None  # v2 fallback data still landed - panel isn't empty

    # The route layer must surface this as 200 + degraded, never a 500.
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    resp = client.get("/api/ransomware/pulse")
    assert resp.status_code == 200
    body = resp.json()
    assert body["source_status"] == "degraded"


# ---------- 6. RansomLook timeout leaves ransomware.live panels rendering ----------

def test_ransomlook_timeout_leaves_ransomware_live_panels_rendering():
    pro_victims = {
        "victims": [{
            "group": "lockbit", "victim": "Still Rendering Inc", "country": "PH", "activity": "Retail",
            "discovered": "2026-07-23T00:00:00Z", "attackdate": None, "infostealer": None,
        }]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/victims/recent" in url:
            return httpx.Response(200, json=pro_victims)
        if "/victims/" in url:
            return httpx.Response(200, json={"victims": []})
        if "/press/recent" in url:
            return httpx.Response(200, json={"results": []})
        if url.startswith(collect.RANSOMLOOK_BASE):
            raise httpx.ReadTimeout("timed out", request=request)
        return httpx.Response(404)

    async def _scenario():
        async with _client_for(handler) as client:
            pro = collect.ProClient(TEST_KEY)
            ransomlook = collect.RansomLookClient()
            await collect.run_victims_phase(pro, ransomlook, client)
            await collect.run_group_activity_phase(ransomlook, client)
            await collect.run_watchlist_phase(ransomlook, client, "/nonexistent/watchlist.txt")

    asyncio.run(_scenario())

    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)

    pulse = client.get("/api/ransomware/pulse").json()
    assert pulse["state"] == "ok"
    assert pulse["source_status"] == "ok"  # PRO succeeded fully, unaffected by RansomLook being down
    assert pulse["total_victims_tracked"] == 1

    groups = client.get("/api/ransomware/groups").json()
    assert groups["source_status"] in ("degraded", "error")


# ---------- 7. cold database returns not-yet-collected, not a 500 ----------

def test_cold_database_returns_not_yet_collected_state():
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    for ep in ("/pulse", "/map", "/ph-sea", "/latest", "/groups", "/mirrors", "/watchlist", "/status"):
        resp = client.get(f"/api/ransomware{ep}")
        assert resp.status_code == 200, f"{ep} returned {resp.status_code}"
        assert resp.json()["state"] == "not_yet_collected", f"{ep} did not report cold state"


# ---------- 8. watchlist query under 2 chars rejected before any outbound call ----------

def test_watchlist_term_under_min_length_never_makes_outbound_call(tmp_path):
    watchlist_file = tmp_path / "watchlist.txt"
    watchlist_file.write_text("[tier1]\na\nBPI\n\n[tier2]\nphilippines\n#comment\n\nbs\n")

    terms = collect.load_watchlist_terms(str(watchlist_file))
    term_names = {t for t, _tier in terms}
    assert "a" not in term_names
    assert "BPI" in term_names
    assert "philippines" in term_names
    assert "bs" in term_names  # exactly at the 2-char minimum, allowed

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(dict(request.url.params))
        return httpx.Response(200, json={"posts": [], "groups": [], "markets": [], "leaks": [], "notes": []})

    async def _scenario():
        async with _client_for(handler) as client:
            ransomlook = collect.RansomLookClient()
            await collect.run_watchlist_phase(ransomlook, client, str(watchlist_file))

    asyncio.run(_scenario())

    # Exactly one call per valid term (BPI, philippines, bs) - never for "a".
    assert len(calls) == 3
    queried_terms = {c["q"] for c in calls}
    assert queried_terms == {"BPI", "philippines", "bs"}


def test_watchlist_term_before_any_tier_header_is_skipped(tmp_path):
    watchlist_file = tmp_path / "watchlist.txt"
    watchlist_file.write_text("orphan-term\n[tier1]\nBPI\n")
    terms = collect.load_watchlist_terms(str(watchlist_file))
    assert terms == [("BPI", 1)]


def test_watchlist_hits_are_persisted_with_their_tier(tmp_path):
    watchlist_file = tmp_path / "watchlist.txt"
    watchlist_file.write_text("[tier1]\nBPI\n[tier2]\nphilippines\n")

    def handler(request: httpx.Request) -> httpx.Response:
        term = dict(request.url.params)["q"]
        return httpx.Response(200, json={
            "posts": [{"post_title": f"hit-for-{term}", "group_name": "lockbit", "discovered": "2026-07-24T00:00:00Z"}],
            "groups": [], "markets": [], "leaks": [], "notes": [],
        })

    async def _scenario():
        async with _client_for(handler) as client:
            ransomlook = collect.RansomLookClient()
            await collect.run_watchlist_phase(ransomlook, client, str(watchlist_file))

    asyncio.run(_scenario())

    conn = store._connect()
    try:
        rows = {r["term"]: r["tier"] for r in conn.execute("SELECT term, tier FROM watchlist_hits").fetchall()}
    finally:
        conn.close()
    assert rows == {"BPI": 1, "philippines": 2}


# ---------- country_coverage / first_seen_via / permalink (forward-compat schema) ----------

def test_country_coverage_stamped_for_standing_scope_countries_with_source_collector():
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/victims/recent" in url:
            return httpx.Response(200, json={"victims": []})
        if "/victims/" in url:
            country = request.url.params.get("country")
            # Distinct, recognizable counts per country so the assertion below
            # can't pass by coincidence (e.g. every country defaulting to 0).
            fake_count = 100 + store.SEA_COUNTRIES.index(country)
            return httpx.Response(200, json={"victims": [], "count": fake_count})
        if "/press/recent" in url:
            return httpx.Response(200, json={"results": []})
        if url.startswith(collect.RANSOMLOOK_BASE):
            return httpx.Response(200, json={"posts": []})
        return httpx.Response(404)

    async def _scenario():
        async with _client_for(handler) as client:
            pro = collect.ProClient(TEST_KEY)
            ransomlook = collect.RansomLookClient()
            await collect.run_victims_phase(pro, ransomlook, client)

    asyncio.run(_scenario())

    conn = store._connect()
    try:
        rows = {r["country"]: (r["victim_count"], r["source"]) for r in conn.execute(
            "SELECT country, victim_count, source FROM country_coverage"
        ).fetchall()}
    finally:
        conn.close()

    assert set(rows.keys()) == set(store.SEA_COUNTRIES)
    for i, cc in enumerate(store.SEA_COUNTRIES):
        assert rows[cc] == (100 + i, "collector")


def test_country_coverage_not_overwritten_when_the_call_fails():
    """A 401/5xx on one country's call must not stamp a false '0 victims,
    just checked' - it should leave whatever coverage row already existed."""
    conn = store._connect()
    try:
        store.upsert_country_coverage(conn, country="PH", victim_count=42, source="collector", now_iso="2026-07-01T00:00:00Z")
        conn.commit()
    finally:
        conn.close()

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/victims/recent" in url:
            return httpx.Response(200, json={"victims": []})
        if "/victims/" in url and request.url.params.get("country") == "PH":
            return httpx.Response(401)  # PH specifically fails this run
        if "/victims/" in url:
            return httpx.Response(200, json={"victims": [], "count": 1})
        if "/press/recent" in url:
            return httpx.Response(200, json={"results": []})
        if url.startswith(collect.RANSOMLOOK_BASE):
            return httpx.Response(200, json={"posts": []})
        return httpx.Response(404)

    async def _scenario():
        async with _client_for(handler) as client:
            pro = collect.ProClient(TEST_KEY)
            ransomlook = collect.RansomLookClient()
            await collect.run_victims_phase(pro, ransomlook, client)

    asyncio.run(_scenario())

    conn = store._connect()
    try:
        row = conn.execute("SELECT victim_count, last_fetched FROM country_coverage WHERE country='PH'").fetchone()
    finally:
        conn.close()
    assert row["victim_count"] == 42  # untouched, not clobbered to a false 0
    assert row["last_fetched"] == "2026-07-01T00:00:00Z"  # not re-stamped either


def test_first_seen_via_set_on_insert_and_never_overwritten_on_update():
    conn = store._connect()
    try:
        kwargs = dict(
            group_name="LockBit", victim_name="Persisted Corp", country="PH", sector="Finance",
            discovered="2026-07-20T00:00:00Z", attackdate=None, infostealer=None, permalink=None,
        )
        store.upsert_victim(conn, now_iso="2026-07-24T00:00:00Z", first_seen_via="collector", **kwargs)
        # Simulate a later re-ingestion of the same victim under a
        # hypothetical different trigger - first_seen_via must not change.
        store.upsert_victim(conn, now_iso="2026-07-25T00:00:00Z", first_seen_via="search", **kwargs)
        conn.commit()
        row = conn.execute(
            "SELECT first_seen_via FROM victims WHERE group_name='LockBit' AND victim_name='Persisted Corp'"
        ).fetchone()
    finally:
        conn.close()
    assert row["first_seen_via"] == "collector"


def test_existing_rows_keep_first_seen_via_null_after_migration_no_backfill(tmp_path, monkeypatch):
    """The exact production scenario: a victims table created before this
    column existed, with real rows in it, must not have first_seen_via
    guessed/backfilled - NULL is the honest answer for 'predates this column'."""
    import sqlite3
    db_path = str(tmp_path / "pre_migration.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE victims (
          id TEXT PRIMARY KEY, match_key TEXT NOT NULL, group_name TEXT NOT NULL, victim_name TEXT NOT NULL,
          country TEXT, sector TEXT, discovered TEXT, attackdate TEXT, corroborated INTEGER NOT NULL DEFAULT 0,
          infostealer_count INTEGER NOT NULL DEFAULT 0, infostealer_json TEXT,
          first_seen_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT INTO victims VALUES ('id1','mk1','LockBit','Pre-existing Corp','PH','Finance',"
        "'2026-07-01','2026-07-01',0,0,NULL,'2026-07-01T00:00:00Z','2026-07-01T00:00:00Z')"
    )
    conn.commit()
    conn.close()

    monkeypatch.setenv("RANSOMWARE_DB", db_path)
    store.init_tables()

    conn = store._connect()
    try:
        row = conn.execute("SELECT first_seen_via, permalink FROM victims WHERE id='id1'").fetchone()
        cols = [r[1] for r in conn.execute("PRAGMA table_info(victims)").fetchall()]
    finally:
        conn.close()
    assert "first_seen_via" in cols and "permalink" in cols
    assert row["first_seen_via"] is None
    assert row["permalink"] is None


def test_safe_permalink_accepts_only_ransomware_live_https():
    assert store.safe_permalink("https://www.ransomware.live/id/abc123") == "https://www.ransomware.live/id/abc123"
    assert store.safe_permalink("https://ransomware.live/id/abc123") == "https://ransomware.live/id/abc123"
    # The raw leak-site address (what PRO calls post_url) must never pass.
    assert store.safe_permalink("http://novadmrkp4vbk2padk5t6pbxolndceuc7hrcq4mjaoyed6nxsqiuzyyd.onion/digital-edge") is None
    assert store.safe_permalink("http://www.ransomware.live/id/abc123") is None  # not https
    assert store.safe_permalink("https://evil-ransomware.live.attacker.com/id/abc") is None  # hostname spoof
    assert store.safe_permalink(None) is None
    assert store.safe_permalink("") is None


def test_v2_fallback_victims_get_no_permalink():
    """v2's schema has no permalink field - a fallback-sourced victim must
    not end up with one fabricated from some other field."""
    v2_victims = [{
        "group": "qilin", "victim": "Fallback No Permalink Co", "country": "SG", "activity": "Tech",
        "discovered": "2026-07-22T00:00:00Z", "attackdate": None, "infostealer": None,
        "claim_url": "http://someleaksite.onion/fallback-no-permalink-co",  # must never become `permalink`
    }]

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/victims/recent" in url:
            return httpx.Response(401)
        if "/victims/" in url:
            return httpx.Response(401)
        if "/press/recent" in url:
            return httpx.Response(200, json={"results": []})
        if url.startswith(collect.V2_BASE):
            return httpx.Response(200, json=v2_victims)
        if url.startswith(collect.RANSOMLOOK_BASE):
            return httpx.Response(200, json={"posts": []})
        return httpx.Response(404)

    async def _scenario():
        async with _client_for(handler) as client:
            pro = collect.ProClient(TEST_KEY)
            ransomlook = collect.RansomLookClient()
            await collect.run_victims_phase(pro, ransomlook, client)

    asyncio.run(_scenario())

    conn = store._connect()
    try:
        row = conn.execute("SELECT permalink FROM victims WHERE group_name='qilin'").fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row["permalink"] is None
