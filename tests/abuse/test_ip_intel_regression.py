"""
Regression: the IP Reputation tab 500'd on a freshly-created database because
app/routers/ip_intel.py assumed `ip_intel_cache` already existed and never
created it (unlike every other router). A new-feature deploy onto a fresh DB
surfaced it. These tests pin the fix: ip_intel self-creates its cache table at
import, so the tab returns 200 with base data regardless of DB provenance.
"""
import sqlite3

from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.routers import ip_intel


def test_ip_intel_cache_table_created_at_import():
    conn = sqlite3.connect(ip_intel.DB_PATH)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert "ip_intel_cache" in tables


def test_ip_intel_cache_roundtrip_after_reinit():
    # Simulate a fresh DB: drop, then re-run what import does.
    conn = sqlite3.connect(ip_intel.DB_PATH)
    conn.execute("DROP TABLE IF EXISTS ip_intel_cache")
    conn.commit()
    conn.close()
    ip_intel._init_cache()

    conn = sqlite3.connect(ip_intel.DB_PATH)
    conn.row_factory = sqlite3.Row
    # Without the fix this raises sqlite3.OperationalError: no such table.
    assert ip_intel.get_cached(conn, "1.1.1.1") is None
    ip_intel.store_cache(conn, "1.1.1.1", {"ip": "1.1.1.1", "ok": True})
    got = ip_intel.get_cached(conn, "1.1.1.1")
    conn.close()
    assert got and got["ip"] == "1.1.1.1"


def test_ip_lookup_endpoint_returns_200_on_fresh_db(monkeypatch):
    """The reported failure: endpoint must return 200 + base JSON, not a 500 HTML page."""
    async def _none(*a, **k):
        return None

    async def _empty(*a, **k):
        return []

    monkeypatch.setattr(ip_intel, "fetch_shodan_internetdb", _none)
    monkeypatch.setattr(ip_intel, "fetch_greynoise", _none)
    monkeypatch.setattr(ip_intel, "fetch_ripestat", _none)
    monkeypatch.setattr(ip_intel, "fetch_urlhaus_host", _none)
    monkeypatch.setattr(ip_intel, "fetch_reverse_dns", _empty)

    # ensure the table is present (as it is at import)
    ip_intel._init_cache()

    app = FastAPI()
    app.state.limiter = ip_intel.limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(ip_intel.router)
    client = TestClient(app)

    r = client.get("/api/ip/lookup/8.8.8.8")
    assert r.status_code == 200
    data = r.json()
    assert data["ip"] == "8.8.8.8"
    # base tab renders even though every enrichment source returned nothing
    assert data["shodan"] is None and data["greynoise"] is None
