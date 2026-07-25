"""
ASN Intelligence (v3.20.0). RIPEstat-only by design - see the module
docstring in app/ip_sources/asn_intel.py for why (BGPview, the originally
briefed source, turned out to have shut down 2025-11-26).

CRITICAL regression guard mirrors test_endpoint_resilience.py's spirit:
a broken/rate-limited RIPEstat call must degrade the ASN block to
unavailable, never 500 the endpoint or blank the rest of the IP result.
"""
import asyncio
import sqlite3

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.ip_sources import asn_intel
from app.routers import ip_intel


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _clean_cache():
    conn = sqlite3.connect(asn_intel.DB_PATH)
    conn.execute("DELETE FROM asn_intel_cache")
    conn.commit()
    conn.close()
    yield


@pytest.fixture
def db():
    conn = sqlite3.connect(asn_intel.DB_PATH)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


class FakeResp:
    def __init__(self, status, json_data=None):
        self.status_code = status
        self._json = json_data

    def json(self):
        if self._json is None:
            raise ValueError("no json body")
        return self._json


def _ok(data):
    return FakeResp(200, {"status": "ok", "data": data})


class RipeFakeClient:
    """Routes on the RIPEstat call name embedded in the URL
    (.../data/<call>/data.json) so a single fake client can stand in for
    network-info, as-overview, announced-prefixes, and asn-neighbours at once."""
    def __init__(self, responses, exc_calls=()):
        self._responses = responses
        self._exc_calls = set(exc_calls)
        self.calls = []

    async def get(self, url, params=None, **kw):
        call = next((c for c in self._responses if f"/{c}/" in url), None)
        self.calls.append((call, (params or {}).get("resource")))
        if call in self._exc_calls:
            raise RuntimeError("simulated network failure")
        if call is None or call not in self._responses:
            return FakeResp(404)
        return self._responses[call]


# ---------- cache table self-init (mirrors test_ip_intel_regression.py) ----------

def test_asn_intel_cache_table_created_at_import():
    conn = sqlite3.connect(asn_intel.DB_PATH)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert "asn_intel_cache" in tables


def test_asn_intel_cache_roundtrip_after_reinit(db):
    conn = sqlite3.connect(asn_intel.DB_PATH)
    conn.execute("DROP TABLE IF EXISTS asn_intel_cache")
    conn.commit()
    conn.close()
    asn_intel._init_cache()

    assert asn_intel._get_cached(db, "as_overview:13335") is None
    asn_intel._store_cache(db, "as_overview:13335", {"holder": "X"})
    assert asn_intel._get_cached(db, "as_overview:13335") == {"holder": "X"}


# ---------- _split_holder ----------

@pytest.mark.parametrize("holder,name,desc", [
    ("CLOUDFLARENET - Cloudflare, Inc.", "CLOUDFLARENET", "Cloudflare, Inc."),
    ("RIPE-NCC-AS RIPE Network Coordination Centre", None, "RIPE-NCC-AS RIPE Network Coordination Centre"),
    ("", None, None),
    (None, None, None),
])
def test_split_holder(holder, name, desc):
    assert asn_intel._split_holder(holder) == (name, desc)


# ---------- fetch_network_info ----------

def test_fetch_network_info_success():
    client = RipeFakeClient({"network-info": _ok({"asns": ["13335"], "prefix": "1.1.1.0/24"})})
    asn, prefix = run(asn_intel.fetch_network_info(client, "1.1.1.1"))
    assert asn == 13335 and prefix == "1.1.1.0/24"


def test_fetch_network_info_no_asn():
    client = RipeFakeClient({"network-info": _ok({"asns": [], "prefix": None})})
    assert run(asn_intel.fetch_network_info(client, "1.1.1.1")) == (None, None)


def test_fetch_network_info_http_error():
    client = RipeFakeClient({"network-info": FakeResp(500)})
    assert run(asn_intel.fetch_network_info(client, "1.1.1.1")) == (None, None)


# ---------- fetch_as_overview (caching) ----------

def test_fetch_as_overview_caches(db):
    client = RipeFakeClient({"as-overview": _ok({"holder": "CLOUDFLARENET - Cloudflare, Inc."})})
    r1 = run(asn_intel.fetch_as_overview(client, db, 13335))
    r2 = run(asn_intel.fetch_as_overview(client, db, 13335))
    assert r1 == r2 == {"holder": "CLOUDFLARENET - Cloudflare, Inc."}
    assert len(client.calls) == 1  # second call served from cache, no second HTTP hit


def test_fetch_as_overview_failure_not_cached(db):
    client = RipeFakeClient({"as-overview": FakeResp(500)})
    assert run(asn_intel.fetch_as_overview(client, db, 13335)) is None
    assert asn_intel._get_cached(db, "as_overview:13335") is None


# ---------- fetch_announced_prefixes (dedup + cap) ----------

def test_fetch_announced_prefixes_dedups_and_sorts(db):
    client = RipeFakeClient({"announced-prefixes": _ok({"prefixes": [
        {"prefix": "1.1.1.0/24"}, {"prefix": "1.1.1.0/24"}, {"prefix": "1.0.0.0/24"},
    ]})})
    result = run(asn_intel.fetch_announced_prefixes(client, db, 13335))
    assert result == {"list": ["1.0.0.0/24", "1.1.1.0/24"], "total_count": 2, "truncated": False}


def test_fetch_announced_prefixes_truncates(db, monkeypatch):
    monkeypatch.setattr(asn_intel, "PREFIX_SERVER_CAP", 3)
    prefixes = [{"prefix": f"10.0.{i}.0/24"} for i in range(5)]
    client = RipeFakeClient({"announced-prefixes": _ok({"prefixes": prefixes})})
    result = run(asn_intel.fetch_announced_prefixes(client, db, 13335))
    assert result["total_count"] == 5
    assert result["truncated"] is True
    assert len(result["list"]) == 3


# ---------- assemble_core ----------

def test_assemble_core_unavailable_when_both_missing():
    assert asn_intel.assemble_core(13335, "1.1.1.0/24", None, None) == {"available": False, "asn": 13335}


def test_assemble_core_singular_plural():
    prefixes_one = {"list": ["1.1.1.0/24"], "total_count": 1, "truncated": False}
    block = asn_intel.assemble_core(13335, "1.1.1.0/24", {"holder": "X - Y"}, prefixes_one)
    assert "1 prefix " in block["summary"] and "prefixes" not in block["summary"]

    prefixes_many = {"list": ["1.1.1.0/24"], "total_count": 2, "truncated": False}
    block2 = asn_intel.assemble_core(13335, "1.1.1.0/24", {"holder": "X - Y"}, prefixes_many)
    assert "2 prefixes" in block2["summary"]


def test_assemble_core_full_shape():
    block = asn_intel.assemble_core(
        13335, "1.1.1.0/24",
        {"holder": "CLOUDFLARENET - Cloudflare, Inc."},
        {"list": ["1.1.1.0/24"], "total_count": 5287, "truncated": False},
    )
    assert block["available"] is True
    assert block["asn"] == 13335
    assert block["name"] == "CLOUDFLARENET"
    assert block["description"] == "Cloudflare, Inc."
    assert block["covering_prefix"] == "1.1.1.0/24"
    assert "AS13335" in block["summary"] and "5,287" in block["summary"]


# ---------- fetch() end-to-end ----------

def test_fetch_happy_path(db):
    client = RipeFakeClient({
        "network-info": _ok({"asns": ["13335"], "prefix": "1.1.1.0/24"}),
        "as-overview": _ok({"holder": "CLOUDFLARENET - Cloudflare, Inc."}),
        "announced-prefixes": _ok({"prefixes": [{"prefix": "1.1.1.0/24"}]}),
    })
    block = run(asn_intel.fetch(client, db, "1.1.1.1"))
    assert block["available"] is True and block["asn"] == 13335


def test_fetch_unavailable_when_no_asn(db):
    client = RipeFakeClient({"network-info": _ok({"asns": [], "prefix": None})})
    assert run(asn_intel.fetch(client, db, "1.1.1.1")) == {"available": False}


def test_fetch_degrades_when_network_info_call_raises(db):
    # The httpx exception is caught inside _ripe_get itself, so this exercises
    # the "no ASN resolved" path, not fetch()'s own outer except - see the
    # next test for that.
    client = RipeFakeClient({"network-info": _ok({"asns": ["13335"], "prefix": "1.1.1.0/24"})},
                             exc_calls={"network-info"})
    assert run(asn_intel.fetch(client, db, "1.1.1.1")) == {"available": False}


def test_fetch_never_raises_on_unexpected_exception(db, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("unexpected bug")

    monkeypatch.setattr(asn_intel, "fetch_network_info", boom)
    assert run(asn_intel.fetch(object(), db, "1.1.1.1")) == {"available": False}


# ---------- fetch_routing ----------

def _neighbour(asn, type_, power):
    return {"asn": asn, "type": type_, "power": power, "v4_peers": power, "v6_peers": 0}


def test_fetch_routing_groups_and_caps(db):
    neighbours = (
        [_neighbour(1000 + i, "left", 100 - i) for i in range(20)] +
        [_neighbour(2000 + i, "right", 100 - i) for i in range(20)] +
        [_neighbour(3000 + i, "uncertain", 1) for i in range(5)]
    )
    client = RipeFakeClient({
        "asn-neighbours": _ok({"neighbours": neighbours}),
        "as-overview": _ok({"holder": "NEIGH - Neighbour Org"}),
    })
    routing = run(asn_intel.fetch_routing(client, db, 13335))
    assert routing["available"] is True
    assert routing["upstream_side"]["total"] == 20
    assert len(routing["upstream_side"]["shown"]) == 15
    assert routing["upstream_side"]["shown"][0]["asn"] == 1000  # power=100, highest
    assert routing["downstream_side"]["total"] == 20
    assert len(routing["downstream_side"]["shown"]) == 15
    assert routing["uncertain_count"] == 5
    assert routing["upstream_side"]["shown"][0]["name"] == "NEIGH"


def test_fetch_routing_unavailable_on_failure(db):
    client = RipeFakeClient({"asn-neighbours": FakeResp(429)})
    assert run(asn_intel.fetch_routing(client, db, 13335)) == {"available": False}


# ---------- endpoint-level resilience ----------

def _app_client():
    app = FastAPI()
    app.state.limiter = ip_intel.limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(ip_intel.router)
    return TestClient(app)


def test_lookup_endpoint_200_when_asn_intel_raises(monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("asn intel down")

    async def none_fetch(*a, **k):
        return None

    async def empty_ptr(ip):
        return []

    async def repsrc(ip, client):
        return {}

    monkeypatch.setattr(ip_intel, "fetch_shodan_internetdb", none_fetch)
    monkeypatch.setattr(ip_intel, "fetch_greynoise", none_fetch)
    monkeypatch.setattr(ip_intel, "fetch_ripestat", none_fetch)
    monkeypatch.setattr(ip_intel, "fetch_urlhaus_host", none_fetch)
    monkeypatch.setattr(ip_intel, "fetch_reverse_dns", empty_ptr)
    monkeypatch.setattr(ip_intel.reputation, "fetch_sources", repsrc)
    monkeypatch.setattr(ip_intel.asn_intel, "fetch", boom)

    r = _app_client().get("/api/ip/lookup/8.8.8.8")
    assert r.status_code == 200                              # asn_intel exploding must not 500
    assert r.json()["asn_intel"] == {"available": False}


def test_routing_endpoint_invalid_asn_400():
    r = _app_client().get("/api/ip/asn/-1/routing")
    assert r.status_code == 400


def test_routing_endpoint_delegates_to_fetch_routing(monkeypatch):
    async def fake_routing(client, db, asn):
        assert asn == 13335
        return {"available": True, "upstream_side": {"total": 0, "shown": []},
                "downstream_side": {"total": 0, "shown": []}, "uncertain_count": 0, "caveat": "x"}

    monkeypatch.setattr(ip_intel.asn_intel, "fetch_routing", fake_routing)
    r = _app_client().get("/api/ip/asn/13335/routing")
    assert r.status_code == 200
    assert r.json()["available"] is True
