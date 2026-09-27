"""The IP tab must not serve a six hour old failure.

/api/ip/lookup writes one blob per IP and reads it back for six hours. A source
that errored, timed out, hit a quota or had no key was stored in that blob like
any other, so the next nine hundred lookups of that IP were told the same source
was unavailable, and the verdict stayed INCOMPLETE, without anything being asked
again.

What must happen instead: the verdict row is still cached, but each ok=false
source is re-attempted on the next lookup. A sixty second negative window keeps
a hammered tab from hammering a down upstream, and Refresh ignores the window
entirely.

The counterpart matters as much: a source that answered must NOT be re-queried
by the retry. AbuseIPDB is 1,000 checks a day and VirusTotal 500, so a partial
retry that re-queried everything would spend the quotas the cache exists to
protect.
"""
import json
import sqlite3

import pytest

from app.ip_sources import reputation
from app.routers import ip_intel
from app.utils import cache

from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

IP = "62.60.130.193"


def _client():
    app = FastAPI()
    app.state.limiter = ip_intel.limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(ip_intel.router)
    return TestClient(app)


def _src(name, ok, state, error=None, **data):
    return {"source": name, "ok": ok, "state": state, "data": data,
            "error": error, "country": data.pop("_country", None)}


def _ok(name, **data):
    return _src(name, True, "ok", **data)


@pytest.fixture
def core(monkeypatch):
    """Stub every non-reputation fetcher, counting the calls."""
    calls = {"shodan": 0, "greynoise": 0, "ripestat": 0, "urlhaus": 0}

    async def shodan(c, ip):
        calls["shodan"] += 1
        return {"ports": [], "vulns": []}

    async def gn(c, ip):
        calls["greynoise"] += 1
        return {"classification": "benign"}

    async def ripe(c, ip):
        calls["ripestat"] += 1
        return {"asn": 64500, "asn_holder": "Example", "country": "PH"}

    async def uh(c, ip):
        calls["urlhaus"] += 1
        return {"query_status": "no_results"}   # a real miss, not a failure

    async def ptr(ip):
        return []

    async def asn(client, db, ip):
        return {"available": False}

    monkeypatch.setattr(ip_intel, "fetch_shodan_internetdb", shodan)
    monkeypatch.setattr(ip_intel, "fetch_greynoise", gn)
    monkeypatch.setattr(ip_intel, "fetch_ripestat", ripe)
    monkeypatch.setattr(ip_intel, "fetch_urlhaus_host", uh)
    monkeypatch.setattr(ip_intel, "fetch_reverse_dns", ptr)
    monkeypatch.setattr(ip_intel.asn_intel, "fetch", asn)
    return calls


def _reputation_stub(monkeypatch, failing, *, fixed_after=True):
    """Reputation fetcher that fails `failing` on the first call only.

    Records which source names each call was asked for, which is how the tests
    below assert that a retry does not re-query a source that answered.
    """
    asked = []

    async def fetch_sources(ip, client, only=None):
        names = list(only) if only else list(reputation.ALL_NAMES)
        asked.append(sorted(names))
        out = {}
        first_round = len(asked) == 1
        for name in names:
            if name in failing and (first_round or not fixed_after):
                out[name] = _src(name, False, "error", "ConnectTimeout")
            elif name == "censys":
                out[name] = _ok(name, ports=[])
            elif name == "threatfox":
                out[name] = _src(name, True, "not_found", matched=False)
            else:
                out[name] = _ok(name, confidence=0, total_reports=0, malicious=0,
                                pulse_count=0)
        return out

    monkeypatch.setattr(reputation, "fetch_sources", fetch_sources)
    monkeypatch.setattr(ip_intel.reputation, "fetch_sources", fetch_sources)
    return asked


def _row(ip=IP):
    import os
    conn = sqlite3.connect(os.getenv("FALCONEYE_DB", "/tmp/falconeye_test.db"))
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT response_json, fetched_at FROM ip_intel_cache WHERE ip = ?", (ip,)
    ).fetchone()
    conn.close()
    return (json.loads(row["response_json"]), row["fetched_at"]) if row else (None, None)


# ---------- the failure is stamped, not stored as an answer ----------

def test_a_failed_source_is_stored_with_a_stamp(core, monkeypatch):
    _reputation_stub(monkeypatch, {"otx"})
    body = _client().get(f"/api/ip/lookup/{IP}").json()
    assert body["reputation"]["verdict"]["verdict"] == reputation.INCOMPLETE

    stored, _ = _row()
    failures = cache.take_failures(stored)
    assert "otx" in failures, (
        "the failed source went into the six hour row with no stamp, so it "
        "would be served as an answer until the row expired"
    )
    # And the bookkeeping never reaches the caller.
    assert cache.FAILURES_KEY not in body


def test_a_clean_lookup_records_no_failures(core, monkeypatch):
    _reputation_stub(monkeypatch, set())
    body = _client().get(f"/api/ip/lookup/{IP}").json()
    assert body["reputation"]["verdict"]["verdict"] == reputation.CLEAN
    stored, _ = _row()
    assert cache.take_failures(stored) == {}


# ---------- the retry, and only of what failed ----------

def test_the_failed_source_alone_is_re_attempted(core, monkeypatch):
    asked = _reputation_stub(monkeypatch, {"otx"})
    c = _client()
    c.get(f"/api/ip/lookup/{IP}")
    assert asked[0] == sorted(reputation.ALL_NAMES)

    monkeypatch.setattr(cache, "NEGATIVE_TTL_SECONDS", 0)
    body = c.get(f"/api/ip/lookup/{IP}").json()

    assert len(asked) == 2, "the failed source was not re-attempted"
    assert asked[1] == ["otx"], (
        f"the retry asked {asked[1]}; sources that answered must not be "
        "re-queried, their quotas are what the cache protects"
    )
    # The core fetchers answered the first time, so they are not re-run either.
    assert core == {"shodan": 1, "greynoise": 1, "ripestat": 1, "urlhaus": 1}

    # And the verdict is recomputed over the merged result.
    verdict = body["reputation"]["verdict"]
    assert verdict["verdict"] == reputation.CLEAN
    assert verdict["sources_responded"] == 4
    assert body["reputation"]["sources"]["otx"]["ok"] is True


def test_inside_the_negative_window_nothing_is_re_attempted(core, monkeypatch):
    asked = _reputation_stub(monkeypatch, {"otx"})
    c = _client()
    c.get(f"/api/ip/lookup/{IP}")
    body = c.get(f"/api/ip/lookup/{IP}").json()

    assert len(asked) == 1, "a down upstream was re-queried within the window"
    assert body["cache_hit"] is True
    assert body["reputation"]["sources"]["otx"]["state"] == "error"


def test_refresh_re_attempts_failures_inside_the_window(core, monkeypatch):
    asked = _reputation_stub(monkeypatch, {"otx"})
    c = _client()
    c.get(f"/api/ip/lookup/{IP}")
    body = c.get(f"/api/ip/lookup/{IP}?refresh=1").json()

    assert len(asked) == 2
    assert asked[1] == sorted(reputation.ALL_NAMES), "refresh re-queries everything"
    assert body["reputation"]["sources"]["otx"]["ok"] is True


def test_a_source_that_keeps_failing_does_not_extend_the_row(core, monkeypatch):
    """Otherwise a permanently broken source keeps a six hour row alive forever."""
    _reputation_stub(monkeypatch, {"otx"}, fixed_after=False)
    c = _client()
    c.get(f"/api/ip/lookup/{IP}")
    _, first_stamp = _row()

    import os
    conn = sqlite3.connect(os.getenv("FALCONEYE_DB", "/tmp/falconeye_test.db"))
    conn.execute("UPDATE ip_intel_cache SET fetched_at = datetime('now', '-3 hours') WHERE ip = ?", (IP,))
    conn.commit()
    conn.close()
    _, aged = _row()

    monkeypatch.setattr(cache, "NEGATIVE_TTL_SECONDS", 0)
    c.get(f"/api/ip/lookup/{IP}")
    _, after = _row()
    assert after == aged, "the partial retry reset the row's age"
    assert after != first_stamp


def test_the_retry_updates_the_stamp_so_the_window_applies_again(core, monkeypatch):
    """A retry that fails again must restart the window, not retry every request."""
    _reputation_stub(monkeypatch, {"otx"}, fixed_after=False)
    c = _client()
    c.get(f"/api/ip/lookup/{IP}")
    stored, _ = _row()
    first = cache.take_failures(stored)["otx"]

    monkeypatch.setattr(cache, "NEGATIVE_TTL_SECONDS", 0)
    c.get(f"/api/ip/lookup/{IP}")
    stored, _ = _row()
    assert cache.take_failures(stored)["otx"] >= first


# ---------- the same rule for the keyless core fetchers ----------

def test_a_failed_core_fetcher_is_re_attempted_too(monkeypatch):
    """Shodan, GreyNoise, RIPEstat and URLhaus are cached in the same row."""
    _reputation_stub(monkeypatch, set())
    state = {"shodan": 0}

    async def shodan(c, ip):
        state["shodan"] += 1
        return None if state["shodan"] == 1 else {"ports": [443], "vulns": []}

    async def gn(c, ip): return {"classification": "benign"}
    async def ripe(c, ip): return {"asn": 1, "asn_holder": "X", "country": "PH"}
    async def uh(c, ip): return {"query_status": "no_results"}
    async def ptr(ip): return []
    async def asn(client, db, ip): return {"available": False}

    monkeypatch.setattr(ip_intel, "fetch_shodan_internetdb", shodan)
    monkeypatch.setattr(ip_intel, "fetch_greynoise", gn)
    monkeypatch.setattr(ip_intel, "fetch_ripestat", ripe)
    monkeypatch.setattr(ip_intel, "fetch_urlhaus_host", uh)
    monkeypatch.setattr(ip_intel, "fetch_reverse_dns", ptr)
    monkeypatch.setattr(ip_intel.asn_intel, "fetch", asn)

    c = _client()
    first = c.get(f"/api/ip/lookup/{IP}").json()
    assert first["shodan"] is None

    monkeypatch.setattr(cache, "NEGATIVE_TTL_SECONDS", 0)
    second = c.get(f"/api/ip/lookup/{IP}").json()
    assert state["shodan"] == 2, "a failed Shodan lookup stayed failed for six hours"
    assert second["shodan"]["ports"] == [443]
    # The merged port list is recomputed from the retried source.
    assert [p["port"] for p in second["reputation"]["ports"]["ports"]] == [443]


def test_reverse_dns_is_not_treated_as_a_failure(monkeypatch, core):
    """An address with no PTR record is the normal case, not an outage."""
    _reputation_stub(monkeypatch, set())
    calls = []

    async def ptr(ip):
        calls.append(ip)
        return []

    monkeypatch.setattr(ip_intel, "fetch_reverse_dns", ptr)
    c = _client()
    c.get(f"/api/ip/lookup/{IP}")
    monkeypatch.setattr(cache, "NEGATIVE_TTL_SECONDS", 0)
    c.get(f"/api/ip/lookup/{IP}")
    assert len(calls) == 1, "an empty PTR was retried as though it had failed"
