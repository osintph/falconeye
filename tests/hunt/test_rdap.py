"""Hunt RDAP client: query each TLD's own RDAP server (IANA bootstrap), cap per
server, retry 429 with backoff, cache 24h, and fall back to whois. The v3.38.11
run left 17 of 25 campaign members with an "unknown" registrar because the single
aggregator throttled the burst; these tests pin the completeness behaviour."""
import asyncio

import pytest

from app.asm import store
from app.hunt import rdap
from app.routers import domain_intel


class FakeResp:
    def __init__(self, status, payload=None, headers=None):
        self.status_code = status
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self):
        return self._payload


def _doc(registrar, created, abuse=None):
    ent = {"roles": ["registrar"], "vcardArray": [None, [["fn", {}, "text", registrar]]]}
    if abuse:
        ent["entities"] = [{"roles": ["abuse"],
                            "vcardArray": [None, [["email", {}, "text", abuse]]]}]
    return {"objectClassName": "domain", "entities": [ent],
            "events": [{"eventAction": "registration", "eventDate": created}]}


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    async def _nosleep(*a, **k):
        return None
    monkeypatch.setattr(rdap.asyncio, "sleep", _nosleep)
    conn = store._connect()
    conn.execute("DELETE FROM hunt_rdap_cache")
    conn.commit()
    conn.close()
    rdap._bootstrap_mem.update(map=None, at=0.0)
    yield


def test_queries_the_tlds_own_rdap_server_not_the_aggregator(monkeypatch):
    async def boot(client):
        return {"com": ["https://rdap.verisign.com/com/v1/"]}
    monkeypatch.setattr(rdap, "_load_bootstrap", boot)
    calls = []

    class C:
        async def get(self, url, **k):
            calls.append(url)
            if "rdap.verisign.com" in url:
                return FakeResp(200, _doc("NameSilo, LLC", "2026-09-01", "abuse@namesilo.com"))
            return FakeResp(404)

    parsed = asyncio.run(rdap.lookup(C(), "aaa-direct.com"))
    assert parsed["registrar"]["name"] == "NameSilo, LLC"
    assert parsed["abuse_contact"]["email"] == "abuse@namesilo.com"
    assert any("rdap.verisign.com" in u for u in calls)
    assert not any("rdap.org" in u for u in calls)  # aggregator never touched


def test_retries_429_with_backoff_then_succeeds(monkeypatch):
    async def boot(client):
        return {"com": ["https://rdap.verisign.com/com/v1/"]}
    monkeypatch.setattr(rdap, "_load_bootstrap", boot)
    state = {"n": 0}

    class C:
        async def get(self, url, **k):
            state["n"] += 1
            if state["n"] == 1:
                return FakeResp(429, headers={"Retry-After": "1"})
            return FakeResp(200, _doc("NameMart Pte. Ltd.", "2026-09-05"))

    parsed = asyncio.run(rdap.lookup(C(), "bbb-retry.com"))
    assert parsed["registrar"]["name"] == "NameMart Pte. Ltd."
    assert state["n"] >= 2  # it retried rather than giving up


def test_whois_fallback_when_rdap_is_throttled(monkeypatch):
    # TLD absent from the bootstrap, so only the aggregator is tried, and it
    # throttles every time: system whois provides the registrar (no "unknown").
    async def boot(client):
        return {}
    monkeypatch.setattr(rdap, "_load_bootstrap", boot)

    class C:
        async def get(self, url, **k):
            return FakeResp(429)

    async def fake_whois(domain):
        return "Domain Name: ccc.help\nRegistrar: NameMart Pte. Ltd.\nCreation Date: 2026-08-14T00:00:00Z\n"
    monkeypatch.setattr(domain_intel, "fetch_whois", fake_whois)
    parsed = asyncio.run(rdap.lookup(C(), "ccc.help"))
    assert parsed["registrar"]["name"] == "NameMart Pte. Ltd."
    assert parsed["events"]["registration"] == "2026-08-14"


def test_answer_is_cached_and_reused(monkeypatch):
    async def boot(client):
        return {"com": ["https://rdap.verisign.com/com/v1/"]}
    monkeypatch.setattr(rdap, "_load_bootstrap", boot)
    calls = {"n": 0}

    class C:
        async def get(self, url, **k):
            calls["n"] += 1
            return FakeResp(200, _doc("NameSilo, LLC", "2026-09-01"))

    d = "ddd-cache.com"
    asyncio.run(rdap.lookup(C(), d))
    after_first = calls["n"]
    again = asyncio.run(rdap.lookup(C(), d))
    assert calls["n"] == after_first  # served from the 24h cache, no new call
    assert again["registrar"]["name"] == "NameSilo, LLC"


def test_unknown_only_when_registry_and_whois_publish_none(monkeypatch):
    # Registry answers 200 but with no registrar entity, and whois has nothing:
    # the registrar is genuinely unavailable, so it is None (shown as "unknown"),
    # never fabricated.
    async def boot(client):
        return {"com": ["https://rdap.verisign.com/com/v1/"]}
    monkeypatch.setattr(rdap, "_load_bootstrap", boot)

    class C:
        async def get(self, url, **k):
            return FakeResp(200, {"objectClassName": "domain", "entities": [], "events": []})

    async def no_whois(domain):
        return None
    monkeypatch.setattr(domain_intel, "fetch_whois", no_whois)
    parsed = asyncio.run(rdap.lookup(C(), "eee-none.com"))
    assert parsed is None or (parsed.get("registrar") in (None, {}))
