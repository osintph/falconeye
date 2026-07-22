"""
Routes: input validation, cache-before-rate-limit-before-HIBP ordering, the
200+rate_limited contract (not 429), and that a cache hit never re-fires the
HIBP client.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.breach import client, routes as breach_routes


def _client():
    app = FastAPI()
    app.state.limiter = breach_routes.limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(breach_routes.router)
    return TestClient(app)


def _mock_hibp(monkeypatch, breaches=None, pastes=None, meta_by_name=None):
    calls = {"breached": 0, "paste": 0, "meta": 0}

    async def fake_breached(email):
        calls["breached"] += 1
        return breaches or []

    async def fake_paste(email):
        calls["paste"] += 1
        return pastes or []

    async def fake_meta(name):
        calls["meta"] += 1
        return (meta_by_name or {}).get(name)

    monkeypatch.setattr(client, "fetch_breached_account", fake_breached)
    monkeypatch.setattr(client, "fetch_paste_account", fake_paste)
    monkeypatch.setattr(client, "fetch_breach_metadata", fake_meta)
    return calls


ADOBE_RAW = {
    "Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com",
    "BreachDate": "2013-10-04", "AddedDate": "2013-12-04T00:00Z", "PwnCount": 152445165,
    "Description": "Adobe breach.", "DataClasses": ["Email addresses", "Passwords"],
    "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png",
    "IsVerified": True, "IsFabricated": False, "IsSensitive": False,
    "IsRetired": False, "IsSpamList": False,
}


# ---------- validation ----------

def test_malformed_email_returns_400():
    r = _client().post("/api/breach/email", json={"email": "not-an-email"})
    assert r.status_code == 400
    assert "detail" in r.json()


def test_malformed_domain_returns_400():
    r = _client().post("/api/breach/domain", json={"domain": "-not a domain-"})
    assert r.status_code == 400
    assert "detail" in r.json()


# ---------- email checks ----------

def test_email_check_returns_enriched_breach(monkeypatch):
    calls = _mock_hibp(monkeypatch, breaches=[{"Name": "Adobe"}], meta_by_name={"Adobe": ADOBE_RAW})
    r = _client().post("/api/breach/email", json={"email": "victim@example.com"})
    assert r.status_code == 200
    d = r.json()
    assert d["cache_hit"] is False
    assert d["rate_limited"] is False
    assert d["breach_count"] == 1
    assert d["breaches"][0]["title"] == "Adobe"
    assert d["breaches"][0]["pwn_count"] == 152445165
    assert d["password_exposed_count"] == 1
    assert calls["meta"] == 1


def test_second_email_lookup_is_cached_and_skips_hibp(monkeypatch):
    calls = _mock_hibp(monkeypatch, breaches=[{"Name": "Adobe"}], meta_by_name={"Adobe": ADOBE_RAW})
    c = _client()
    r1 = c.post("/api/breach/email", json={"email": "victim@example.com"})
    r2 = c.post("/api/breach/email", json={"email": "victim@example.com"})
    assert r1.json()["cache_hit"] is False
    assert r2.json()["cache_hit"] is True
    assert r2.json()["breach_count"] == r1.json()["breach_count"]
    assert calls["breached"] == 1  # second call never touched HIBP
    assert calls["paste"] == 1


def test_email_rate_limit_returns_200_with_flag_not_429(monkeypatch):
    _mock_hibp(monkeypatch)
    c = _client()
    for i in range(breach_routes.EMAIL_IP_PER_HOUR):
        r = c.post("/api/breach/email", json={"email": f"victim{i}@example.com"})
        assert r.json().get("rate_limited") is not True

    r_over = c.post("/api/breach/email", json={"email": "one-too-many@example.com"})
    assert r_over.status_code == 200
    assert r_over.json()["rate_limited"] is True


# ---------- domain checks ----------

def test_domain_check_returns_enriched_breach(monkeypatch):
    async def fake_by_domain(domain):
        return [{"Name": "Adobe"}]

    async def fake_meta(name):
        return ADOBE_RAW

    monkeypatch.setattr(client, "fetch_breaches_by_domain", fake_by_domain)
    monkeypatch.setattr(client, "fetch_breach_metadata", fake_meta)
    monkeypatch.setattr(breach_routes, "_resolve_hosting_ip", lambda domain: _async_none())

    r = _client().post("/api/breach/domain", json={"domain": "example.com"})
    assert r.status_code == 200
    d = r.json()
    assert d["domain"] == "example.com"
    assert d["breach_count"] == 1
    assert d["breaches"][0]["name"] == "Adobe"


async def _async_none():
    return None


def test_domain_rate_limit_returns_200_with_flag_not_429(monkeypatch):
    async def fake_by_domain(domain):
        return []

    monkeypatch.setattr(client, "fetch_breaches_by_domain", fake_by_domain)
    monkeypatch.setattr(breach_routes, "_resolve_hosting_ip", lambda domain: _async_none())

    c = _client()
    for i in range(breach_routes.DOMAIN_IP_PER_HOUR):
        r = c.post("/api/breach/domain", json={"domain": f"example{i}.com"})
        assert r.json().get("rate_limited") is not True

    r_over = c.post("/api/breach/domain", json={"domain": "onetoomany.com"})
    assert r_over.status_code == 200
    assert r_over.json()["rate_limited"] is True


# ---------- passive sections ----------

def test_recent_breaches(monkeypatch):
    async def fake_all():
        return [ADOBE_RAW]

    async def fake_latest():
        return None

    monkeypatch.setattr(client, "fetch_all_breaches", fake_all)
    monkeypatch.setattr(client, "fetch_latest_breach", fake_latest)

    r = _client().get("/api/breach/recent")
    assert r.status_code == 200
    d = r.json()
    assert len(d["breaches"]) == 1
    assert d["breaches"][0]["name"] == "Adobe"


def test_all_breaches_caches(monkeypatch):
    calls = {"n": 0}

    async def fake_all():
        calls["n"] += 1
        return [ADOBE_RAW]

    monkeypatch.setattr(client, "fetch_all_breaches", fake_all)

    c = _client()
    r1 = c.get("/api/breach/all")
    r2 = c.get("/api/breach/all")
    assert r1.json()["cache_hit"] is False
    assert r2.json()["cache_hit"] is True
    assert calls["n"] == 1


def test_dataclasses(monkeypatch):
    async def fake_dc():
        return ["Email addresses", "Passwords"]

    monkeypatch.setattr(client, "fetch_dataclasses", fake_dc)
    r = _client().get("/api/breach/dataclasses")
    assert r.status_code == 200
    assert r.json()["data_classes"] == ["Email addresses", "Passwords"]
