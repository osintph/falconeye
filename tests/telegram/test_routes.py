"""Routes: validation boundary, tier-merge/degradation, unresolved-then-tier3 flow, caching."""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.telegram import routes as telegram_routes
from app.telegram import tier1_scrape, tier2_bot, tier3_mtproto


def _client():
    app = FastAPI()
    app.state.limiter = telegram_routes.limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(telegram_routes.router)
    return TestClient(app)


def _ok(state_module, data):
    async def fake(*a, **kw):
        return {"ok": True, "state": state_module.OK, "data": data, "error": None}
    return fake


def _not_ok(state, error="boom"):
    async def fake(*a, **kw):
        return {"ok": False, "state": state, "data": {}, "error": error}
    return fake


def test_invalid_query_rejected():
    r = _client().post("/api/telegram/lookup", json={"query": "no way this is valid !!"})
    assert r.status_code == 400


def test_found_channel_merges_tiers_and_degrades_gracefully(monkeypatch):
    monkeypatch.setattr(tier1_scrape, "run", _ok(tier1_scrape, {
        "entity_type": "channel", "display_name": "Telegram News", "verified": True,
        "description": "Official channel", "photo_url": "https://cdn/x.jpg",
        "member_count": 10_000_000, "has_preview": True, "messages": [],
    }))
    monkeypatch.setattr(tier2_bot, "run", _not_ok(tier2_bot.NO_CREDS, "Bot API token not configured"))
    monkeypatch.setattr(tier3_mtproto, "run", _not_ok(tier3_mtproto.NOT_AUTHENTICATED, "MTProto session not authenticated"))

    r = _client().post("/api/telegram/lookup", json={"query": "@telegram"})
    assert r.status_code == 200
    d = r.json()
    assert d["header"]["entity_type"] == "channel"
    assert d["header"]["display_name"] == {"value": "Telegram News", "source": "scrape"}
    assert d["header"]["member_count"] == {"value": 10_000_000, "source": "scrape"}
    assert d["tiers"]["tier2"]["state"] == tier2_bot.NO_CREDS
    assert d["tiers"]["tier3"]["state"] == tier3_mtproto.NOT_AUTHENTICATED
    assert d["cache_hit"] is False


def test_tier3_overrides_tier1_type_and_verified_when_available(monkeypatch):
    monkeypatch.setattr(tier1_scrape, "run", _ok(tier1_scrape, {
        "entity_type": "channel", "display_name": "Pavel Durov", "verified": True,
        "description": "", "photo_url": None, "member_count": 11_555_170,
        "has_preview": True, "messages": [],
    }))
    monkeypatch.setattr(tier2_bot, "run", _not_ok(tier2_bot.NOT_APPLICABLE))
    monkeypatch.setattr(tier3_mtproto, "run", _ok(tier3_mtproto, {
        "entity_type": "user", "display_name": "Pavel Durov", "verified": True,
        "scam": False, "fake": False, "bio": None, "dc_location": "DC5 (Singapore)",
        "account_era_estimate": "2013-2014",
    }))

    r = _client().post("/api/telegram/lookup", json={"query": "durov"})
    d = r.json()
    assert d["header"]["entity_type"] == "user"  # tier3 authoritative, overrides tier1's channel guess
    assert d["header"]["dc_location"] == {"value": "DC5 (Singapore)", "source": "mtproto"}


def test_unresolved_tier1_then_tier3_not_found_is_clean_404(monkeypatch):
    monkeypatch.setattr(tier1_scrape, "run", _not_ok(tier1_scrape.UNRESOLVED, "No public t.me page"))
    monkeypatch.setattr(tier3_mtproto, "run", _not_ok(tier3_mtproto.NOT_FOUND, "No entity resolves"))

    r = _client().post("/api/telegram/lookup", json={"query": "thisdoesnotexist99999999zz"})
    assert r.status_code == 404
    assert "not found" in r.json()["detail"].lower() or "no telegram entity" in r.json()["detail"].lower()


def test_unresolved_tier1_and_tier3_unavailable_is_404_with_caveat(monkeypatch):
    monkeypatch.setattr(tier1_scrape, "run", _not_ok(tier1_scrape.UNRESOLVED, "No public t.me page"))
    monkeypatch.setattr(tier3_mtproto, "run", _not_ok(tier3_mtproto.NOT_AUTHENTICATED, "MTProto session not authenticated"))

    r = _client().post("/api/telegram/lookup", json={"query": "somehandle"})
    assert r.status_code == 404
    assert "MTProto" in r.json()["detail"]


def test_unresolved_tier1_then_tier3_success_resolves_entity(monkeypatch):
    monkeypatch.setattr(tier1_scrape, "run", _not_ok(tier1_scrape.UNRESOLVED, "No public t.me page"))
    monkeypatch.setattr(tier3_mtproto, "run", _ok(tier3_mtproto, {
        "entity_type": "user", "display_name": "Hidden User", "verified": False,
        "scam": False, "fake": False, "bio": "private bio",
    }))
    monkeypatch.setattr(tier2_bot, "run", _not_ok(tier2_bot.NOT_APPLICABLE))

    r = _client().post("/api/telegram/lookup", json={"query": "hiddenuser"})
    assert r.status_code == 200
    d = r.json()
    assert d["header"]["entity_type"] == "user"
    assert d["header"]["display_name"] == {"value": "Hidden User", "source": "mtproto"}


def test_second_lookup_is_cached(monkeypatch):
    calls = {"n": 0}

    async def fake_tier1(*a, **kw):
        calls["n"] += 1
        return {"ok": True, "state": tier1_scrape.OK, "data": {
            "entity_type": "user", "display_name": "X", "verified": False,
            "description": "", "photo_url": None, "member_count": None,
            "has_preview": False, "messages": [],
        }, "error": None}

    monkeypatch.setattr(tier1_scrape, "run", fake_tier1)
    monkeypatch.setattr(tier2_bot, "run", _not_ok(tier2_bot.NOT_APPLICABLE))
    monkeypatch.setattr(tier3_mtproto, "run", _not_ok(tier3_mtproto.NO_CREDS))

    c = _client()
    r1 = c.post("/api/telegram/lookup", json={"query": "cacheme"})
    r2 = c.post("/api/telegram/lookup", json={"query": "cacheme"})
    assert r1.json()["cache_hit"] is False
    assert r2.json()["cache_hit"] is True
    assert calls["n"] == 1
