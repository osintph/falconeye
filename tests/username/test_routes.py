"""Routes: validation boundary, structured response, rate limiting, scope sizing."""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.username import routes as username_routes
from app.username.parser import select_sites


def _client():
    app = FastAPI()
    app.state.limiter = username_routes.limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(username_routes.router)
    return TestClient(app)


def _stub_sweep(monkeypatch, captured=None):
    async def fake_sweep(sites, username, concurrency=20, deadline_s=55.0):
        if captured is not None:
            captured["n"] = len(sites)
        return [], 0
    monkeypatch.setattr(username_routes.checker, "sweep", fake_sweep)


def test_valid_scan_returns_structured_200(monkeypatch):
    _stub_sweep(monkeypatch)
    r = _client().post("/api/username/scan", json={"username": "torvalds", "scope": "quick", "include_nsfw": False})
    assert r.status_code == 200
    d = r.json()
    for key in ("username", "scope", "checked_count", "hit_count", "dual_source_count", "duration_ms", "categories", "warnings"):
        assert key in d
    assert d["username"] == "torvalds"


def test_invalid_username_rejected(monkeypatch):
    _stub_sweep(monkeypatch)
    c = _client()
    for bad in ["../etc/passwd", "has space", "a" * 41, "", "semi;colon", "sla/sh", "qu?ery"]:
        r = c.post("/api/username/scan", json={"username": bad, "scope": "quick"})
        assert r.status_code == 400, bad


def test_rate_limit_blocks_fourth_in_hour(monkeypatch):
    _stub_sweep(monkeypatch)
    c = _client()
    for i in range(3):
        assert c.post("/api/username/scan", json={"username": f"user{i}"}).status_code == 200
    r = c.post("/api/username/scan", json={"username": "user4"})
    assert r.status_code == 429


def test_quick_scope_is_smaller_than_full():
    assert 0 < len(select_sites("quick", False)) < len(select_sites("full", False))


def test_meta_endpoint():
    r = _client().get("/api/username/meta")
    assert r.status_code == 200
    d = r.json()
    assert d["total_sites"] > 800
    assert 0 < d["quick_sites"] < d["total_sites"]
    assert d["dual_source_sites"] > 0
