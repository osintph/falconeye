"""
Tests for GET /api/prospect/{domain}.
Uses FastAPI TestClient (synchronous). Redis is mocked as an AsyncMock.
"""
import json
import os
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

os.environ.setdefault("SEARCHAPI_KEY", "test-key-do-not-use")
os.environ.setdefault("PROSPECT_ENABLED", "true")
os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import app.prospect.routes as _routes_module  # noqa: E402


def _build_app():
    """Fresh FastAPI app for each test to avoid shared rate-limit state."""
    fapp = FastAPI()
    lim = Limiter(key_func=get_remote_address)
    fapp.state.limiter = lim
    fapp.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    fapp.include_router(_routes_module.router)
    return TestClient(fapp, raise_server_exceptions=False)


_DOSSIER = {
    "domain": "stripe.com",
    "generated_at": "2026-01-01T00:00:00+00:00",
    "sections": {
        "about_domain": {"knowledge_graph": {"title": "Stripe, Inc."}},
        "ads_transparency": None,
    },
    "errors": [],
}


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------

def test_kill_switch_returns_503():
    client = _build_app()
    with patch.object(_routes_module, "PROSPECT_ENABLED", False):
        resp = client.get("/api/prospect/stripe.com")
    assert resp.status_code == 503
    assert "disabled" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------

def test_invalid_domain_returns_400():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)

    client = _build_app()
    with patch.object(_routes_module, "_redis", mock_redis):
        resp = client.get("/api/prospect/not_a_domain!!")
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Cache hit path
# ---------------------------------------------------------------------------

def test_cache_hit_returns_cached_true():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=json.dumps(_DOSSIER))

    client = _build_app()
    with patch.object(_routes_module, "_redis", mock_redis):
        resp = client.get("/api/prospect/stripe.com")

    assert resp.status_code == 200
    data = resp.json()
    assert data["cached"] is True
    assert data["domain"] == "stripe.com"
    mock_redis.get.assert_awaited_once_with("prospect:stripe.com")


def test_cache_miss_calls_service_and_sets_cache():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.setex = AsyncMock()

    async def mock_build(domain):
        return dict(_DOSSIER, domain=domain)

    client = _build_app()
    with patch.object(_routes_module, "_redis", mock_redis), \
         patch("app.prospect.routes.build_dossier", mock_build):
        resp = client.get("/api/prospect/stripe.com")

    assert resp.status_code == 200
    data = resp.json()
    assert data["cached"] is False
    mock_redis.setex.assert_awaited_once()
    args = mock_redis.setex.call_args[0]
    assert args[0] == "prospect:stripe.com"
    assert args[1] == 6 * 3600  # TTL


# ---------------------------------------------------------------------------
# Rate limit
# ---------------------------------------------------------------------------

def test_rate_limit_enforced():
    """21 rapid requests from the same IP must trigger at least one 429."""
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.setex = AsyncMock()

    async def mock_build(domain):
        return dict(_DOSSIER, domain=domain)

    client = _build_app()
    statuses = []
    with patch.object(_routes_module, "_redis", mock_redis), \
         patch("app.prospect.routes.build_dossier", mock_build):
        for _ in range(21):
            resp = client.get("/api/prospect/stripe.com")
            statuses.append(resp.status_code)

    assert 429 in statuses, f"Expected 429 but got statuses: {set(statuses)}"
