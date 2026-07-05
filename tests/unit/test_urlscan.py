"""
Unit tests for app/utils/urlscan.py

All tests mock safe_fetch so no real HTTP requests are made.
"""

import asyncio
import json
from unittest.mock import AsyncMock, patch

from app.utils.urlscan import check_urlscan


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resp(status: int, body: dict) -> dict:
    return {"status": status, "headers": {}, "body": json.dumps(body), "url_final": ""}


_MALICIOUS_BODY = {
    "results": [
        {
            "page": {"url": "http://gobpi.cc/cancel/abc"},
            "task": {
                "time": "2026-07-01T10:00:00Z",
                "screenshotURL": "https://urlscan.io/screenshots/abc.png",
            },
            "verdicts": {
                "overall": {
                    "verdict": "malicious",
                    "malicious": True,
                    "tags": ["phishing", "banking"],
                }
            },
        }
    ]
}

_BENIGN_BODY = {
    "results": [
        {
            "page": {"url": "https://example.com/"},
            "task": {
                "time": "2026-06-01T08:00:00Z",
                "screenshotURL": "https://urlscan.io/screenshots/xyz.png",
            },
            "verdicts": {
                "overall": {
                    "verdict": "benign",
                    "malicious": False,
                    "tags": [],
                }
            },
        }
    ]
}

_EMPTY_BODY = {"results": []}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_returns_malicious_verdict():
    async def run():
        with patch("app.utils.urlscan.safe_fetch", new=AsyncMock(return_value=_resp(200, _MALICIOUS_BODY))):
            result = await check_urlscan("http://gobpi.cc/cancel/abc")
        assert result["found"] is True
        assert result["malicious"] is True
        assert result["verdict"] == "malicious"
        assert "phishing" in result["tags"]
        assert result["screenshot_url"] == "https://urlscan.io/screenshots/abc.png"
        assert result["submitted_at"] == "2026-07-01T10:00:00Z"
    asyncio.run(run())


def test_returns_benign_verdict():
    async def run():
        with patch("app.utils.urlscan.safe_fetch", new=AsyncMock(return_value=_resp(200, _BENIGN_BODY))):
            result = await check_urlscan("https://example.com/page")
        assert result["found"] is True
        assert result["malicious"] is False
        assert result["verdict"] == "benign"
    asyncio.run(run())


def test_empty_results_returns_found_false():
    async def run():
        with patch("app.utils.urlscan.safe_fetch", new=AsyncMock(return_value=_resp(200, _EMPTY_BODY))):
            result = await check_urlscan("https://notinurlscan.example.com/")
        assert result["found"] is False
        assert result["verdict"] == ""
        assert result["malicious"] is False
    asyncio.run(run())


def test_rate_limit_429_returns_found_false():
    async def run():
        with patch("app.utils.urlscan.safe_fetch", new=AsyncMock(return_value=_resp(429, {}))):
            result = await check_urlscan("http://gobpi.cc/")
        assert result["found"] is False
        assert result["verdict"] == ""
    asyncio.run(run())


def test_non_200_status_returns_found_false():
    async def run():
        with patch("app.utils.urlscan.safe_fetch", new=AsyncMock(return_value=_resp(503, {}))):
            result = await check_urlscan("http://gobpi.cc/")
        assert result["found"] is False
    asyncio.run(run())


def test_safe_fetch_exception_returns_found_false():
    from app.utils.safe_fetch import SafeFetchError

    async def run():
        with patch("app.utils.urlscan.safe_fetch", new=AsyncMock(side_effect=SafeFetchError("blocked"))):
            result = await check_urlscan("http://192.168.1.1/")
        assert result["found"] is False
    asyncio.run(run())


def test_generic_exception_returns_found_false():
    async def run():
        with patch("app.utils.urlscan.safe_fetch", new=AsyncMock(side_effect=Exception("network error"))):
            result = await check_urlscan("http://gobpi.cc/")
        assert result["found"] is False
    asyncio.run(run())


def test_malformed_json_body_returns_found_false():
    async def run():
        bad_resp = {"status": 200, "headers": {}, "body": "not-json", "url_final": ""}
        with patch("app.utils.urlscan.safe_fetch", new=AsyncMock(return_value=bad_resp)):
            result = await check_urlscan("http://gobpi.cc/")
        assert result["found"] is False
    asyncio.run(run())


def test_empty_url_returns_found_false():
    async def run():
        result = await check_urlscan("")
        assert result["found"] is False
    asyncio.run(run())


def test_result_has_all_expected_keys():
    async def run():
        with patch("app.utils.urlscan.safe_fetch", new=AsyncMock(return_value=_resp(200, _MALICIOUS_BODY))):
            result = await check_urlscan("http://gobpi.cc/")
        for key in ("found", "verdict", "malicious", "submitted_at", "screenshot_url", "live_url", "tags"):
            assert key in result, f"Missing key: {key}"
    asyncio.run(run())


def test_uses_api_key_header_when_configured(monkeypatch):
    """When URLSCAN_API_KEY is set, the API-Key header must be sent."""
    monkeypatch.setattr("app.utils.urlscan.URLSCAN_API_KEY", "test-key-abc")
    captured_headers = {}

    async def fake_fetch(url, headers=None, timeout=10.0):
        captured_headers.update(headers or {})
        return _resp(200, _EMPTY_BODY)

    async def run():
        with patch("app.utils.urlscan.safe_fetch", new=AsyncMock(side_effect=fake_fetch)):
            await check_urlscan("http://gobpi.cc/")
        assert captured_headers.get("API-Key") == "test-key-abc"
    asyncio.run(run())


def test_no_api_key_header_when_key_empty(monkeypatch):
    """Without URLSCAN_API_KEY, no API-Key header should appear."""
    monkeypatch.setattr("app.utils.urlscan.URLSCAN_API_KEY", "")
    captured_headers = {}

    async def fake_fetch(url, headers=None, timeout=10.0):
        captured_headers.update(headers or {})
        return _resp(200, _EMPTY_BODY)

    async def run():
        with patch("app.utils.urlscan.safe_fetch", new=AsyncMock(side_effect=fake_fetch)):
            await check_urlscan("http://gobpi.cc/")
        assert "API-Key" not in captured_headers
    asyncio.run(run())
