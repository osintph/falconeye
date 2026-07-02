"""
Tests for SearchAPIClient.
Uses asyncio.run() so no pytest-asyncio dependency is required.
httpx.AsyncClient is patched at the module level to inject mock responses.
"""
import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

os.environ.setdefault("SEARCHAPI_KEY", "test-key-do-not-use")

from app.prospect.client import SearchAPIClient  # noqa: E402


class _MockResponse:
    """Thin stand-in for httpx.Response used in tests."""

    def __init__(self, status_code: int, body=None):
        self.status_code = status_code
        self._body = body or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=httpx.Request("GET", "https://example.com"),
                response=httpx.Response(self.status_code),
            )


def _make_mock_client(responses: list[_MockResponse]):
    """Return a mock async context manager whose .get() yields responses in order."""
    mock_get = AsyncMock(side_effect=responses)
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=MagicMock(get=mock_get))
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx, mock_get


# ---------------------------------------------------------------------------
# Auth header
# ---------------------------------------------------------------------------

def test_correct_auth_header():
    """Authorization: Bearer header must be sent on every request."""
    captured = {}

    async def _run():
        async def mock_get(url, *, headers, params, **kwargs):
            captured["headers"] = headers
            return _MockResponse(200, {"ok": True})

        with patch("httpx.AsyncClient") as MockCls:
            ctx = MagicMock()
            inner = MagicMock()
            inner.get = mock_get
            ctx.__aenter__ = AsyncMock(return_value=inner)
            ctx.__aexit__ = AsyncMock(return_value=False)
            MockCls.return_value = ctx

            client = SearchAPIClient()
            await client.search("test_engine", {"domain": "example.com"})

    asyncio.run(_run())
    assert captured["headers"].get("Authorization") == "Bearer test-key-do-not-use"


# ---------------------------------------------------------------------------
# 5xx retry
# ---------------------------------------------------------------------------

def test_retry_on_5xx():
    """5xx responses are retried up to three times; success on third attempt returns data."""
    call_count = [0]
    sleep_calls = []

    async def _run():
        responses = [
            _MockResponse(503),
            _MockResponse(502),
            _MockResponse(200, {"result": "ok"}),
        ]

        async def mock_get(url, **kwargs):
            r = responses[call_count[0]]
            call_count[0] += 1
            return r

        async def mock_sleep(seconds):
            sleep_calls.append(seconds)

        with patch("httpx.AsyncClient") as MockCls, patch("asyncio.sleep", mock_sleep):
            ctx = MagicMock()
            inner = MagicMock()
            inner.get = mock_get
            ctx.__aenter__ = AsyncMock(return_value=inner)
            ctx.__aexit__ = AsyncMock(return_value=False)
            MockCls.return_value = ctx

            client = SearchAPIClient()
            result = await client.search("engine", {"domain": "x.com"})

        return result

    result = asyncio.run(_run())
    assert result == {"result": "ok"}
    assert call_count[0] == 3
    assert len(sleep_calls) == 2  # slept before retry 2 and 3


def test_raises_after_three_5xx_retries():
    """Exhausting three 5xx retries must propagate an HTTPStatusError."""
    call_count = [0]

    async def _run():
        async def mock_get(url, **kwargs):
            call_count[0] += 1
            resp = _MockResponse(500)
            return resp

        async def mock_sleep(_):
            pass

        with patch("httpx.AsyncClient") as MockCls, patch("asyncio.sleep", mock_sleep):
            ctx = MagicMock()
            inner = MagicMock()
            inner.get = mock_get
            ctx.__aenter__ = AsyncMock(return_value=inner)
            ctx.__aexit__ = AsyncMock(return_value=False)
            MockCls.return_value = ctx

            client = SearchAPIClient()
            await client.search("engine", {"domain": "x.com"})

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(_run())
    # 1 initial + 3 retries = 4 calls
    assert call_count[0] == 4


# ---------------------------------------------------------------------------
# 4xx raise immediately
# ---------------------------------------------------------------------------

def test_immediate_raise_on_400():
    """4xx (other than 429) must raise immediately without retry."""
    call_count = [0]

    async def _run():
        async def mock_get(url, **kwargs):
            call_count[0] += 1
            return _MockResponse(400)

        with patch("httpx.AsyncClient") as MockCls:
            ctx = MagicMock()
            inner = MagicMock()
            inner.get = mock_get
            ctx.__aenter__ = AsyncMock(return_value=inner)
            ctx.__aexit__ = AsyncMock(return_value=False)
            MockCls.return_value = ctx

            client = SearchAPIClient()
            await client.search("engine", {"domain": "x.com"})

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(_run())
    assert call_count[0] == 1


# ---------------------------------------------------------------------------
# 429 exponential backoff
# ---------------------------------------------------------------------------

def test_exponential_backoff_on_429():
    """429 responses must be retried with exponential backoff; success on third attempt."""
    call_count = [0]
    sleep_calls = []

    async def _run():
        responses = [
            _MockResponse(429),
            _MockResponse(429),
            _MockResponse(200, {"data": "good"}),
        ]

        async def mock_get(url, **kwargs):
            r = responses[call_count[0]]
            call_count[0] += 1
            return r

        async def mock_sleep(seconds):
            sleep_calls.append(seconds)

        with patch("httpx.AsyncClient") as MockCls, patch("asyncio.sleep", mock_sleep):
            ctx = MagicMock()
            inner = MagicMock()
            inner.get = mock_get
            ctx.__aenter__ = AsyncMock(return_value=inner)
            ctx.__aexit__ = AsyncMock(return_value=False)
            MockCls.return_value = ctx

            client = SearchAPIClient()
            return await client.search("engine", {"domain": "x.com"})

    result = asyncio.run(_run())
    assert result == {"data": "good"}
    assert call_count[0] == 3
    # Sleep values must be non-decreasing (exponential)
    assert sleep_calls[1] >= sleep_calls[0]
