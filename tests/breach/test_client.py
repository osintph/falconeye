"""
HIBP client: retry/backoff on 429 honoring Retry-After, 404 -> None (not an
error), non-2xx -> HibpError, and response shaping (including stripping the
HTML HIBP's Description field may contain).
"""
import asyncio

import pytest

from app.breach import client


def _fake_safe_fetch(responses):
    """Return an async safe_fetch replacement that yields *responses* in order
    (repeating the last one if called more times than provided)."""
    calls = {"n": 0, "headers_seen": []}

    async def _fake(url, method="GET", headers=None, timeout=15.0, **kw):
        calls["headers_seen"].append(headers or {})
        idx = min(calls["n"], len(responses) - 1)
        calls["n"] += 1
        return responses[idx]

    return _fake, calls


def test_get_returns_parsed_json_on_200(monkeypatch):
    fake, calls = _fake_safe_fetch([{"status": 200, "headers": {}, "body": '{"x": 1}'}])
    monkeypatch.setattr(client, "safe_fetch", fake)
    monkeypatch.setattr(client.asyncio, "sleep", _instant_sleep)
    result = asyncio.run(client._get("/whatever"))
    assert result == {"x": 1}
    assert calls["n"] == 1


def test_get_returns_none_on_404(monkeypatch):
    fake, _ = _fake_safe_fetch([{"status": 404, "headers": {}, "body": ""}])
    monkeypatch.setattr(client, "safe_fetch", fake)
    assert asyncio.run(client._get("/whatever")) is None


async def _instant_sleep(_seconds):
    return None


def test_get_retries_on_429_then_succeeds(monkeypatch):
    fake, calls = _fake_safe_fetch([
        {"status": 429, "headers": {"Retry-After": "1"}, "body": ""},
        {"status": 200, "headers": {}, "body": '{"ok": true}'},
    ])
    monkeypatch.setattr(client, "safe_fetch", fake)
    monkeypatch.setattr(client.asyncio, "sleep", _instant_sleep)
    result = asyncio.run(client._get("/whatever"))
    assert result == {"ok": True}
    assert calls["n"] == 2


def test_get_gives_up_after_max_retries_on_repeated_429(monkeypatch):
    fake, calls = _fake_safe_fetch([{"status": 429, "headers": {}, "body": ""}])
    monkeypatch.setattr(client, "safe_fetch", fake)
    monkeypatch.setattr(client.asyncio, "sleep", _instant_sleep)
    with pytest.raises(client.HibpError):
        asyncio.run(client._get("/whatever"))
    assert calls["n"] == client._MAX_RETRIES + 1


def test_get_raises_on_unexpected_status(monkeypatch):
    fake, _ = _fake_safe_fetch([{"status": 500, "headers": {}, "body": ""}])
    monkeypatch.setattr(client, "safe_fetch", fake)
    with pytest.raises(client.HibpError):
        asyncio.run(client._get("/whatever"))


def test_paid_endpoint_sends_api_key_header(monkeypatch):
    fake, calls = _fake_safe_fetch([{"status": 200, "headers": {}, "body": "[]"}])
    monkeypatch.setattr(client, "safe_fetch", fake)
    monkeypatch.setattr(client, "HIBP_API_KEY", "test-key-123")
    asyncio.run(client.fetch_breached_account("victim@example.com"))
    assert calls["headers_seen"][0].get("hibp-api-key") == "test-key-123"


def test_free_endpoint_omits_api_key_header(monkeypatch):
    fake, calls = _fake_safe_fetch([{"status": 200, "headers": {}, "body": "[]"}])
    monkeypatch.setattr(client, "safe_fetch", fake)
    monkeypatch.setattr(client, "HIBP_API_KEY", "test-key-123")
    asyncio.run(client.fetch_all_breaches())
    assert "hibp-api-key" not in calls["headers_seen"][0]


def test_shape_breach_maps_fields_and_strips_html_description():
    raw = {
        "Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com",
        "BreachDate": "2013-10-04", "AddedDate": "2013-12-04T00:00Z",
        "PwnCount": 152445165,
        "Description": 'In October 2013, <a href="https://example.com">Adobe</a> lost 152M rows.',
        "DataClasses": ["Email addresses", "Passwords"],
        "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png",
        "IsVerified": True, "IsFabricated": False, "IsSensitive": False,
        "IsRetired": False, "IsSpamList": False,
    }
    shaped = client.shape_breach(raw)
    assert shaped["name"] == "Adobe"
    assert shaped["pwn_count"] == 152445165
    assert "<a" not in shaped["description"]
    assert "Adobe lost 152M rows" in shaped["description"]
    assert shaped["data_classes"] == ["Email addresses", "Passwords"]
    assert shaped["is_verified"] is True


def test_shape_paste_maps_fields():
    raw = {"Source": "Pastebin", "Id": "abc123", "Title": "dump", "Date": "2020-01-01T00:00Z", "EmailCount": 42}
    shaped = client.shape_paste(raw)
    assert shaped == {"source": "Pastebin", "id": "abc123", "title": "dump", "date": "2020-01-01T00:00Z", "email_count": 42}
