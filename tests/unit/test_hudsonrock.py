"""Hudson Rock source: stripping, kill switch, and failure behaviour.

Added with the source itself in v3.33.0 (GitHub issue #1). The two things that
matter most here are not "does it parse":

1. **Nothing sensitive escapes.** Hudson Rock's published stealer schema carries
   plaintext credentials, session cookies, malware paths and the victim's search
   history. The client allowlists a handful of fields; these tests feed it a
   record containing every dangerous field and assert none of them survive, by
   scanning the serialised output rather than by checking named keys. A denylist
   test would pass while a newly added field leaked.

2. **Every failure looks like "disabled".** A timeout, a 429, a 5xx, an HTML
   error page and a changed schema must all produce exactly what the source
   produces when switched off: None. No partial render, no user-facing error.
"""
import asyncio
import json

import pytest

from app.hudsonrock import client


# A stealer record with every sensitive field the vendor documents.
HOSTILE_STEALER = {
    "_id": "abc123",
    "stealer_family": "RedLine",
    "date_compromised": "2025-03-04T11:22:33.000Z",
    "date_uploaded": "2025-03-09T00:00:00.000Z",
    "stealer": "US[84A9A4763718C8066F757039D966D3C5] [2008-10-31T05_43_39]",
    "ip": "203.0.113.9",
    "computer_name": "VICTIM-LAPTOP",
    "operating_system": "Windows 11 Pro x64",
    "malware_path": "C:\\Users\\victim\\AppData\\Local\\Temp\\loader.exe",
    "antiviruses": ["Windows Defender"],
    "employeeAt": ["victim-corp.example"],
    "clientAt": ["bank.example"],
    "credentials": [
        {"type": "employee", "url": "https://vpn.victim-corp.example/login",
         "domain": "victim-corp.example", "username": "jdoe@victim-corp.example",
         "password": "Summer2025!"},
    ],
    "employee_session_cookies": [{"name": "SSO", "value": "eyJhbGciOi"}],
    "installed_software": ["Chrome 122"],
    "search_data": ["how to remove a virus"],
}

SENSITIVE_MARKERS = [
    "Summer2025!", "jdoe@victim-corp.example", "vpn.victim-corp.example",
    "loader.exe", "AppData", "203.0.113.9", "VICTIM-LAPTOP",
    "Windows 11 Pro x64", "eyJhbGciOi", "Chrome 122",
    "how to remove a virus", "bank.example", "victim-corp.example",
    "Windows Defender", "84A9A4763718C8066F757039D966D3C5",
]


def _serialised(payload) -> str:
    return json.dumps(payload, default=str)


# ---------- stripping ----------

def test_email_sanitizer_drops_every_sensitive_field():
    out = client.sanitize_email({"stealers": [HOSTILE_STEALER],
                                 "total_corporate_services": 2,
                                 "total_user_services": 5})
    blob = _serialised(out)
    for marker in SENSITIVE_MARKERS:
        assert marker not in blob, (
            f"{marker!r} survived sanitize_email. The allowlist in "
            "app/hudsonrock/client.py is the only thing standing between "
            "stealer-log contents and the browser."
        )
    # What it should keep.
    assert out["found"] is True
    assert out["total"] == 1
    assert out["stealer_families"] == {"RedLine": 1}
    assert out["first_compromised"] == "2025-03-04T11:22:33.000Z"


def test_domain_sanitizer_drops_urls_and_password_stats():
    payload = {
        "total": 12, "employees": 3, "users": 9, "third_parties": 1,
        "logo": "https://cdn.brandfetch.io/victim.example/logo",
        "data": {
            "employees_urls": [{"url": "https://sso.victim.example/adfs", "occurrence": 5}],
            "clients_urls": [{"url": "https://portal.victim.example/login", "occurrence": 2}],
            "all_urls": [{"url": "https://vpn.victim.example", "occurrence": 1}],
        },
        "employeePasswords": {"totalPass": 40, "too_weak": {"qty": 9, "perc": 22.5}},
        "userPasswords": {"totalPass": 80, "weak": {"qty": 50, "perc": 62.5}},
        "thirdPartyDomains": [{"domain": "microsoftonline.com", "occurrence": 14}],
        "antiviruses": {"total": 10, "list": [{"name": "Windows Defender [ON]", "count": 4}]},
        "applications": [{"keyword": "adfs"}],
        "stealerFamilies": {"total": 12, "RedLine": 7, "Lumma": 5},
        "last_employee_compromised": "2026-01-02T03:04:05.000Z",
        "is_shopify": True,
    }
    out = client.sanitize_domain(payload)
    blob = _serialised(out)
    for marker in ("sso.victim.example", "portal.victim.example", "vpn.victim.example",
                   "microsoftonline.com", "brandfetch", "totalPass", "too_weak",
                   "Windows Defender", "adfs", "is_shopify"):
        assert marker not in blob, f"{marker!r} survived sanitize_domain"

    assert out["stealer_families"] == {"RedLine": 7, "Lumma": 5}
    assert out["total"] == 12
    assert out["last_employee_compromised"] == "2026-01-02T03:04:05.000Z"


def test_family_names_that_look_like_paths_or_urls_are_dropped():
    """A family name is a short label. Anything else is a shape we do not trust."""
    out = client.sanitize_email({"stealers": [
        {"stealer_family": "C:\\Users\\victim\\stealer.exe", "date_compromised": "2025-01-01T00:00:00Z"},
        {"stealer_family": "https://evil.example/panel", "date_compromised": "2025-01-01T00:00:00Z"},
        {"stealer_family": "RedLine", "date_compromised": "2025-01-01T00:00:00Z"},
    ]})
    assert out["stealer_families"] == {"RedLine": 1}


def test_malformed_dates_are_dropped_not_forwarded():
    out = client.sanitize_email({"stealers": [
        {"stealer_family": "Lumma", "date_compromised": "not a date"},
        {"stealer_family": "Lumma", "date_compromised": {"$date": 12345}},
    ]})
    assert out["first_compromised"] is None and out["last_compromised"] is None


# ---------- kill switch ----------

def test_kill_switch_is_off_by_default():
    """A source with no published rate limit or terms is not on by default."""
    from app import config
    assert config.HUDSONROCK_ENABLED is False


def test_disabled_source_never_calls_upstream(monkeypatch):
    called = []
    monkeypatch.setattr(client, "HUDSONROCK_ENABLED", False)
    monkeypatch.setattr(client, "_fetch", lambda *a, **k: called.append(a))
    assert asyncio.run(client.lookup_domain("example.com", "1.2.3.4")) is None
    assert asyncio.run(client.lookup_email("a@example.com", "1.2.3.4")) is None
    assert called == []


# ---------- failure modes ----------

@pytest.fixture
def enabled(monkeypatch):
    """Source on, cache bypassed, quota available."""
    monkeypatch.setattr(client, "HUDSONROCK_ENABLED", True)
    monkeypatch.setattr(client.cache, "get", lambda *a, **k: None)
    monkeypatch.setattr(client.cache, "set", lambda *a, **k: None)
    monkeypatch.setattr(client, "_quota_ok", lambda ip: True)


def _serve(monkeypatch, *, status=200, body="{}", raises=None):
    async def fake(url, **kw):
        if raises is not None:
            raise raises
        return {"status": status, "body": body}
    monkeypatch.setattr(client, "safe_fetch", fake)


@pytest.mark.parametrize("status", [429, 500, 502, 503, 403, 404])
def test_upstream_error_statuses_look_exactly_like_disabled(enabled, monkeypatch, status):
    _serve(monkeypatch, status=status)
    assert asyncio.run(client.lookup_domain("example.com", "1.2.3.4")) is None
    assert asyncio.run(client.lookup_email("a@example.com", "1.2.3.4")) is None


def test_timeout_looks_exactly_like_disabled(enabled, monkeypatch):
    from app.utils.safe_fetch import SafeFetchError
    _serve(monkeypatch, raises=SafeFetchError("timed out"))
    assert asyncio.run(client.lookup_domain("example.com", "1.2.3.4")) is None


def test_unexpected_exception_looks_exactly_like_disabled(enabled, monkeypatch):
    _serve(monkeypatch, raises=RuntimeError("connection reset"))
    assert asyncio.run(client.lookup_domain("example.com", "1.2.3.4")) is None


def test_html_error_page_looks_exactly_like_disabled(enabled, monkeypatch):
    _serve(monkeypatch, body="<html><body>502 Bad Gateway</body></html>")
    assert asyncio.run(client.lookup_domain("example.com", "1.2.3.4")) is None


def test_schema_drift_degrades_to_nothing(enabled, monkeypatch):
    """The shape changed under us: a list where an object was, nulls throughout.

    Either the call returns None, or it returns an inert result. What it must
    never do is raise, or render half a card.
    """
    for body in ('[]', 'null', '"a string"', '{"stealers": "not-a-list"}',
                 '{"stealerFamilies": ["RedLine"]}', '{"total": {"nested": 1}}',
                 '{"stealers": [{"stealer_family": null}]}'):
        _serve(monkeypatch, body=body)
        for out in (asyncio.run(client.lookup_domain("example.com", "1.2.3.4")),
                    asyncio.run(client.lookup_email("a@example.com", "1.2.3.4"))):
            if out is not None:
                assert out.get("found") is False, f"{body} produced {out!r}"
                assert out.get("stealer_families") == {}


def test_over_quota_looks_exactly_like_disabled(monkeypatch):
    """The upstream quota is not ours, so being over the cap renders nothing."""
    monkeypatch.setattr(client, "HUDSONROCK_ENABLED", True)
    monkeypatch.setattr(client.cache, "get", lambda *a, **k: None)
    monkeypatch.setattr(client, "_quota_ok", lambda ip: False)

    called = []
    async def fake(url, **kw):
        called.append(url)
        return {"status": 200, "body": "{}"}
    monkeypatch.setattr(client, "safe_fetch", fake)

    assert asyncio.run(client.lookup_domain("example.com", "1.2.3.4")) is None
    assert called == [], "over quota must not reach upstream at all"


def test_cache_hit_does_not_consume_quota(monkeypatch):
    monkeypatch.setattr(client, "HUDSONROCK_ENABLED", True)
    monkeypatch.setattr(client.cache, "get",
                        lambda *a, **k: {"found": False, "total": 0, "cache_hit": True,
                                         "fetched_at": "2026-01-01"})
    quota_calls = []
    monkeypatch.setattr(client, "_quota_ok", lambda ip: quota_calls.append(ip) or True)

    out = asyncio.run(client.lookup_domain("example.com", "1.2.3.4"))
    assert out is not None
    assert quota_calls == [], "a cache hit must not spend upstream quota"
    # Cache bookkeeping is not part of the response contract.
    assert "cache_hit" not in out and "fetched_at" not in out


def test_a_good_response_survives_end_to_end(enabled, monkeypatch):
    """The happy path, so the failure tests above cannot pass vacuously."""
    _serve(monkeypatch, body=json.dumps({
        "total": 7, "employees": 2, "users": 5, "third_parties": 0,
        "stealerFamilies": {"total": 7, "RedLine": 4, "Lumma": 3},
        "last_user_compromised": "2026-02-03T04:05:06.000Z",
    }))
    out = asyncio.run(client.lookup_domain("example.com", "1.2.3.4"))
    assert out["found"] is True
    assert out["stealer_families"] == {"RedLine": 4, "Lumma": 3}
    assert out["last_user_compromised"] == "2026-02-03T04:05:06.000Z"
