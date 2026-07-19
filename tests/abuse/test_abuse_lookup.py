"""Tests for RDAP abuse-contact parsing and the lookup service."""
import asyncio
import json

from app.abuse import lookup
from app.abuse.lookup import _extract_abuse_email, _valid_email, _rir_from_url


# ARIN-style: abuse entity nested under the registrant org entity.
ARIN_RDAP = {
    "handle": "NET-1-2-3-0-1",
    "name": "PROV-NET",
    "country": "US",
    "entities": [
        {
            "handle": "ORG-1",
            "roles": ["registrant"],
            "entities": [
                {
                    "handle": "ABUSE-ARIN",
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Abuse Department"],
                        ["email", {}, "text", "abuse@prov.example"],
                        ["tel", {}, "text", "+1-555-0100"],
                    ]],
                }
            ],
        }
    ],
}

# RIPE-style: abuse entity at the top level.
RIPE_RDAP = {
    "handle": "1.2.3.0 - 1.2.3.255",
    "name": "RIPE-EXAMPLE",
    "country": "NL",
    "entities": [
        {
            "handle": "AB-RIPE",
            "roles": ["abuse"],
            "vcardArray": ["vcard", [
                ["fn", {}, "text", "Abuse Contact"],
                ["email", {}, "text", "abuse@ripe.example"],
            ]],
        }
    ],
}


def test_email_regex_accepts_and_rejects():
    assert _valid_email("abuse@prov.example")
    assert _valid_email("network-abuse@google.com")
    for bad in ["not-an-email", "a@b", "<a@b.com>", "a@b.com, c@d.com",
                "a b@c.com", "", "abuse@localhost", "abuse@@x.com", None]:
        assert not _valid_email(bad), bad


def test_extract_abuse_email_arin_nested():
    assert _extract_abuse_email(ARIN_RDAP) == "abuse@prov.example"


def test_extract_abuse_email_ripe_toplevel():
    assert _extract_abuse_email(RIPE_RDAP) == "abuse@ripe.example"


def test_extract_abuse_email_malformed_returns_none():
    for junk in [{}, {"entities": None}, {"entities": [{"roles": ["abuse"]}]},
                 {"entities": [{"roles": ["abuse"], "vcardArray": ["vcard", "nope"]}]},
                 {"entities": [123, "x", {"roles": "abuse"}]}]:
        assert _extract_abuse_email(junk) is None


def test_rir_from_url():
    assert _rir_from_url("https://rdap.arin.net/registry/ip/1.2.3.4") == "ARIN"
    assert _rir_from_url("https://rdap.db.ripe.net/ip/1.2.3.4") == "RIPE"
    assert _rir_from_url("https://rdap.apnic.net/ip/1.1.1.1") == "APNIC"


def test_lookup_ip_parses_and_caches(monkeypatch):
    calls = {"n": 0}

    async def fake_fetch(url, **kw):
        calls["n"] += 1
        return {"status": 200, "headers": {}, "body": json.dumps(ARIN_RDAP),
                "url_final": "https://rdap.arin.net/registry/ip/1.2.3.4"}

    monkeypatch.setattr(lookup, "safe_fetch", fake_fetch)

    r = asyncio.run(lookup.lookup_ip_abuse("1.2.3.4"))
    assert r["abuse_email"] == "abuse@prov.example"
    assert r["rir"] == "ARIN"
    assert r["network_name"] == "PROV-NET"
    assert r["error"] is None
    assert calls["n"] == 1

    # second call must hit the cache, not the network
    r2 = asyncio.run(lookup.lookup_ip_abuse("1.2.3.4"))
    assert r2["abuse_email"] == "abuse@prov.example"
    assert r2.get("cache_hit") is True
    assert calls["n"] == 1


def test_lookup_ip_private_short_circuits(monkeypatch):
    async def fake_fetch(url, **kw):
        raise AssertionError("safe_fetch must not be called for a private IP")

    monkeypatch.setattr(lookup, "safe_fetch", fake_fetch)
    r = asyncio.run(lookup.lookup_ip_abuse("127.0.0.1"))
    assert r["abuse_email"] is None
    assert r["error"]


def test_lookup_ip_malformed_response_no_raise(monkeypatch):
    async def fake_fetch(url, **kw):
        return {"status": 200, "headers": {}, "body": "not-json{", "url_final": "https://rdap.arin.net/x"}

    monkeypatch.setattr(lookup, "safe_fetch", fake_fetch)
    r = asyncio.run(lookup.lookup_ip_abuse("8.8.8.8"))
    assert r["abuse_email"] is None
    assert r["error"]


def test_lookup_ip_rdap_http_500_degrades_gracefully(monkeypatch):
    """RDAP returning a 500 must yield a normal result dict with `error`, never raise."""
    async def fake_fetch(url, **kw):
        return {"status": 500, "headers": {}, "body": "Internal Server Error",
                "url_final": "https://rdap.arin.net/registry/ip/9.9.9.9"}

    monkeypatch.setattr(lookup, "safe_fetch", fake_fetch)
    r = asyncio.run(lookup.lookup_ip_abuse("9.9.9.9"))
    assert r["abuse_email"] is None
    assert r["error"]
    assert r["target"] == "9.9.9.9"
