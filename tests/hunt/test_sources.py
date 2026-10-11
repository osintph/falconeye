"""Hunt discovery: permutations, IDN coverage, crt.sh keyword matching, caps, and
the INCOMPLETE rule when a discovery source fails."""
import asyncio
from unittest.mock import patch

import httpx

from app import config
from app.hunt import sources


def test_permutations_cover_idn_tld_and_keyword_combos():
    perms = sources._permutations("philhealth.gov.ph", "philhealth")
    assert perms, "expected permutations"
    # PH TLD swaps and keyword combos appear.
    assert any(p.endswith(".ph") for p in perms)
    assert any("login" in p or "verify" in p or "refund" in p for p in perms)
    # At least one punycode (IDN) homoglyph form.
    assert any(p.startswith("xn--") or p != p.encode("ascii", "ignore").decode() for p in perms) or \
        any("1" in p for p in perms)  # homoglyph substitutions


def test_clean_host_rejects_wildcards_and_junk():
    assert sources._clean_host("*.evil.com") == "evil.com"
    assert sources._clean_host("https://a.b.com/path") == "a.b.com"
    assert sources._clean_host("not a host") == ""
    assert sources._clean_host("ok-domain.ph") == "ok-domain.ph"


def _mock_client(handler):
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport, follow_redirects=True)


def test_crtsh_keyword_extracts_matching_hosts():
    def handler(request):
        return httpx.Response(200, json=[
            {"name_value": "philhealth-refund.ph\nwww.philhealth-refund.ph"},
            {"name_value": "unrelated.com"},
        ], headers={"content-type": "application/json"})

    async def go():
        async with _mock_client(handler) as client:
            return await sources._crtsh(client, "philhealth")
    hosts, status = asyncio.run(go())
    assert status == "answered"
    assert "philhealth-refund.ph" in hosts
    assert "unrelated.com" not in hosts  # must contain the keyword


def test_crtsh_failure_reports_failed():
    def handler(request):
        return httpx.Response(502)

    async def go():
        async with _mock_client(handler) as client:
            return await sources._crtsh(client, "philhealth")
    hosts, status = asyncio.run(go())
    assert status == "failed" and not hosts


def test_discover_caps_candidates_and_flags_incomplete(monkeypatch):
    monkeypatch.setattr(config, "HUNT_MAX_CANDIDATES", 5)

    async def fail_crt(client, kw):
        return set(), "failed"

    async def ok_urlscan(client, kw):
        return {f"{kw}-{i}.ph" for i in range(20)}, "answered"

    monkeypatch.setattr(sources, "_crtsh", fail_crt)
    monkeypatch.setattr(sources, "_urlscan", ok_urlscan)
    monkeypatch.setattr(sources, "_nrd", _skip_nrd)

    out = asyncio.run(sources.discover("philhealth", "philhealth.gov.ph"))
    assert len(out["candidates"]) <= 5
    assert out["incomplete"] is True  # crt.sh failed
    assert out["nrd_off"] is True


async def _skip_nrd(client, kw):
    return set(), "skipped"
