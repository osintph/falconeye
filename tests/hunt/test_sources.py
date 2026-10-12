"""Hunt discovery: permutations on open TLDs, restricted-namespace and legit
exclusion, crt.sh keyword matching with retry, caps, and the INCOMPLETE rule."""
import asyncio

import httpx

from app import config
from app.hunt import sources


def _fast_crtsh(monkeypatch):
    """Make the crt.sh gate and retry backoff instant for tests."""
    monkeypatch.setattr(config, "HUNT_CRTSH_MIN_INTERVAL", 0.0)
    monkeypatch.setattr(config, "HUNT_CRTSH_RETRY_DELAY", 0.0)
    monkeypatch.setattr(sources.store, "reserve_gate_slot", lambda *a, **k: 0.0)


def test_permutations_use_open_tlds_and_keyword_combos():
    perms = sources._permutations("philhealth.gov.ph", "philhealth")
    assert perms, "expected permutations"
    assert any(p.endswith(".ph") for p in perms)
    assert any(("login" in p or "verify" in p or "refund" in p) for p in perms)


def test_permutations_exclude_restricted_namespaces_and_legit():
    perms = sources._permutations("philhealth.gov.ph", "philhealth")
    # An attacker cannot register under .gov.ph, so no candidate lands there.
    assert not any(p.endswith(".gov.ph") for p in perms)
    assert not any(p.endswith(".edu.ph") or p.endswith(".mil.ph") for p in perms)
    # The legit domain and its subdomains are never candidates.
    assert "philhealth.gov.ph" not in perms
    assert not any(p.endswith(".philhealth.gov.ph") for p in perms)


def test_clean_host_rejects_wildcards_and_junk():
    assert sources._clean_host("*.evil.com") == "evil.com"
    assert sources._clean_host("https://a.b.com/path") == "a.b.com"
    assert sources._clean_host("not a host") == ""
    assert sources._clean_host("ok-domain.ph") == "ok-domain.ph"


def test_is_legit_or_sub():
    assert sources._is_legit_or_sub("philhealth.gov.ph", "philhealth.gov.ph")
    assert sources._is_legit_or_sub("member.philhealth.gov.ph", "philhealth.gov.ph")
    assert not sources._is_legit_or_sub("philhealthgov.ph", "philhealth.gov.ph")


def _mock_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)


def test_crtsh_keyword_extracts_matching_hosts(monkeypatch):
    _fast_crtsh(monkeypatch)

    def handler(request):
        return httpx.Response(200, json=[
            {"name_value": "philhealth-refund.ph\nwww.philhealth-refund.ph"},
            {"name_value": "unrelated.com"},
        ], headers={"content-type": "application/json"})

    async def go():
        async with _mock_client(handler) as client:
            return await sources._crtsh(client, "philhealth")
    hosts, status, note = asyncio.run(go())
    assert status == "answered"
    assert "philhealth-refund.ph" in hosts
    assert "unrelated.com" not in hosts  # must contain the keyword


def test_crtsh_502_retries_once_then_backs_off(monkeypatch):
    _fast_crtsh(monkeypatch)
    monkeypatch.setattr(sources.store, "ct_cache_get", lambda *a, **k: None)
    monkeypatch.setattr(sources.store, "gate_wait", lambda *a, **k: 0.0)
    backoff = {"set": 0}
    monkeypatch.setattr(sources.store, "gate_set_backoff",
                        lambda *a, **k: backoff.__setitem__("set", backoff["set"] + 1))
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(502)

    async def go():
        async with _mock_client(handler) as client:
            return await sources._crtsh(client, "philhealth")
    hosts, status, note = asyncio.run(go())
    assert status == "failed" and not hosts
    assert calls["n"] == 2  # one request plus a single in-run retry, then give up
    assert backoff["set"] == 1 and "502" in note and "retried once" in note
    assert "block" not in note.lower()  # must never claim the IP is blocked


def test_crtsh_recovers_on_the_retry(monkeypatch):
    # 502 then 200 on the retry: the run still gets the answer, no backoff.
    _fast_crtsh(monkeypatch)
    monkeypatch.setattr(sources.store, "ct_cache_get", lambda *a, **k: None)
    monkeypatch.setattr(sources.store, "gate_wait", lambda *a, **k: 0.0)
    monkeypatch.setattr(sources.store, "ct_cache_put", lambda *a, **k: None)
    backoff = {"set": 0}
    monkeypatch.setattr(sources.store, "gate_set_backoff",
                        lambda *a, **k: backoff.__setitem__("set", backoff["set"] + 1))
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(502)
        return httpx.Response(200, json=[{"name_value": "philhealth-login.ph"}],
                              headers={"content-type": "application/json"})

    async def go():
        async with _mock_client(handler) as client:
            return await sources._crtsh(client, "philhealth")
    hosts, status, note = asyncio.run(go())
    assert status == "answered" and "philhealth-login.ph" in hosts
    assert calls["n"] == 2 and backoff["set"] == 0  # recovered on the retry, no backoff


def test_crtsh_served_from_cache_makes_no_request(monkeypatch):
    _fast_crtsh(monkeypatch)
    monkeypatch.setattr(sources.store, "ct_cache_get",
                        lambda kw, ttl: ["philhealth-refund.ph", "other.com"])
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(200, json=[], headers={"content-type": "application/json"})

    async def go():
        async with _mock_client(handler) as client:
            return await sources._crtsh(client, "philhealth")
    hosts, status, note = asyncio.run(go())
    assert status == "answered" and calls["n"] == 0  # cache hit, no network
    assert "philhealth-refund.ph" in hosts and "other.com" not in hosts  # keyword filter
    assert "cache" in note


def test_crtsh_skips_request_while_backing_off(monkeypatch):
    _fast_crtsh(monkeypatch)
    monkeypatch.setattr(sources.store, "ct_cache_get", lambda *a, **k: None)
    monkeypatch.setattr(sources.store, "gate_wait", lambda *a, **k: 999.0)  # long backoff
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(200, json=[], headers={"content-type": "application/json"})

    async def go():
        async with _mock_client(handler) as client:
            return await sources._crtsh(client, "philhealth")
    hosts, status, note = asyncio.run(go())
    assert status == "failed" and calls["n"] == 0  # skipped the request during backoff
    assert "retry" in note


async def _skip_nrd(client, kw):
    return set(), "skipped"


async def _fail_crt(client, kw):
    return set(), "failed", "crt.sh keyword search returned 502 (crt.sh side)"


def _us_meta(age=100):
    return {"first_seen": "2026-09-01", "title": "", "labels": [], "asn": None,
            "age_days": age, "server": None, "result_url": "", "observed": set()}


async def _ok_urlscan(client, kw, legit="", pages=5):
    return {f"{kw}-{i}.ph": _us_meta() for i in range(20)}, "answered", 1


async def _fail_urlscan(client, kw, legit="", pages=5):
    return {}, "failed", 0


def test_discover_does_not_fetch_cap_and_labels_hits(monkeypatch):
    # Resolve-before-cap: discovery keeps every candidate up to the resolve ceiling
    # (no fetch cap here), so all 20 urlscan hits are present and labelled.
    _fast_crtsh(monkeypatch)
    monkeypatch.setattr(sources, "_crtsh", _fail_crt)
    monkeypatch.setattr(sources, "_urlscan", _ok_urlscan)
    monkeypatch.setattr(sources, "_nrd", _skip_nrd)

    out = asyncio.run(sources.discover("philhealth", "philhealth.gov.ph"))
    hits = [c for c in out["candidates"] if c["keyword_hit"]]
    assert len(hits) == 20  # every urlscan hit kept, not capped at discovery
    assert all("urlscan.io" in c["origins"] for c in hits)
    assert len(out["candidates"]) > 20  # permutations are also present (resolve-before-cap)


def test_crtsh_failure_alone_does_not_make_incomplete(monkeypatch):
    # crt.sh is best effort: if urlscan answered, a crt.sh failure is COMPLETE.
    _fast_crtsh(monkeypatch)
    monkeypatch.setattr(sources, "_crtsh", _fail_crt)
    monkeypatch.setattr(sources, "_urlscan", _ok_urlscan)
    monkeypatch.setattr(sources, "_nrd", _skip_nrd)
    out = asyncio.run(sources.discover("philhealth", "philhealth.gov.ph"))
    assert out["incomplete"] is False
    ct = next(s for s in out["source_status"] if s["source"] == "crt.sh")
    assert ct["status"] == "failed" and "block" not in (ct.get("note") or "").lower()


def test_discover_drops_irrelevant_keyword_hits(monkeypatch):
    _fast_crtsh(monkeypatch)

    async def crt_none(client, kw):
        return set(), "answered", ""

    async def us(client, kw, legit="", pages=5):
        return ({"mmda-ltoncap.net": _us_meta(30), "stammdaten.de": _us_meta(2000),
                 "emmday.in": _us_meta(500)}, "answered", 1)

    monkeypatch.setattr(sources, "_crtsh", crt_none)
    monkeypatch.setattr(sources, "_urlscan", us)
    monkeypatch.setattr(sources, "_nrd", _skip_nrd)
    out = asyncio.run(sources.discover("mmda", "mmda.gov.ph"))
    doms = [c["domain"] for c in out["candidates"]]
    assert "mmda-ltoncap.net" in doms  # relevant lookalike kept
    assert "stammdaten.de" not in doms and "emmday.in" not in doms  # buried, dropped
    assert out["irrelevant_count"] >= 2


def test_discover_incomplete_when_urlscan_fails(monkeypatch):
    # urlscan is the primary keyword source; its failure makes the run INCOMPLETE.
    _fast_crtsh(monkeypatch)
    monkeypatch.setattr(sources, "_crtsh", _fail_crt)
    monkeypatch.setattr(sources, "_urlscan", _fail_urlscan)
    monkeypatch.setattr(sources, "_nrd", _skip_nrd)
    out = asyncio.run(sources.discover("philhealth", "philhealth.gov.ph"))
    assert out["incomplete"] is True


def test_discover_excludes_the_legit_domain(monkeypatch):
    _fast_crtsh(monkeypatch)

    async def crt_with_legit(client, kw):
        # crt.sh returns the legit domain and a lookalike; the legit must be dropped.
        return {"philhealth.gov.ph", "philhealth-login.ph"}, "answered", ""

    async def no_urlscan(client, kw, legit="", pages=5):
        return {}, "answered", 0

    monkeypatch.setattr(sources, "_crtsh", crt_with_legit)
    monkeypatch.setattr(sources, "_urlscan", no_urlscan)
    monkeypatch.setattr(sources, "_nrd", _skip_nrd)

    out = asyncio.run(sources.discover("philhealth", "philhealth.gov.ph"))
    domains = [c["domain"] for c in out["candidates"]]
    assert "philhealth.gov.ph" not in domains
    assert "philhealth-login.ph" in domains
