"""
Tests for the consolidated kit report and the /api/scanner/kit-report endpoint.

Covers offline mode shape, the SSRF guard holding on acquisition and probing,
the daily rate limit, and the promotion rule that picks which bundle actually
gets torn down.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import KIT_REPORT_RATE_LIMIT_PER_DAY
from app.routers import scanner as scanner_routes
from app.scanner import kit_acquire, kit_report, rabbithunt_sig
from app.utils.safe_fetch import SafeFetchError
from tests.scanner.kit_fixtures import (
    SERVER_RENDERED_HTML,
    SPA_SHELL_HTML,
    build_clean_bundle,
    build_obfuscated_bundle,
)


def _client(burst_limit=False):
    app = FastAPI()
    app.state.limiter = scanner_routes.limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(scanner_routes.router)
    scanner_routes.limiter.enabled = burst_limit
    return TestClient(app)


# ---------- input sniffing ----------

@pytest.mark.parametrize("text,expected", [
    (build_obfuscated_bundle(), True),
    (build_clean_bundle(), True),
    (SPA_SHELL_HTML, False),
    (SERVER_RENDERED_HTML, False),
    ("<!DOCTYPE html><html><body>hi</body></html>", False),
    ("", False),
    ("   ", False),
    ("just a sentence with no code in it", False),
])
def test_looks_like_javascript(text, expected):
    assert kit_report.looks_like_javascript(text) is expected


# ---------- offline mode ----------

def test_offline_report_shape_has_live_fields_null():
    report = kit_report.build_offline_report(build_obfuscated_bundle())

    assert report["mode"] == "offline"
    # Live-only fields are null, not empty: "not collected" and "collected and
    # found nothing" are different findings.
    assert report["page"] is None
    assert report["socket_probe"] is None
    assert report["enrichment"] is None
    assert report["score"]["host"] is None
    assert report["timeline"] == []
    assert all(v is None for v in report["target"].values())

    # Everything derivable from the bundle is still populated.
    assert report["analysis"]["decode_score"] == 1.0
    assert report["score"]["bundle"]["verdict"] == "STRONG MATCH"
    assert report["indicators"]
    assert report["bundles"][0]["sha256"]
    assert report["notes"]


def test_offline_report_on_a_clean_bundle_is_no_match():
    report = kit_report.build_offline_report(build_clean_bundle())
    assert report["score"]["bundle"]["verdict"] == "NO MATCH"


def test_offline_endpoint_returns_the_report(monkeypatch):
    client = _client()
    resp = client.post("/api/scanner/kit-report",
                       json={"raw_html": build_obfuscated_bundle()})
    assert resp.status_code == 200
    body = resp.json()
    assert body["mode"] == "offline"
    assert body["score"]["bundle"]["verdict"] == "STRONG MATCH"
    assert body["page"] is None


def test_pasted_html_without_a_url_is_rejected_with_guidance():
    client = _client()
    resp = client.post("/api/scanner/kit-report", json={"raw_html": SERVER_RENDERED_HTML})
    assert resp.status_code == 400
    assert "not a JavaScript bundle" in resp.json()["detail"]


def test_empty_request_is_rejected():
    client = _client()
    assert client.post("/api/scanner/kit-report", json={}).status_code == 400


# ---------- the SSRF guard holds ----------

@pytest.mark.parametrize("blocked_url", [
    "http://127.0.0.1/admin",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "http://10.0.0.5/",
    "http://192.168.1.1/",
    "file:///etc/passwd",
])
def test_acquisition_refuses_blocked_targets(blocked_url):
    """A blocked target comes back as a recorded refusal, never a fetch."""
    import asyncio
    page = asyncio.run(kit_acquire.fetch_page(blocked_url))
    assert page["status"] is None
    assert page["body"] == ""
    assert page["error"]


def test_blocked_target_is_refused_before_anything_else_touches_it(monkeypatch):
    """A refused target must not then be probed, fetched or enriched."""
    import asyncio

    touched = []

    async def _tripwire(*args, **kwargs):
        touched.append(args)
        return {"found": False}

    monkeypatch.setattr(kit_report, "_rdap", _tripwire)
    monkeypatch.setattr(kit_report, "_ct", _tripwire)
    monkeypatch.setattr(kit_report, "_urlscan", _tripwire)
    monkeypatch.setattr(kit_acquire, "probe_socket", _tripwire)

    with pytest.raises(SafeFetchError):
        asyncio.run(kit_report.build_live_report("http://127.0.0.1/kit/"))

    assert touched == [], "a blocked target must not be probed or enriched"


def test_socket_probe_refuses_a_private_host():
    import asyncio
    probe = asyncio.run(rabbithunt_sig.probe_socket("127.0.0.1", "/com/"))
    assert probe["root"]["status"] is None
    assert probe["campaign"]["status"] is None
    assert probe["path_scoped"] is False


def test_endpoint_returns_400_for_a_blocked_url():
    client = _client()
    resp = client.post("/api/scanner/kit-report", json={"url": "http://127.0.0.1/"})
    assert resp.status_code == 400
    assert "blocked" in resp.json()["detail"].lower()


@pytest.mark.parametrize("host,expected", [
    ("jtexpress.mwkqbr.club", True),
    ("example.com", True),
    ("127.0.0.1", False),
    ("10.0.0.1", False),
    ("::1", False),
    ("localhost", False),
    ("", False),
])
def test_is_domain_gates_registry_lookups(host, expected):
    assert kit_report.is_domain(host) is expected


# ---------- rate limiting ----------

def test_daily_rate_limit_enforced():
    client = _client()
    payload = {"raw_html": build_clean_bundle()}

    for i in range(KIT_REPORT_RATE_LIMIT_PER_DAY):
        assert client.post("/api/scanner/kit-report", json=payload).status_code == 200, \
            f"request {i + 1} should be allowed"

    resp = client.post("/api/scanner/kit-report", json=payload)
    assert resp.status_code == 429
    assert "Daily limit reached" in resp.json()["detail"]


def test_rate_limit_counts_rejected_requests_too():
    """The quota protects the endpoint, so it is spent before the work starts."""
    client = _client()
    for _ in range(KIT_REPORT_RATE_LIMIT_PER_DAY):
        client.post("/api/scanner/kit-report", json={"raw_html": build_clean_bundle()})
    resp = client.post("/api/scanner/kit-report", json={"raw_html": SERVER_RENDERED_HTML})
    assert resp.status_code == 429


# ---------- acquisition helpers ----------

def test_spa_shell_detected_as_client_rendered_not_a_block():
    result = kit_acquire.is_spa(SPA_SHELL_HTML)
    assert result["spa"] is True
    assert "not a block" in result["reason"]


def test_server_rendered_page_is_not_an_spa():
    assert kit_acquire.is_spa(SERVER_RENDERED_HTML)["spa"] is False


def test_empty_body_is_not_claimed_to_be_an_spa():
    assert kit_acquire.is_spa("")["spa"] is False


def test_extract_assets_finds_href_and_src_and_marks_the_entry():
    assets = kit_acquire.extract_assets(SPA_SHELL_HTML, "https://host.example/com/")
    names = [a["name"] for a in assets]
    assert "CS7qCa7O.js" in names
    assert "B3_5Glc7.js" in names, "modulepreload href assets must be collected"
    assert "D2c36igU.js" in names
    assert "X8NV_Jr5.css" in names

    by_name = {a["name"]: a for a in assets}
    assert by_name["CS7qCa7O.js"]["entry"] is True
    assert by_name["B3_5Glc7.js"]["entry"] is False
    assert by_name["CS7qCa7O.js"]["url"] == "https://host.example/com/assets/CS7qCa7O.js"
    assert by_name["X8NV_Jr5.css"]["kind"] == "css"
    assert assets[0]["entry"] is True, "the entry bundle sorts first"


def test_the_analyzed_bundle_is_the_richest_not_just_the_script_src():
    """The signature can live in a modulepreload chunk, not the script src.

    Promoting the script-src entry unconditionally would have found nothing at
    all in the case this is modelled on.
    """
    thin_loader = kit_report.kit_analyzer.analyze(build_clean_bundle())
    kit_chunk = kit_report.kit_analyzer.analyze(
        build_obfuscated_bundle(), signature=rabbithunt_sig.get_signature())

    scored = [
        (thin_loader, rabbithunt_sig.score_bundle(thin_loader)),
        (kit_chunk, rabbithunt_sig.score_bundle(kit_chunk)),
    ]
    assert kit_report._pick_primary(scored) == 1


def test_entry_bundle_helper_prefers_the_script_src():
    bundles = [
        {"name": "a.js", "entry": False, "text": "x", "size_bytes": 900},
        {"name": "b.js", "entry": True, "text": "y", "size_bytes": 10},
    ]
    assert kit_acquire.entry_bundle(bundles)["name"] == "b.js"
    assert kit_acquire.entry_bundle([]) is None
    assert kit_acquire.entry_bundle([{"name": "c.js", "text": "", "entry": True}]) is None


# ---------- timeline ----------

def test_timeline_rows_are_sourced_and_ordered():
    rdap = {
        "found": True,
        "events": {"registration": "2026-08-17T13:04:00Z",
                   "last changed": "2026-08-21T08:58:26Z"},
        "status": ["client hold", "client transfer prohibited"],
        "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
        "registrar": "Dominet (HK) Limited",
    }
    ct = {"first_seen": "2026-08-18T00:00:00Z", "issuer": "Google Trust Services"}
    urlscan = {"submitted_at": "2026-08-19T03:21:00Z"}

    rows = kit_report.build_timeline(rdap, ct, urlscan)
    assert [r["source"] for r in rows] == ["RDAP", "CT", "urlscan", "RDAP"]
    assert "Dominet (HK) Limited" in rows[0]["event"]
    assert rows[0]["time"] == "2026-08-17 13:04 UTC"
    assert "client hold" in rows[-1]["event"]
    assert "ns1.cloudflare.com" in rows[-1]["event"]


def test_timeline_emits_no_row_without_a_source():
    """A row with no lookup behind it would be a guess."""
    assert kit_report.build_timeline({}, {}, {}) == []


def test_registrable_domain():
    assert kit_report.registrable_domain("jtexpress.mwkqbr.club") == "mwkqbr.club"
    assert kit_report.registrable_domain("a.b.c.example.co.uk") == "example.co.uk"
    assert kit_report.registrable_domain("shop.example.com.ph") == "example.com.ph"
    assert kit_report.registrable_domain("example.com") == "example.com"
    assert kit_report.registrable_domain("localhost") == "localhost"
    assert kit_report.registrable_domain("") == ""


# ---------- the LLM never sees raw content ----------

def test_llm_view_carries_no_raw_bundle_or_page_content():
    report = kit_report.build_offline_report(build_obfuscated_bundle())
    report["page"] = {"status": 200, "server": "cloudflare", "spa": True,
                      "session_cookie": "_vt=abc", "set_cookie": "_vt=abc; Path=/",
                      "body": "<html>SHOULD NOT LEAK</html>"}
    view = kit_report._llm_view(report)

    import json
    blob = json.dumps(view, ensure_ascii=False)
    assert "SHOULD NOT LEAK" not in blob
    assert "set_cookie" not in view["page"]
    # Decoded bundle strings and indicator hit values must not travel either.
    assert "decoded_sample" not in blob
    assert "NLFRWBHXVQJTCPYK" not in blob, "raw key material need not reach the model"
    assert "table_hits" not in blob
    # Structural facts still make it through.
    assert view["socket"]["path"] == "/console"
    assert view["storage_keys"] == ["t_config"]


def test_llm_summary_disabled_returns_none(monkeypatch):
    import asyncio
    monkeypatch.setattr(kit_report, "LLM_ANALYSIS_ENABLED", False)
    assert asyncio.run(kit_report.llm_summary({})) is None


# ---------- caching ----------

def test_analysis_is_cached_by_bundle_sha256():
    signature = rabbithunt_sig.get_signature()
    src = build_obfuscated_bundle()
    first = kit_report.analyze_cached(src, "deadbeef" * 8, signature)
    second = kit_report.analyze_cached("totally different source", "deadbeef" * 8, signature)
    # Same key returns the memoized analysis, which is the point.
    assert second["sha256"] == first["sha256"]
    assert second["table_entries"] == first["table_entries"]
    assert "cache_hit" not in second


def test_failed_analysis_is_not_cached():
    signature = rabbithunt_sig.get_signature()
    oversized = "x" * (kit_report.kit_analyzer.MAX_INPUT_BYTES + 1)
    kit_report.analyze_cached(oversized, "cafebabe" * 8, signature)
    good = kit_report.analyze_cached(build_obfuscated_bundle(), "cafebabe" * 8, signature)
    assert good["error"] is None
    assert good["table_entries"] == 68
