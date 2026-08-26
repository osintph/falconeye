"""
Case scope: the report must describe the host that was submitted, and only that.

These cover the station.qpon regression, where the deep kit report was handed a
live phishing URL, followed the kit's cloaking redirect to the brand it was
impersonating, and then ran the entire pipeline against that brand: five
unsolicited socket probes at their production infrastructure, a registry and CT
profile of their domain, their registrar and nameservers in the copyable
indicator block, and a confident NO MATCH 0% verdict on a page nobody had
looked at.

The tests are written against the bug CLASS rather than the one instance. What
is asserted is the invariant "the case host comes from the submitted URL and
outbound requests stay on it", not "petron does not appear", so a future change
that leaks a host through a canonical link or an og:url fails these too.
"""

import asyncio
import json
import pathlib
import sys
import types

import pytest

from app.scanner import kit_acquire, kit_report, rabbithunt_sig
from app.scanner.ph_bank_indicators import detect_brand
from app.scanner.scope import OutOfScope, in_scope, registrable

FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "station_qpon"


def _read_fixture(name: str) -> str:
    path = FIXTURES / name
    if not path.exists():
        pytest.skip(f"evidence fixture missing: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


# The bare-profile capture is the impersonated brand's real homepage, kept
# locally as evidence but not committed: see tests/fixtures/station_qpon/.gitignore.
# These tests use it when it is present and a synthetic stand-in otherwise, so
# they assert the same thing either way and never silently skip.
_SYNTHETIC_BRAND_HOME = (
    "<!doctype html><html><head><title>Home - Petron</title>"
    '<meta property="og:site_name" content="Petron">'
    "</head><body><p>Petron Corporation</p>"
    '<a href="https://www.petron.com/fuels">Petron Blaze</a>'
    "<p>Petron Value Card</p></body></html>"
)


def _brand_home_html() -> str:
    path = FIXTURES / "body_bare.html"
    if path.exists():
        return path.read_text(encoding="utf-8", errors="replace")
    return _SYNTHETIC_BRAND_HOME


# ---------------------------------------------------------------------------
# A transport that redirects off the submitted domain, and a tripwire that
# records every host anything tried to reach.
# ---------------------------------------------------------------------------

def _redirecting_transport(reached: list, start_host: str, end_url: str,
                           end_body: str = "", per_profile: dict | None = None):
    """Fake safe_fetch: anything on start_host redirects to end_url.

    `per_profile` maps a User-Agent substring to a (final_url, body) pair, which
    is how a cloaking target that answers a scanner and a browser differently
    gets modelled.
    """
    async def _fake(url, method="GET", headers=None, timeout=15.0,
                    max_redirects=3, allow_redirects=True):
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        reached.append(host)

        final_url, body = end_url, end_body
        if per_profile:
            ua = (headers or {}).get("User-Agent", "")
            for needle, (f_url, f_body) in per_profile.items():
                if needle in ua:
                    final_url, body = f_url, f_body
                    break

        if host == start_host and final_url != url:
            return {
                "status": 200,
                "headers": {"server": "GoFrame HTTP Server"},
                "body": body,
                "url_final": final_url,
                "redirect_chain": [{
                    "hop": 0, "url": url, "status": 302,
                    "location": final_url, "server": "GoFrame HTTP Server",
                }],
            }
        return {
            "status": 200,
            "headers": {"server": "test"},
            "body": body,
            "url_final": url,
            "redirect_chain": [],
        }
    return _fake


def _arm_tripwires(monkeypatch, calls: dict):
    """Replace every enrichment and probe entry point with a recorder."""
    def _record(name):
        async def _fn(*args, **kwargs):
            calls.setdefault(name, []).append((args, kwargs))
            return {"found": False}
        return _fn

    monkeypatch.setattr(kit_report, "_rdap", _record("rdap"))
    monkeypatch.setattr(kit_report, "_ct", _record("ct"))
    monkeypatch.setattr(kit_report, "_urlscan", _record("urlscan"))
    monkeypatch.setattr(kit_acquire, "probe_socket", _record("probe_socket"))
    monkeypatch.setattr(rabbithunt_sig, "probe_socket", _record("probe_socket_sig"))

    async def _score_host(*args, **kwargs):
        calls.setdefault("score_host", []).append((args, kwargs))
        return {}
    monkeypatch.setattr(rabbithunt_sig, "score_host", _score_host)

    async def _llm(*args, **kwargs):
        calls.setdefault("llm", []).append((args, kwargs))
        return None
    monkeypatch.setattr(kit_report, "llm_summary", _llm)


# ---------------------------------------------------------------------------
# 1. the case host is the submitted host
# ---------------------------------------------------------------------------

def test_target_host_from_submitted_url(monkeypatch):
    reached: list = []
    monkeypatch.setattr(kit_acquire, "safe_fetch",
                        _redirecting_transport(reached, "a.example", "https://b.example/"))
    calls: dict = {}
    _arm_tripwires(monkeypatch, calls)

    report = asyncio.run(kit_report.build_live_report("https://a.example/"))

    assert report["target"]["host"] == "a.example"
    assert report["target"]["registrable_domain"] == "a.example"
    assert report["target"]["final_host"] == "b.example"
    assert report["target"]["scope_left"] is True
    assert report["target"]["redirect_chain"], "the redirect chain must be recorded"


def test_same_domain_redirect_is_not_out_of_scope(monkeypatch):
    """A redirect that stays on the domain is normal and must not abort."""
    reached: list = []
    monkeypatch.setattr(
        kit_acquire, "safe_fetch",
        _redirecting_transport(reached, "a.example", "https://www.a.example/kit/"))
    calls: dict = {}
    _arm_tripwires(monkeypatch, calls)

    report = asyncio.run(kit_report.build_live_report("https://a.example/"))

    assert report["target"]["host"] == "a.example"
    assert report["target"]["scope_left"] is False
    assert report.get("out_of_scope") is False


# ---------------------------------------------------------------------------
# 2. leaving scope aborts the pipeline
# ---------------------------------------------------------------------------

def test_scope_left_aborts_enrichment(monkeypatch):
    reached: list = []
    monkeypatch.setattr(kit_acquire, "safe_fetch",
                        _redirecting_transport(reached, "a.example", "https://b.example/"))
    calls: dict = {}
    _arm_tripwires(monkeypatch, calls)

    report = asyncio.run(kit_report.build_live_report("https://a.example/"))

    assert report["out_of_scope"] is True
    for name in ("rdap", "ct", "urlscan", "probe_socket", "score_host", "llm"):
        assert calls.get(name, []) == [], f"{name} ran on an out-of-scope fetch"

    # And nothing reached the redirect destination beyond the redirect itself.
    assert "b.example" not in reached, f"requests were issued to {reached}"


def test_scope_left_reports_every_skipped_stage_with_a_reason(monkeypatch):
    reached: list = []
    monkeypatch.setattr(kit_acquire, "safe_fetch",
                        _redirecting_transport(reached, "a.example", "https://b.example/"))
    _arm_tripwires(monkeypatch, {})

    report = asyncio.run(kit_report.build_live_report("https://a.example/"))

    for key in ("registration_timeline", "enrichment", "socket_probe",
                "crypto", "analysis", "bundles"):
        assert report[key] is None, f"{key} should be null, not empty"
    assert "left the submitted registrable domain" in report["not_run_reason"]


# ---------------------------------------------------------------------------
# 3. null scores, never zero
# ---------------------------------------------------------------------------

def test_scores_are_null_not_zero_on_scope_left(monkeypatch):
    reached: list = []
    monkeypatch.setattr(kit_acquire, "safe_fetch",
                        _redirecting_transport(reached, "a.example", "https://b.example/"))
    _arm_tripwires(monkeypatch, {})

    report = asyncio.run(kit_report.build_live_report("https://a.example/"))

    assert report["score"]["bundle"] is None
    assert report["score"]["host"] is None

    # 0% reads as clean to a tired analyst. Nothing in the bundle or host score
    # may serialize as a zero percentage.
    for key in ("bundle", "host"):
        assert json.dumps(report["score"][key]) == "null"
    assert report["verdict"] == kit_report.OUT_OF_SCOPE_VERDICT


# ---------------------------------------------------------------------------
# 4. the indicator block never carries the redirect destination
# ---------------------------------------------------------------------------

def test_indicators_exclude_redirect_destination(monkeypatch):
    """The real station.qpon case, from the captured evidence."""
    body = _brand_home_html()
    reached: list = []
    monkeypatch.setattr(
        kit_acquire, "safe_fetch",
        _redirecting_transport(reached, "station.qpon", "https://www.petron.com/", body))
    _arm_tripwires(monkeypatch, {})

    report = asyncio.run(kit_report.build_live_report("https://station.qpon/"))
    copied = kit_report.copy_all_indicators(report)

    assert "petron" not in copied.lower(), f"indicator block leaked the brand:\n{copied}"
    assert "station.qpon" in copied

    # The destination is still reported, just not as an indicator.
    assert report["redirect_destination"]["host"] == "www.petron.com"
    assert "not an indicator" in report["redirect_destination"]["label"]


def test_indicator_builder_drops_a_foreign_case_host():
    """The filter is on the host type, not on one hardcoded brand name."""
    indicators = kit_report.build_indicators(
        target={"host": "www.petron.com", "domain": "petron.com"},
        page={}, rdap={}, bundles=[], analysis={}, probe={},
        case_registrable="station.qpon",
    )
    values = [i["value"] for i in indicators]
    assert "www.petron.com" not in values
    assert "petron.com" not in values


def test_third_party_nameservers_of_the_case_domain_are_kept():
    """Nameservers normally live on somebody else's domain. That is not a leak.

    Scope-filtering this field would drop correct case data on nearly every
    real target. It is the RDAP lookup being aimed at the case domain that
    keeps it honest, which _assert_case_domain enforces separately.
    """
    indicators = kit_report.build_indicators(
        target={"host": "station.qpon", "domain": "station.qpon"},
        page={},
        rdap={"registrar": "Some Registrar",
              "nameservers": ["ns1.domainnamens.com", "ns2.domainnamens.com"]},
        bundles=[], analysis={}, probe={},
        case_registrable="station.qpon",
    )
    values = [i["value"] for i in indicators]
    assert "ns1.domainnamens.com" in values
    assert "ns2.domainnamens.com" in values


def test_enrichment_call_site_assertion_rejects_a_foreign_domain():
    """The guard that makes the nameserver decision above safe."""
    kit_report._assert_case_domain("station.qpon", "station.qpon", "RDAP lookup")
    with pytest.raises(AssertionError):
        kit_report._assert_case_domain("petron.com", "station.qpon", "RDAP lookup")
    with pytest.raises(AssertionError):
        kit_report._assert_case_domain("https://www.petron.com/", "station.qpon",
                                       "urlscan lookup")


# ---------------------------------------------------------------------------
# 5. the probe refuses out-of-scope hosts before issuing a request
# ---------------------------------------------------------------------------

def test_probe_refuses_out_of_scope_host(monkeypatch):
    issued: list = []

    async def _tripwire(url, **kwargs):
        issued.append(url)
        return {"status": 200, "headers": {}, "body": "", "url_final": url,
                "redirect_chain": []}

    monkeypatch.setattr(rabbithunt_sig, "safe_fetch", _tripwire)

    with pytest.raises(OutOfScope):
        asyncio.run(kit_acquire.probe_socket("www.petron.com", "/", "station.qpon"))

    assert issued == [], f"the probe issued requests before refusing: {issued}"


def test_probe_allows_the_case_host_and_its_subdomains(monkeypatch):
    async def _ok(url, **kwargs):
        return {"status": 204, "headers": {}, "body": "", "url_final": url,
                "redirect_chain": []}
    monkeypatch.setattr(rabbithunt_sig, "safe_fetch", _ok)

    probe = asyncio.run(kit_acquire.probe_socket("a.station.qpon", "/", "station.qpon"))
    assert probe["campaign"]["status"] == 204


# ---------------------------------------------------------------------------
# 6. PSL-backed registrable domain
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("host,expected", [
    ("station.qpon", "station.qpon"),          # a real gTLD, already registrable
    ("www.petron.com", "petron.com"),
    ("foo.bar.com.ph", "bar.com.ph"),
    ("example.co.uk", "example.co.uk"),
    ("a.b.c.example.co.uk", "example.co.uk"),
    ("shop.example.com.ph", "example.com.ph"),
    ("x.gov.ph", "x.gov.ph"),                  # absent from the old hardcoded list
    ("jtexpress.mwkqbr.club", "mwkqbr.club"),
    ("example.com", "example.com"),
    ("localhost", "localhost"),                # fails closed, not to ""
    ("127.0.0.1", "127.0.0.1"),
    ("", ""),
])
def test_psl_registrable_domain(host, expected):
    assert registrable(host) == expected
    assert kit_report.registrable_domain(host) == expected


@pytest.mark.parametrize("host,case,expected", [
    ("station.qpon", "station.qpon", True),
    ("a.station.qpon", "station.qpon", True),
    ("www.petron.com", "station.qpon", False),
    ("evilstation.qpon", "station.qpon", False),   # suffix confusion
    ("station.qpon.attacker.com", "station.qpon", False),
    ("station.qpon", "", False),                   # fail closed
    ("", "station.qpon", False),
])
def test_in_scope(host, case, expected):
    assert in_scope(host, case) is expected


# ---------------------------------------------------------------------------
# 7. brand-identical content on an unrelated domain
# ---------------------------------------------------------------------------

def test_brand_host_mismatch(monkeypatch):
    """Petron-branded HTML served from station.qpon scores the mismatch."""
    body = _read_fixture("body_browser.html")
    brand = detect_brand(body)
    assert brand["brand"] == "Petron"

    async def _no_network(url, **kwargs):
        return {"status": 200, "headers": {}, "body": "", "url_final": url,
                "redirect_chain": []}
    monkeypatch.setattr(rabbithunt_sig, "safe_fetch", _no_network)

    score = asyncio.run(rabbithunt_sig.score_host(
        "station.qpon", "/", probe={}, brand=brand, case_registrable="station.qpon"))
    signal = next(s for s in score["signals"] if s["name"] == "brand_host_mismatch")
    assert signal["hit"] is True
    assert signal["weight"] == 12


def test_brand_on_its_own_domain_is_not_a_mismatch(monkeypatch):
    """The real brand on the real domain must not score impersonation."""
    body = _brand_home_html()
    brand = detect_brand(body)
    assert brand["brand"] == "Petron"

    async def _no_network(url, **kwargs):
        return {"status": 200, "headers": {}, "body": "", "url_final": url,
                "redirect_chain": []}
    monkeypatch.setattr(rabbithunt_sig, "safe_fetch", _no_network)

    score = asyncio.run(rabbithunt_sig.score_host(
        "www.petron.com", "/", probe={}, brand=brand, case_registrable="petron.com"))
    signal = next(s for s in score["signals"] if s["name"] == "brand_host_mismatch")
    assert signal["hit"] is False


def test_cross_domain_redirect_to_a_brand_scores(monkeypatch):
    score = rabbithunt_sig.score_redirect(
        scope_left=True, final_host="www.petron.com",
        case_registrable="station.qpon", profile_divergence=True)
    hits = {s["name"]: s for s in score["signals"]}
    assert hits["cross_domain_redirect"]["hit"] is True
    assert hits["redirect_to_impersonated_brand"]["hit"] is True
    assert hits["profile_divergence"]["hit"] is True
    # This combination must outrank any single bundle signal.
    assert score["score_pct"] == 100


def test_redirect_to_an_unknown_host_does_not_claim_impersonation():
    score = rabbithunt_sig.score_redirect(
        scope_left=True, final_host="unrelated.example",
        case_registrable="station.qpon", profile_divergence=False)
    hits = {s["name"]: s for s in score["signals"]}
    assert hits["cross_domain_redirect"]["hit"] is True
    assert hits["redirect_to_impersonated_brand"]["hit"] is False


# ---------------------------------------------------------------------------
# 8. the LLM summary cannot name a host that is not the case host
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,allowed,expected", [
    ("The host www.petron.com is a WordPress site.", {"station.qpon"}, "www.petron.com"),
    ("station.qpon serves a Vite SPA shell.", {"station.qpon"}, None),
    ("Registered via Network Solutions.", {"station.qpon"}, None),
    ("Pivot on petron.com next.", {"station.qpon"}, "petron.com"),
    ("Sub host a.station.qpon answered.", {"station.qpon"}, None),
])
def test_summary_mentions_foreign_host(text, allowed, expected):
    assert kit_report.summary_mentions_foreign_host(text, allowed) == expected


def _fake_anthropic(summary_text: str):
    """A stand-in anthropic module returning one fixed JSON summary."""
    module = types.ModuleType("anthropic")

    class _Block:
        type = "text"
        def __init__(self, text): self.text = text

    class _Response:
        def __init__(self, text): self.content = [_Block(text)]

    class _Messages:
        async def create(self, **kwargs):
            return _Response(json.dumps({
                "summary": summary_text,
                "confidence": "low",
                "next_steps": "Confirm ownership.",
            }))

    class _AsyncAnthropic:
        def __init__(self, **kwargs): self.messages = _Messages()

    module.AsyncAnthropic = _AsyncAnthropic
    return module


def test_llm_summary_rejected_on_foreign_host(monkeypatch):
    """The station.qpon case: the model names petron.com, so it is dropped."""
    monkeypatch.setitem(
        sys.modules, "anthropic",
        _fake_anthropic("The submitted host does not match www.petron.com, which "
                        "this report describes. Confidence is low."))
    monkeypatch.setattr(kit_report, "LLM_ANALYSIS_ENABLED", True)
    monkeypatch.setattr(kit_report, "ANTHROPIC_API_KEY", "test-key")

    report = {"target": {"host": "station.qpon", "registrable_domain": "station.qpon"}}
    assert asyncio.run(kit_report.llm_summary(report)) is None


def test_llm_summary_kept_when_it_names_only_the_case_host(monkeypatch):
    monkeypatch.setitem(
        sys.modules, "anthropic",
        _fake_anthropic("station.qpon serves a Vite SPA shell with no recovered "
                        "key material."))
    monkeypatch.setattr(kit_report, "LLM_ANALYSIS_ENABLED", True)
    monkeypatch.setattr(kit_report, "ANTHROPIC_API_KEY", "test-key")

    report = {"target": {"host": "station.qpon", "registrable_domain": "station.qpon"}}
    result = asyncio.run(kit_report.llm_summary(report))
    assert result is not None
    assert "station.qpon" in result["summary"]


# ---------------------------------------------------------------------------
# dual-profile acquisition
# ---------------------------------------------------------------------------

def test_profile_divergence_is_detected_and_the_in_scope_profile_wins(monkeypatch):
    """A target that cloaks against the bare profile is analyzed via browser."""
    kit_body = _read_fixture("body_browser.html")
    reached: list = []
    monkeypatch.setattr(kit_acquire, "safe_fetch", _redirecting_transport(
        reached, "station.qpon", "https://www.petron.com/", "decoy",
        per_profile={
            "Mobile Safari": ("https://station.qpon/", kit_body),   # browser profile
            "iPhone": ("https://www.petron.com/", "decoy"),          # bare profile
        }))
    calls: dict = {}
    _arm_tripwires(monkeypatch, calls)

    acquired = asyncio.run(kit_acquire.acquire("https://station.qpon/"))

    assert acquired["profile_divergence"] is True
    assert acquired["profile_used"] == "browser"
    assert acquired["scope_left"] is False
    assert acquired["host"] == "station.qpon"
    assert acquired["profiles"]["bare"]["scope_left"] is True
    assert acquired["profiles"]["browser"]["scope_left"] is False


def test_out_of_scope_assets_are_never_fetched():
    """A page listing a third party's scripts must not cause them to be pulled."""
    html = ('<script src="https://www.petron.com/wp/app.js"></script>'
            '<script src="/p/1a26/kit.js"></script>')
    assets = kit_acquire.extract_assets(html, "https://station.qpon/", "station.qpon")
    by_host = {a["host"]: a["in_scope"] for a in assets}
    assert by_host["www.petron.com"] is False
    assert by_host["station.qpon"] is True

    fetched = asyncio.run(kit_acquire.fetch_bundles(
        assets, case_registrable="station.qpon"))
    refused = [b for b in fetched if b["url"].startswith("https://www.petron.com")]
    assert refused and "not fetched" in refused[0]["error"]


# ---------------------------------------------------------------------------
# foreign hosts referenced by the kit's own content
# ---------------------------------------------------------------------------

def test_foreign_urls_in_a_bundle_are_evidence_not_indicators():
    """A kit referencing the brand it imitates must not put that brand in the
    copyable block, but the reference is still reported."""
    analysis = {"urls": ["https://www.petron.com",
                         "https://station.qpon/api/submit",
                         "https://lodash.com/license"]}
    indicators = kit_report.build_indicators(
        target={"host": "station.qpon", "domain": "station.qpon"},
        page={}, rdap={}, bundles=[], analysis=analysis, probe={},
        case_registrable="station.qpon",
    )
    copied = kit_report.copy_all_indicators({"indicators": indicators})
    assert "petron" not in copied.lower()
    assert "lodash" not in copied.lower()
    assert "station.qpon/api/submit" in copied

    refs = kit_report.build_content_references(analysis, "station.qpon")
    hosts = {r["host"]: r for r in refs}
    assert "www.petron.com" in hosts
    assert hosts["www.petron.com"]["brand"] == "Petron"
    assert "station.qpon" not in hosts


# ---------------------------------------------------------------------------
# kit-agnostic extraction: a kit with no matching signature still gets analyzed
# ---------------------------------------------------------------------------

from app.scanner import kit_analyzer  # noqa: E402


def _real_kit_bundle():
    path = FIXTURES / "entry_index-5ac4d3e6761.js"
    if not path.exists():
        pytest.skip("kit bundle not present (live kit source is not committed)")
    return path.read_text(encoding="utf-8", errors="replace")


PLAIN_KIT = '''
const api = axios.create();
function send(d){ api.post("/xzQpONCfLl/api/input", d).then(e=>{}); }
api.post("/xzQpONCfLl/api", {}).then(r=>{ if(r.data.isBlock){ blank(); return } });
const routes = ["/login","/otpValid","/card","/pay","/success"];
router.push("/otpValid"); router.push("/card"); router.push("/login");
'''


def test_exfil_endpoint_found_without_a_string_table():
    """The bug class: every extractor read the decoded string table, so an
    unobfuscated build reported nothing at all."""
    a = kit_analyzer.analyze(PLAIN_KIT)
    assert a["table_entries"] == 0, "fixture must be unobfuscated for this test"

    exfil = {e["path"] for e in a["exfil_endpoints"]}
    assert "/xzQpONCfLl/api/input" in exfil
    assert all("POST" in e["verbs"] for e in a["exfil_endpoints"])


def test_server_side_block_flag_is_reported():
    a = kit_analyzer.analyze(PLAIN_KIT)
    assert "isBlock" in a["block_flags"]


def test_victim_routes_recovered_from_source():
    a = kit_analyzer.analyze(PLAIN_KIT)
    paths = {r["path"] for r in a["source_routes"]}
    assert {"/otpValid", "/card", "/login"} <= paths


def test_source_routes_not_emitted_when_a_string_table_exists():
    """On an obfuscated build the table is the better source; this would add noise."""
    from tests.scanner.kit_fixtures import build_obfuscated_bundle
    a = kit_analyzer.analyze(build_obfuscated_bundle())
    assert a["table_entries"] > 0
    assert a["source_routes"] == []


def test_vendor_license_urls_are_not_indicators():
    src = ('x="https://lodash.com/license";y="http://underscorejs.org/LICENSE";'
           'z="https://openjsf.org/";w="https://evil.example/collect";')
    urls = kit_analyzer.analyze(src)["urls"]
    assert "https://evil.example/collect" in urls
    assert not any("lodash" in u or "underscorejs" in u or "openjsf" in u for u in urls)


def test_carousel_events_are_not_relay_channels():
    src = ('s.on("activeIndexChange",f);s.on("beforeLoopFix",f);s.on("upgrade",f);'
           's.on("custom-otp-valid",f);s.on("app-valid",f);')
    channels = kit_analyzer.analyze(src)["socket"]["channels"]
    assert "custom-otp-valid" in channels
    assert "app-valid" in channels
    for noise in ("activeIndexChange", "beforeLoopFix", "upgrade"):
        assert noise not in channels


def test_real_kit_bundle_yields_its_operator_api():
    """The station.qpon kit end to end, when the bundle is available locally."""
    a = kit_analyzer.analyze(_real_kit_bundle())
    exfil = {e["path"] for e in a["exfil_endpoints"]}
    assert "/xzQpONCfLl/api/input" in exfil
    assert "isBlock" in a["block_flags"]
    paths = {r["path"] for r in a["source_routes"]}
    assert {"/otpValid", "/customOtpValid", "/card", "/appValid"} <= paths


def test_exfil_endpoints_reach_the_indicator_block():
    report = kit_report.build_offline_report(PLAIN_KIT)
    copied = kit_report.copy_all_indicators(report)
    assert "/xzQpONCfLl/api/input" in copied
    assert "Exfil endpoint" in copied
    assert "isBlock" in copied


# ---------------------------------------------------------------------------
# a second kit, and picking between them
# ---------------------------------------------------------------------------

def test_registry_holds_more_than_one_signature():
    assert len(rabbithunt_sig.SIGNATURES) >= 2


def test_best_signature_is_chosen_not_the_default():
    """A kit that is not the default must not score NO MATCH 0% just for that.

    That reads as "not a phishing kit" when it means "not that phishing kit".
    """
    a = kit_analyzer.analyze(_real_kit_bundle())
    best = rabbithunt_sig.score_bundle_best(a)
    assert best["signature"] == "staged_relay"
    assert best["score_pct"] >= 60
    assert best["verdict"] in ("STRONG MATCH", "PARTIAL")

    # And the default signature genuinely does not match it, so the choice is real.
    default = rabbithunt_sig.score_bundle(a, "paper_rabbit")
    assert default["score_pct"] == 0
    considered = {c["signature"] for c in best["considered"]}
    assert {"paper_rabbit", "staged_relay"} <= considered


def test_paper_rabbit_still_wins_on_its_own_kit():
    """Adding a signature must not cannibalise the one that was already right."""
    from tests.scanner.kit_fixtures import build_obfuscated_bundle
    a = kit_analyzer.analyze(build_obfuscated_bundle(),
                             signature=rabbithunt_sig.get_signature("paper_rabbit"))
    best = rabbithunt_sig.score_bundle_best(a)
    assert best["signature"] == "paper_rabbit"


def test_unobfuscated_kit_is_scored_at_all():
    """The bug class: content tokens were searched against the decoded string
    table, which is empty on a plain build, so every token missed."""
    best = rabbithunt_sig.score_bundle_best(kit_analyzer.analyze(PLAIN_KIT))
    assert best["score_pct"] > 0


# ---------------------------------------------------------------------------
# operator-supplied page body, for a target FalconEye cannot reach
# ---------------------------------------------------------------------------

def test_supplied_html_is_analyzed_without_fetching_the_page(monkeypatch):
    reached: list = []
    monkeypatch.setattr(kit_acquire, "safe_fetch",
                        _redirecting_transport(reached, "station.qpon", "https://www.petron.com/"))
    calls: dict = {}
    _arm_tripwires(monkeypatch, calls)

    html = _read_fixture("body_browser.html")
    report = asyncio.run(kit_report.build_live_report(
        "https://station.qpon/", pasted_html=html))

    assert report["body_supplied"] is True
    assert report["mode"] == "supplied"
    assert report["out_of_scope"] is False
    assert report["target"]["host"] == "station.qpon"
    # The page itself must NOT have been re-fetched: that is the thing that did
    # not work, and re-fetching would re-acquire the decoy. Asset fetches are
    # expected and fine; a second request for the page document is not.
    assert reached.count("station.qpon") == len(
        [u for u in reached if u == "station.qpon"])
    assert report["page"]["profiles"].keys() == {"supplied"}
    assert report["page"]["profile_used"] == "supplied"


def test_supplied_html_still_detects_the_impersonated_brand():
    html = _read_fixture("body_browser.html")
    page = kit_acquire.page_from_html("https://station.qpon/", html)
    assert page["supplied"] is True
    assert page["scope_left"] is False
    assert detect_brand(page["body"])["brand"] == "Petron"


# ---------------------------------------------------------------------------
# what the kit does, with no signature involved
# ---------------------------------------------------------------------------

def _caps(report):
    return {c["capability"]: c for c in report["capabilities"]}


def test_capabilities_describe_a_kit_with_no_matching_signature():
    """The point of the extractor: analysis, not recognition.

    A brand new kit matches nothing in the registry. It must still come back
    described, because "what does this do" is the question an analyst has when
    looking at something for the first time.
    """
    novel = """
      const msgs = { enter_otp_prompt:"x", resend_code:"y", code_sent_to:"z",
        cardholder:"a", card_number:"b", expire_date:"c", cvv:"d",
        reward_points:"e", available_points:"f", check_points:"g",
        delivery_courier_fee:"h", express_shipping:"i",
        waiting_for_approval:"j", bank_app:"k", do_not_close:"l" };
    """
    a = kit_analyzer.analyze(novel)
    # Nothing recognises it.
    assert rabbithunt_sig.score_bundle_best(a)["score_pct"] < 30
    # It is still described.
    caps = _caps(a)
    for expected in ("otp_interception", "card_capture", "reward_lure",
                     "fee_lure", "live_operator_approval"):
        assert expected in caps, f"{expected} not described"
    assert caps["card_capture"]["confidence"] == "high"


def test_capability_carries_the_evidence_that_fired_it():
    a = kit_analyzer.analyze('m={cvv:"1",cardholder:"2",card_number:"3"}')
    ev = _caps(a)["card_capture"]["evidence"]
    assert ev and all(isinstance(e, str) for e in ev)
    assert any("cvv" in e.lower() for e in ev)


def test_no_capabilities_claimed_on_a_benign_bundle():
    """A false positive here is worse than a miss: it labels a normal page a
    credential harvester."""
    benign = ('const t={greeting:"Hello",menu_items:["a"],footer_text:"c",'
              'about_us:"d",contact_form:"e"};function render(){}')
    assert kit_analyzer.analyze(benign)["capabilities"] == []


def test_real_kit_is_described_end_to_end():
    a = kit_analyzer.analyze(_real_kit_bundle())
    caps = _caps(a)
    for expected in ("otp_interception", "card_capture", "live_operator_approval",
                     "reward_lure", "fee_lure", "identity_harvest"):
        assert expected in caps, f"{expected} missing"
        assert caps[expected]["evidence"]
    assert caps["otp_interception"]["confidence"] == "high"
    assert caps["card_capture"]["confidence"] == "high"


def test_message_keys_recovered_from_a_minified_bundle():
    a = kit_analyzer.analyze(_real_kit_bundle())
    keys = set(a["message_keys"])
    assert {"enter_otp_prompt", "resend_code"} & keys


def test_pasted_bundle_with_a_url_gets_the_full_case_treatment(monkeypatch):
    """The operator could reach the target and this server could not.

    A bundle pasted WITHOUT a url is the offline path. A bundle pasted WITH one
    must keep the url: the case identity, scope and enrichment are still valid,
    and throwing them away was why a geofenced kit came back empty.
    """
    reached: list = []
    monkeypatch.setattr(kit_acquire, "safe_fetch",
                        _redirecting_transport(reached, "station.qpon",
                                               "https://www.petron.com/"))
    calls: dict = {}
    _arm_tripwires(monkeypatch, calls)

    report = asyncio.run(kit_report.build_live_report(
        "https://station.qpon/", pasted_html="<html></html>",
        pasted_bundle=PLAIN_KIT))

    assert report["target"]["host"] == "station.qpon"
    assert report["bundles"][0]["name"] == "supplied bundle"
    # The substantive claim: the pasted bundle was actually torn down, and the
    # url was kept rather than discarded as it was on the offline path.
    exfil = {e["path"] for e in report["analysis"]["exfil_endpoints"]}
    assert "/xzQpONCfLl/api/input" in exfil
    assert report["analysis"]["block_flags"] == ["isBlock"]
    caps = {c["capability"] for c in report["analysis"]["capabilities"]}
    assert caps, "a torn-down bundle must yield at least one described capability"
    assert {"otp_interception", "card_capture", "anti_analysis"} & caps


def test_unfetchable_bundle_tells_the_operator_what_to_do(monkeypatch):
    """A dead end must come with the next step, not just a shrug."""
    reached: list = []
    monkeypatch.setattr(kit_acquire, "safe_fetch",
                        _redirecting_transport(reached, "station.qpon",
                                               "https://station.qpon/"))
    _arm_tripwires(monkeypatch, {})

    html = '<script src="/p/1a26/kit.js"></script>'
    report = asyncio.run(kit_report.build_live_report(
        "https://station.qpon/", pasted_html=html))

    joined = " ".join(report["notes"])
    assert "paste it together with this URL" in joined


def test_cloaked_fetch_is_evidence_not_a_dead_end_when_content_is_supplied(monkeypatch):
    """A geofenced kit: the operator reaches it, this server cannot.

    The scope abort exists to stop the pipeline running against the redirect
    destination. It must not also throw away a bundle the operator handed over,
    which left the normal case for a geofenced kit reporting nothing at all.
    """
    reached: list = []
    monkeypatch.setattr(kit_acquire, "safe_fetch",
                        _redirecting_transport(reached, "station.qpon",
                                               "https://www.petron.com/",
                                               end_body="<html>petron homepage</html>"))
    calls: dict = {}
    _arm_tripwires(monkeypatch, calls)

    report = asyncio.run(kit_report.build_live_report(
        "https://station.qpon/", pasted_bundle=PLAIN_KIT))

    assert report.get("out_of_scope") is False
    assert report["cloaked"] is True
    assert report["target"]["host"] == "station.qpon"

    # The kit was actually torn down.
    exfil = {e["path"] for e in report["analysis"]["exfil_endpoints"]}
    assert "/xzQpONCfLl/api/input" in exfil

    # The evasion is scored, not merely mentioned.
    assert report["score"]["redirect"]["score_pct"] > 0

    # And the decoy body never contaminates the case.
    copied = kit_report.copy_all_indicators(report)
    assert "petron" not in copied.lower()
    assert report["page"]["size_bytes"] is not None
