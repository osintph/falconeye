"""Refresh (cache bypass), and the single source-of-truth for the source list.

Refresh exists because a self-hoster added API keys and kept being served the
answer computed before those keys existed, twice in one day. The 6 hour cache is
correct for ordinary use; what was missing was a way to say "ask again now".

The source list exists because the page disagreed with itself: the IP tab intro
named five sources, the in-tab privacy note named nine, the home feature card
said "Shodan and GreyNoise", and the privacy policy table named nine in another
order. A visitor could not tell where their IP was actually sent.
"""
import inspect
import re

import pytest

from app import config
from app.ip_sources import catalog, reputation
from app.main import render_index
from app.routers import domain_intel, email_header, ip_intel

INDEX = "app/static/index.html"


def _render():
    with open(INDEX, encoding="utf-8") as f:
        return render_index(f.read())


# ---------- refresh ----------

@pytest.mark.parametrize("func", [ip_intel.lookup_ip, domain_intel.lookup_domain])
def test_lookup_endpoints_accept_a_refresh_flag(func):
    params = inspect.signature(func).parameters
    assert "refresh" in params, f"{func.__name__} has no refresh parameter"
    assert params["refresh"].default is False, "refresh must be opt-in"


def test_email_analyze_accepts_a_refresh_flag():
    assert "refresh" in email_header.HeaderAnalyzeRequest.model_fields
    assert email_header.HeaderAnalyzeRequest(raw_header="x").refresh is False


@pytest.mark.parametrize("module,needle", [
    (ip_intel, "None if refresh else get_cached"),
    (domain_intel, "None if refresh else get_cached"),
])
def test_refresh_bypasses_the_cache_read(module, needle):
    src = inspect.getsource(module)
    assert needle in src, (
        f"{module.__name__} does not bypass its cache on refresh, so Refresh "
        "would return the same cached row it is meant to replace."
    )


def test_email_refresh_bypasses_the_cache_read():
    src = inspect.getsource(email_header)
    assert 'getattr(req, "refresh", False)' in src


@pytest.mark.parametrize("func", [ip_intel.lookup_ip, domain_intel.lookup_domain])
def test_refresh_is_still_rate_limited(func):
    """A refresh must cost a lookup, or it is a free way to spend source quota.

    Both paths go through the same decorated endpoint, so the limiter applies
    by construction. This asserts the decorator is still there.
    """
    assert hasattr(func, "__wrapped__") or getattr(func, "__name__", ""), func
    src = inspect.getsource(inspect.getmodule(func))
    pattern = rf"@limiter\.limit\([^)]*\)\s*\nasync def {func.__name__}\b"
    assert re.search(pattern, src), (
        f"{func.__name__} lost its rate limit decorator, so Refresh would be "
        "unmetered against the upstream sources."
    )


def test_the_frontend_offers_refresh_on_all_three_cards():
    js = open("app/static/app.js", encoding="utf-8").read()
    for kind in ("ip", "domain", "email"):
        assert f'data-refresh-kind="{kind}"' in js, f"no Refresh control for {kind}"
    assert "_feRefreshOnce" in js and "refresh=1" in js


# ---------- the source list ----------

def test_catalog_has_the_five_verdict_sources_and_matches_reputation():
    assert len(catalog.REPUTATION_SOURCES) == 5
    assert [s["key"] for s in catalog.REPUTATION_SOURCES] == reputation._NAMES, (
        "the catalog and the consensus source list have drifted"
    )


def test_tab_copy_and_privacy_policy_are_rendered_from_the_catalog():
    """The two lists disagreed (five versus nine). They cannot now."""
    out = _render()
    five = catalog.reputation_labels()
    nine = catalog.all_labels()

    assert five in out, f"the tab intro does not list the verdict sources: {five}"
    assert nine in out, f"the privacy copy does not list every upstream: {nine}"

    # Both strings are present more than nowhere, and neither is a stale literal.
    assert out.count(five) >= 1 and out.count(nine) >= 2, (
        "expected the full list in both the in-tab privacy note and the "
        "privacy policy table"
    )


def test_no_hand_written_source_list_survives_in_the_page():
    """A literal list is how the two drifted apart in the first place."""
    raw = open(INDEX, encoding="utf-8").read()
    stale = [
        "AbuseIPDB, VirusTotal, OTX, Censys, ThreatFox",
        "AbuseIPDB, VirusTotal, AlienVault OTX, Censys, and ThreatFox, plus Shodan",
        "IP reputation with Shodan and GreyNoise",
    ]
    found = [f for f in stale if f in raw]
    assert not found, (
        "hand-written source lists are back in index.html: "
        f"{found}. Render them from app/ip_sources/catalog.py instead."
    )


def test_adding_a_source_changes_both_rendered_lists(monkeypatch):
    extra = {"key": "newsrc", "label": "NewSource", "env": None}
    monkeypatch.setattr(catalog, "SUPPORTING_SOURCES",
                        catalog.SUPPORTING_SOURCES + (extra,))
    monkeypatch.setattr(catalog, "ALL_SOURCES",
                        catalog.REPUTATION_SOURCES + catalog.SUPPORTING_SOURCES)
    assert "NewSource" in catalog.all_labels()
    assert "NewSource" in _render(), "the page did not pick up a new source"


# ---------- AbuseIPDB score visibility ----------

def _sources(**over):
    base = {
        "abuseipdb": {"source": "abuseipdb", "ok": True, "state": "ok",
                      "data": {"confidence": 0, "total_reports": 0}, "error": None},
        "virustotal": {"source": "virustotal", "ok": True, "state": "ok",
                       "data": {"malicious": 0}, "error": None},
        "otx": {"source": "otx", "ok": True, "state": "ok",
                "data": {"pulse_count": 0}, "error": None},
        "censys": {"source": "censys", "ok": True, "state": "ok", "data": {}, "error": None},
        "threatfox": {"source": "threatfox", "ok": True, "state": "ok",
                      "data": {"matched": False}, "error": None},
    }
    base.update(over)
    return base


def test_a_subthreshold_abuseipdb_score_is_still_shown():
    """The reported case: 24% over 8 reports rendered as a bare CLEAN."""
    v = reputation.compute_verdict(_sources(abuseipdb={
        "source": "abuseipdb", "ok": True, "state": "ok", "error": None,
        "data": {"confidence": 24, "total_reports": 8, "categories": ["SSH"]},
    }))
    # The cutoff is deliberately unchanged, so the verdict is still CLEAN.
    assert v["verdict"] == reputation.CLEAN
    assert reputation.ABUSEIPDB_SUSPICIOUS == 25

    # But the evidence is on the card now.
    values = {(s["label"], s["value"]) for s in v["signals"]}
    assert ("Abuse confidence", "24%") in values
    assert ("Reports", "8") in values


def test_zero_scores_produce_no_signals():
    assert reputation.compute_verdict(_sources())["signals"] == []


def test_signals_appear_for_every_verdict_including_malicious():
    v = reputation.compute_verdict(_sources(abuseipdb={
        "source": "abuseipdb", "ok": True, "state": "ok", "error": None,
        "data": {"confidence": 95, "total_reports": 300},
    }))
    assert v["verdict"] == reputation.MALICIOUS
    assert any(s["value"] == "95%" for s in v["signals"])


def test_an_unavailable_source_contributes_no_signal():
    v = reputation.compute_verdict(_sources(abuseipdb={
        "source": "abuseipdb", "ok": False, "state": "quota", "error": "quota",
        "data": {"confidence": 99, "total_reports": 500},
    }))
    assert v["signals"] == [], "a payload from a failed source must not be shown"


def test_the_card_renders_signals():
    js = open("app/static/app.js", encoding="utf-8").read()
    assert "vd.signals" in js, "the verdict card does not render the signals"
