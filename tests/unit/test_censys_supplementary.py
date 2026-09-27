"""Censys is enrichment, not a vote, and an exhausted credit balance is not an error.

Two separate problems, both of which made the IP card read wrong:

1. Censys sat in the consensus. Its host lookup costs one Censys credit per call
   and the free allowance is 100 credits a month, so on a public instance it is
   the first source to go quiet, and when it did the verdict dropped to
   INCOMPLETE and the card said "4 of 5 reputation sources responded". Censys
   contributes ports and services, never a reputation signal: nothing in
   compute_verdict ever read a Censys field. An absent port scan was being
   reported as missing threat intelligence.

2. An exhausted balance answers HTTP 422, which fell through to the generic
   "HTTP 422" branch and rendered as a red error on the sub-card. Running out of
   a monthly allowance is an expected operating state of the free tier, not a
   fault to investigate.

The tests below fix the boundary in both directions: Censys can be absent,
exhausted, unconfigured or switched off without touching the verdict, and the
four unmetered sources are what CLEAN is computed over.
"""
import os

os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import pytest

from app.ip_sources import catalog, censys, reputation
from app.ip_sources.base import (
    DISABLED,
    ERROR,
    NO_CREDITS,
    NO_KEY,
    NOT_FOUND,
    OK,
    QUOTA,
    SourceResult,
)

VERDICT_SOURCES = ("abuseipdb", "virustotal", "otx", "threatfox")


def _src(name, *, ok=True, state=OK, data=None, error=None, country=None):
    return SourceResult(name, ok, state, data or {}, error, country).as_dict()


def _all_quiet(**over):
    """Every verdict source answered, none of them flagged anything."""
    sources = {
        "abuseipdb": _src("abuseipdb", data={"confidence": 0, "total_reports": 0}),
        "virustotal": _src("virustotal", data={"malicious": 0}),
        "otx": _src("otx", data={"pulse_count": 0}),
        "threatfox": _src("threatfox", data={"matched": False}),
        "censys": _src("censys", data={"ports": []}),
    }
    sources.update(over)
    return sources


# ---------- 1. Censys is out of the consensus ----------

def test_the_verdict_is_computed_over_the_four_unmetered_sources():
    v = reputation.compute_verdict(_all_quiet())
    assert v["sources_total"] == 4
    assert v["sources_responded"] == 4
    assert v["verdict"] == reputation.CLEAN
    assert "4 of 4" in v["coverage_note"]


def test_the_coverage_note_never_counts_censys():
    """Censys answering must not inflate the count either."""
    v = reputation.compute_verdict(_all_quiet())
    assert "5" not in v["coverage_note"], v["coverage_note"]


@pytest.mark.parametrize("state,error", [
    (ERROR, "ConnectTimeout"),
    (QUOTA, "rate limit reached"),
    (NO_CREDITS, "monthly credits exhausted"),
    (NO_KEY, "no PAT configured"),
    (DISABLED, "CENSYS_ENABLED is not set"),
])
def test_censys_being_unavailable_never_makes_a_verdict_incomplete(state, error):
    sources = _all_quiet(censys=_src("censys", ok=False, state=state, error=error))
    v = reputation.compute_verdict(sources)
    assert v["verdict"] == reputation.CLEAN, (
        f"Censys in state {state!r} downgraded the verdict. Censys is enrichment; "
        "it has never contributed a reputation signal."
    )
    assert v["sources_responded"] == 4
    assert "censys" not in {u["source"] for u in v["sources_unavailable"]}


def test_censys_missing_entirely_is_not_an_unavailable_source():
    """A lookup that never asked Censys at all must read exactly the same."""
    sources = _all_quiet()
    del sources["censys"]
    v = reputation.compute_verdict(sources)
    assert v["verdict"] == reputation.CLEAN
    assert v["sources_total"] == 4 and v["sources_responded"] == 4
    assert v["sources_unavailable"] == []


def test_clean_is_all_of_the_unmetered_sources_responding():
    """The CLEAN guarantee from v3.33.2 still holds over the smaller set."""
    for name in VERDICT_SOURCES:
        sources = _all_quiet(**{name: _src(name, ok=False, state=ERROR, error="down")})
        v = reputation.compute_verdict(sources)
        assert v["verdict"] == reputation.INCOMPLETE, (
            f"{name} was down and the verdict was still {v['verdict']}"
        )
        assert v["sources_responded"] == 3
        assert "3 of 4" in v["coverage_note"]


def test_censys_still_contributes_ports_and_geo():
    """Dropping it from the vote must not drop the enrichment it exists for."""
    sources = _all_quiet(censys=_src(
        "censys",
        data={"ports": [{"port": 22, "service": "SSH"}], "asn_country": "RS"},
        country="LT",
    ))
    block = reputation.assemble(sources, shodan_ports=[80])
    ports = {p["port"] for p in block["ports"]["ports"]}
    assert ports == {22, 80}
    assert "Censys" in block["ports"]["consulted"]
    assert set(block["geo"]["countries"]) == {"LT", "RS"}


def test_censys_is_not_in_the_verdict_source_list():
    assert "censys" not in reputation._NAMES
    assert list(reputation._NAMES) == list(VERDICT_SOURCES)
    assert "censys" in reputation.ENRICHMENT_NAMES


def test_configured_sources_counts_four_and_ignores_censys(monkeypatch):
    for env in ("ABUSEIPDB_KEY", "VT_KEY", "OTX_API_KEY", "ABUSECH_AUTH_KEY", "CENSYS_PAT"):
        monkeypatch.delenv(env, raising=False)
    cfg = reputation.configured_sources()
    assert cfg["total"] == 4
    assert {m["env"] for m in cfg["missing"]} == {
        "ABUSEIPDB_KEY", "VT_KEY", "OTX_API_KEY", "ABUSECH_AUTH_KEY"}
    assert "CENSYS_PAT" not in {m["env"] for m in cfg["missing"]}


def test_configured_sources_publishes_the_labels_the_page_renders(monkeypatch):
    """The pre-lookup notice named the five sources as a literal in app.js."""
    cfg = reputation.configured_sources()
    assert cfg["labels"] == catalog.reputation_labels()
    assert "Censys" not in cfg["labels"]


# ---------- the catalog moved it too ----------

def test_catalog_lists_censys_as_supporting_not_reputation():
    rep_keys = [s["key"] for s in catalog.REPUTATION_SOURCES]
    sup_keys = [s["key"] for s in catalog.SUPPORTING_SOURCES]
    assert rep_keys == list(VERDICT_SOURCES)
    assert "censys" in sup_keys
    assert rep_keys == list(reputation._NAMES), "catalog and consensus have drifted"


def test_the_privacy_copy_still_names_censys_while_it_is_enabled(monkeypatch):
    """Moving it out of the vote does not stop us sending the IP there."""
    monkeypatch.setattr(catalog.config, "CENSYS_ENABLED", True)
    assert "Censys" in catalog.all_labels()
    assert "Censys" not in catalog.reputation_labels()


def test_the_privacy_copy_drops_censys_when_it_is_switched_off(monkeypatch):
    """A disabled source is one the visitor's IP is never sent to, so the note
    must not claim otherwise."""
    monkeypatch.setattr(catalog.config, "CENSYS_ENABLED", False)
    assert "Censys" not in catalog.all_labels()


# ---------- 2. HTTP 422 insufficient balance ----------

class FakeResp:
    def __init__(self, status, payload=None, text=""):
        self.status_code = status
        self._payload = payload
        self.text = text or ""

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeClient:
    def __init__(self, resp=None):
        self._resp = resp

    async def get(self, url, **kw):
        return self._resp


def _run(coro):
    import asyncio
    return asyncio.new_event_loop().run_until_complete(coro)


@pytest.fixture(autouse=True)
def _censys_on(monkeypatch):
    monkeypatch.setattr(censys.config, "CENSYS_ENABLED", True)
    monkeypatch.setenv("CENSYS_PAT", "pat-not-real")
    monkeypatch.delenv("CENSYS_ORG_ID", raising=False)


@pytest.mark.parametrize("body", [
    {"error": "insufficient balance"},
    {"message": "Insufficient balance to perform this action"},
    {"code": 422, "error": {"message": "insufficient credit balance"}},
])
def test_422_insufficient_balance_is_a_credit_state_not_an_error(body):
    r = _run(censys.fetch("1.2.3.4", FakeClient(FakeResp(422, body, text=str(body)))))
    assert r.state == NO_CREDITS, (
        "an exhausted monthly credit balance rendered as a red error; it is an "
        "expected state of the free tier"
    )
    assert r.ok is False
    assert "credit" in (r.error or "").lower()


def test_a_422_that_is_not_about_credits_is_still_an_error():
    """The other 422 we have seen is a bad organization id. Do not paper over it."""
    r = _run(censys.fetch("1.2.3.4", FakeClient(
        FakeResp(422, {"error": "organization_id is not a valid UUID"},
                 text="organization_id is not a valid UUID"))))
    assert r.state == ERROR
    assert "422" in (r.error or "")


def test_429_is_still_the_rate_limit_state():
    r = _run(censys.fetch("1.2.3.4", FakeClient(FakeResp(429, None, text=""))))
    assert r.state == QUOTA


def test_404_is_still_a_clean_miss():
    r = _run(censys.fetch("1.2.3.4", FakeClient(FakeResp(404, None))))
    assert r.ok and r.state == NOT_FOUND


# ---------- 3. CENSYS_ENABLED ----------

def test_censys_is_not_called_at_all_when_disabled(monkeypatch):
    monkeypatch.setattr(censys.config, "CENSYS_ENABLED", False)

    class Forbid(FakeClient):
        async def get(self, url, **kw):
            raise AssertionError("Censys was queried while disabled")

    r = _run(censys.fetch("1.2.3.4", Forbid()))
    assert r.state == DISABLED and r.ok is False


def test_disabled_censys_is_never_fetched_by_the_aggregator(monkeypatch):
    monkeypatch.setattr(reputation.config, "CENSYS_ENABLED", False)

    calls = []

    async def fake_fetch(ip, client):
        calls.append(ip)
        raise AssertionError("fetched a disabled source")

    monkeypatch.setattr(reputation._MODULES["censys"], "fetch", fake_fetch)
    for name in VERDICT_SOURCES:
        async def ok_fetch(ip, client, _n=name):
            return SourceResult(_n, True, OK, {}, None)
        monkeypatch.setattr(reputation._MODULES[name], "fetch", ok_fetch)

    sources = _run(reputation.fetch_sources("1.2.3.4", FakeClient()))
    assert calls == []
    assert sources["censys"]["state"] == DISABLED
    # And it is still in the dict, so the card can say why it is silent.
    assert set(sources) == set(VERDICT_SOURCES) | {"censys"}


def test_the_default_is_off():
    """Off by default: the call costs the operator a Censys credit."""
    from app.utils.env import getenv_clean
    import inspect

    from app import config
    src = inspect.getsource(config)
    assert 'CENSYS_ENABLED' in src
    assert 'getenv_clean("CENSYS_ENABLED", "false")' in src, (
        "CENSYS_ENABLED must default to false: each lookup spends a credit"
    )


def test_env_example_documents_the_flag_and_the_credit_cost():
    text = open(".env.example", encoding="utf-8").read()
    assert "CENSYS_ENABLED=false" in text
    lowered = text.lower()
    assert "credit" in lowered
    assert "100 credits" in lowered, "the monthly allowance is the whole point of the flag"


def test_the_docstring_states_what_the_platform_api_actually_costs():
    """It claimed the free tier included host lookup, full stop."""
    doc = censys.__doc__ or ""
    lowered = doc.lower()
    assert "credit" in lowered
    assert "100" in doc, "the monthly allowance belongs in the docstring"
    # And the claim that got this wrong must be gone.
    assert "free tier includes host lookup" not in lowered


# ---------- what the page renders ----------

def _js():
    return open("app/static/app.js", encoding="utf-8").read()


def test_censys_has_no_sub_card_among_the_verdict_sources():
    js = _js()
    assert "_repCard('Censys'" not in js, (
        "Censys still has a sub-card next to the four that vote, which is what "
        "made an absent port scan look like missing threat intelligence"
    )
    assert "_repCensys" not in js, "dead renderer left behind"


def test_the_ports_card_carries_the_censys_note():
    js = _js()
    assert "censysNote(" in js
    assert "Censys: monthly credits exhausted" in js


def test_the_pre_lookup_notice_is_rendered_from_the_config():
    """A literal list in app.js is how the page disagreed with itself before."""
    js = _js()
    assert "cfg.labels" in js
    assert "AbuseIPDB, VirusTotal, AlienVault OTX, Censys and ThreatFox" not in js


def test_the_pdf_does_not_present_censys_as_a_verdict_source():
    js = _js()
    assert "Censys (enrichment, not part of the verdict)" in js
