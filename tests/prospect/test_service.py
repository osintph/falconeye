"""
Tests for build_dossier(), _fetch_news(), and _filter_jobs().

Engine functions are mocked with real fixtures captured from SearchAPI.
Uses asyncio.run() (no pytest-asyncio required).

Key structural notes for v3.3.1:
  - about_domain is called first (sequential) to drive identity resolution.
  - Wave 1 runs ads_transparency, meta_page_search, _fetch_news, optional google_jobs.
  - Wave 2 runs ads_historical and meta_ads.
  - Jobs call is skipped when identity.confidence == "low".
  - News results are filtered; retry triggered when drop rate >60%.
"""
import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# ---------------------------------------------------------------------------
# Helper: build a patch context for all engines
# ---------------------------------------------------------------------------

def _patch_all(**overrides):
    """Return a dict of engine name -> mock. Overrides replace defaults."""
    defaults = {
        "about_domain": AsyncMock(return_value=_load("about_domain_stripe_com.json")),
        "ads_transparency": AsyncMock(return_value=_load("ads_transparency_stripe.json")),
        "ads_transparency_historical": AsyncMock(return_value=_load("ads_transparency_advertiser_stripe.json")),
        "meta_page_search": AsyncMock(return_value=_load("meta_page_search_stripe.json")),
        "meta_ads": AsyncMock(return_value=_load("meta_ads_stripe.json")),
        "google_news_search": AsyncMock(return_value=_load("news_stripe.json")),
        "google_jobs_search": AsyncMock(return_value=_load("jobs_stripe.json")),
    }
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# Full happy path
# ---------------------------------------------------------------------------

def test_build_dossier_all_succeed():
    """All 7 engine calls succeed: sections populated, no errors, derived present."""
    mocks = _patch_all()

    async def _run():
        with patch("app.prospect.service.about_domain", mocks["about_domain"]), \
             patch("app.prospect.service.ads_transparency", mocks["ads_transparency"]), \
             patch("app.prospect.service.ads_transparency_historical", mocks["ads_transparency_historical"]), \
             patch("app.prospect.service.meta_page_search", mocks["meta_page_search"]), \
             patch("app.prospect.service.meta_ads", mocks["meta_ads"]), \
             patch("app.prospect.service.google_news_search", mocks["google_news_search"]), \
             patch("app.prospect.service.google_jobs_search", mocks["google_jobs_search"]):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    result = asyncio.run(_run())

    assert result["domain"] == "stripe.com"
    assert result["errors"] == []
    assert result["generated_at"]

    # Derived identity present
    derived = result["derived"]
    assert derived["confidence"] == "high"
    assert derived["source"] == "knowledge_graph"
    assert "stripe" in derived["canonical_name"].lower()
    assert "stripe" in derived["company_name"].lower()

    # All 7 sections present
    s = result["sections"]
    assert s["about_domain"] is not None
    assert s["ads_transparency"] is not None
    assert s["ads_transparency_historical"] is not None
    assert s["meta_page_search"] is not None
    assert s["meta_ads"] is not None
    assert s["google_news"] is not None
    assert s["google_jobs"] is not None


# ---------------------------------------------------------------------------
# Wave 2 chains from wave 1
# ---------------------------------------------------------------------------

def test_wave2_uses_advertiser_id_from_ads30d():
    """ads_historical is called with the advertiser_id from the 30-day response."""
    captured_id = []

    async def mock_ads_hist(client, advertiser_id):
        captured_id.append(advertiser_id)
        return {}

    mocks = _patch_all(ads_transparency_historical=mock_ads_hist)

    async def _run():
        with patch("app.prospect.service.about_domain", mocks["about_domain"]), \
             patch("app.prospect.service.ads_transparency", mocks["ads_transparency"]), \
             patch("app.prospect.service.ads_transparency_historical", mock_ads_hist), \
             patch("app.prospect.service.meta_page_search", mocks["meta_page_search"]), \
             patch("app.prospect.service.meta_ads", mocks["meta_ads"]), \
             patch("app.prospect.service.google_news_search", mocks["google_news_search"]), \
             patch("app.prospect.service.google_jobs_search", mocks["google_jobs_search"]):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    asyncio.run(_run())
    assert len(captured_id) == 1
    assert captured_id[0] == "AR16951989901585285121"


def test_wave2_uses_page_id_from_meta_search():
    """meta_ads is called with the page_id from the first meta_page_search result."""
    captured_page_id = []

    async def mock_meta_ads(client, page_id, **kwargs):
        captured_page_id.append(page_id)
        return {}

    mocks = _patch_all(meta_ads=mock_meta_ads)

    async def _run():
        with patch("app.prospect.service.about_domain", mocks["about_domain"]), \
             patch("app.prospect.service.ads_transparency", mocks["ads_transparency"]), \
             patch("app.prospect.service.ads_transparency_historical", mocks["ads_transparency_historical"]), \
             patch("app.prospect.service.meta_page_search", mocks["meta_page_search"]), \
             patch("app.prospect.service.meta_ads", mock_meta_ads), \
             patch("app.prospect.service.google_news_search", mocks["google_news_search"]), \
             patch("app.prospect.service.google_jobs_search", mocks["google_jobs_search"]):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    asyncio.run(_run())
    assert len(captured_page_id) == 1
    assert captured_page_id[0] == "175383762511776"


# ---------------------------------------------------------------------------
# Low-confidence domain: jobs skipped
# ---------------------------------------------------------------------------

def test_low_confidence_skips_jobs():
    """When about_domain returns no KG, identity is low-confidence and jobs are not called."""
    jobs_called = []

    async def mock_about(client, domain):
        return {}  # no KG -> low confidence

    async def mock_jobs(client, query):
        jobs_called.append(True)
        return {}

    async def mock_news(client, query, **kwargs):
        return {"organic_results": []}

    async def _run():
        with patch("app.prospect.service.about_domain", mock_about), \
             patch("app.prospect.service.ads_transparency", AsyncMock(return_value={"ad_creatives": []})), \
             patch("app.prospect.service.meta_page_search", AsyncMock(return_value={"page_results": []})), \
             patch("app.prospect.service.google_news_search", mock_news), \
             patch("app.prospect.service.google_jobs_search", mock_jobs), \
             patch("app.prospect.service.ads_transparency_historical", AsyncMock(return_value={})), \
             patch("app.prospect.service.meta_ads", AsyncMock(return_value={})):
            from app.prospect.service import build_dossier
            return await build_dossier("unknowndomain12345.tld")

    result = asyncio.run(_run())
    assert not jobs_called, "google_jobs_search must NOT be called for low-confidence identity"
    assert result["sections"]["google_jobs"] is None
    assert result["derived"]["confidence"] == "low"
    # No error for skipped jobs
    assert not any(e["section"] == "google_jobs" for e in result["errors"])


def test_low_confidence_uses_site_news_query():
    """When confidence is low, news query is site:{domain} not a quoted name."""
    captured_query = []

    async def mock_about(client, domain):
        return {}

    async def mock_news(client, query, **kwargs):
        captured_query.append(query)
        return {"organic_results": []}

    async def _run():
        with patch("app.prospect.service.about_domain", mock_about), \
             patch("app.prospect.service.ads_transparency", AsyncMock(return_value={"ad_creatives": []})), \
             patch("app.prospect.service.meta_page_search", AsyncMock(return_value={"page_results": []})), \
             patch("app.prospect.service.google_news_search", mock_news), \
             patch("app.prospect.service.google_jobs_search", AsyncMock(return_value={})), \
             patch("app.prospect.service.ads_transparency_historical", AsyncMock(return_value={})), \
             patch("app.prospect.service.meta_ads", AsyncMock(return_value={})):
            from app.prospect.service import build_dossier
            return await build_dossier("nondescript.io")

    asyncio.run(_run())
    assert len(captured_query) == 1
    assert "site:nondescript.io" in captured_query[0]
    # No quoted company name in a low-confidence query
    assert captured_query[0].startswith("site:")


def test_high_confidence_uses_quoted_news_query():
    """When confidence is high, news query is quoted canonical_name OR site:{domain}."""
    captured_query = []

    async def mock_news(client, query, **kwargs):
        captured_query.append(query)
        return {"organic_results": []}

    mocks = _patch_all(google_news_search=mock_news)

    async def _run():
        with patch("app.prospect.service.about_domain", mocks["about_domain"]), \
             patch("app.prospect.service.ads_transparency", mocks["ads_transparency"]), \
             patch("app.prospect.service.ads_transparency_historical", mocks["ads_transparency_historical"]), \
             patch("app.prospect.service.meta_page_search", mocks["meta_page_search"]), \
             patch("app.prospect.service.meta_ads", mocks["meta_ads"]), \
             patch("app.prospect.service.google_news_search", mock_news), \
             patch("app.prospect.service.google_jobs_search", mocks["google_jobs_search"]):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    asyncio.run(_run())
    # At least one news query was issued (may be 2 if retry triggered)
    assert len(captured_query) >= 1
    first_query = captured_query[0]
    assert '"' in first_query  # quoted canonical name
    assert "stripe" in first_query.lower()
    assert "site:stripe.com" in first_query


# ---------------------------------------------------------------------------
# News validation: drop unrelated articles
# ---------------------------------------------------------------------------

def test_news_drop_filter_removes_unrelated_articles():
    """Articles with none of the identity tokens are filtered out."""
    from app.prospect.resolver import CompanyIdentity

    identity = CompanyIdentity(
        display_name="Stripe, Inc.",
        canonical_name="Stripe, Inc.",
        aliases=["Stripe", "stripe"],
        confidence="high",
        source="knowledge_graph",
    )

    news_result = {
        "organic_results": [
            {"title": "Stripe raises new funding round", "snippet": "Stripe the payments company announced..."},
            {"title": "Completely unrelated article about weather", "snippet": "Temperatures will rise this weekend"},
            {"title": "Stripe announces new developer tools", "snippet": "Stripe API improvements launched today"},
        ]
    }

    async def mock_news(client, query, **kwargs):
        return news_result

    async def _run():
        from app.prospect.service import _fetch_news
        client = object()  # not used, mock intercepts
        with patch("app.prospect.service.google_news_search", mock_news):
            return await _fetch_news(client, '"Stripe, Inc." OR site:stripe.com', "stripe.com", identity)

    result = asyncio.run(_run())
    articles = result.get("organic_results", [])
    # Weather article must be dropped
    titles = [a["title"] for a in articles]
    assert "Completely unrelated article about weather" not in titles
    # Stripe articles must be kept
    assert any("Stripe" in t for t in titles)


def test_news_retry_on_high_drop_rate():
    """When >60% of articles are dropped, a stricter query is retried."""
    from app.prospect.resolver import CompanyIdentity

    identity = CompanyIdentity(
        display_name="Stripe, Inc.",
        canonical_name="Stripe, Inc.",
        aliases=["Stripe", "stripe"],
        confidence="high",
        source="knowledge_graph",
    )

    # 5 unrelated articles -> 100% drop rate -> retry
    unrelated = [
        {"title": f"Unrelated article {i}", "snippet": "nothing about payments"}
        for i in range(5)
    ]
    good_article = {"title": "Stripe the company launches feature", "snippet": "Stripe announced..."}

    call_count = []

    async def mock_news(client, query, **kwargs):
        call_count.append(query)
        if len(call_count) == 1:
            return {"organic_results": unrelated}  # first call: all bad
        return {"organic_results": [good_article]}  # retry: good result

    async def _run():
        from app.prospect.service import _fetch_news
        client = object()
        with patch("app.prospect.service.google_news_search", mock_news):
            return await _fetch_news(client, '"Stripe, Inc." OR site:stripe.com', "stripe.com", identity)

    result = asyncio.run(_run())
    # Retry was triggered
    assert len(call_count) == 2
    # Second query is the stricter site:-anchored form
    assert 'site:stripe.com' in call_count[1]
    assert '"Stripe, Inc."' in call_count[1]
    # Result contains the good article
    assert len(result.get("organic_results", [])) == 1


# ---------------------------------------------------------------------------
# Jobs fuzzy validation
# ---------------------------------------------------------------------------

def test_jobs_filter_keeps_matching_companies():
    from app.prospect.resolver import CompanyIdentity
    from unittest.mock import patch as _patch

    identity = CompanyIdentity(
        display_name="Stripe, Inc.",
        canonical_name="Stripe, Inc.",
        aliases=["Stripe", "stripe"],
        confidence="high",
        source="knowledge_graph",
    )

    jobs = [
        {"title": "Engineer", "company_name": "Stripe"},
        {"title": "Manager", "company_name": "Stripe, Inc."},
        {"title": "Analyst", "company_name": "Random Corp"},
        {"title": "Designer", "company_name": ""},
    ]

    # Patch _HAVE_RAPIDFUZZ True and use real rapidfuzz if available, else a mock ratio
    try:
        from rapidfuzz.fuzz import partial_ratio
        real_ratio = partial_ratio
    except ImportError:
        def real_ratio(a, b): return 100 if a == b else (90 if a in b or b in a else 10)

    with _patch("app.prospect.service._HAVE_RAPIDFUZZ", True), \
         _patch("app.prospect.service._partial_ratio", real_ratio):
        from app.prospect.service import _filter_jobs
        kept = _filter_jobs(jobs, identity, "stripe.com")

    company_names = [j["company_name"] for j in kept]
    assert "Stripe" in company_names
    assert "Stripe, Inc." in company_names
    assert "Random Corp" not in company_names


def test_jobs_filter_drops_mismatched_companies():
    from app.prospect.resolver import CompanyIdentity
    from unittest.mock import patch as _patch

    identity = CompanyIdentity(
        display_name="BP",
        canonical_name="BP p.l.c.",
        aliases=["BP", "bp"],
        confidence="high",
        source="knowledge_graph",
    )

    jobs = [
        {"title": "Engineer", "company_name": "BP"},
        {"title": "Analyst", "company_name": "British Petroleum Services"},
        {"title": "Dev", "company_name": "Random Tech Co"},
    ]

    try:
        from rapidfuzz.fuzz import partial_ratio
        real_ratio = partial_ratio
    except ImportError:
        def real_ratio(a, b): return 100 if a == b else (90 if a in b or b in a else 10)

    with _patch("app.prospect.service._HAVE_RAPIDFUZZ", True), \
         _patch("app.prospect.service._partial_ratio", real_ratio):
        from app.prospect.service import _filter_jobs
        kept = _filter_jobs(jobs, identity, "bp.com")

    company_names = [j["company_name"] for j in kept]
    assert "BP" in company_names
    assert "Random Tech Co" not in company_names


# ---------------------------------------------------------------------------
# Partial failures (wave 1 and wave 2)
# ---------------------------------------------------------------------------

def test_partial_failure_about_domain():
    """about_domain failure recorded in errors; identity falls back to domain root."""
    async def mock_about_fail(client, domain):
        raise RuntimeError("timeout")

    async def _run():
        with patch("app.prospect.service.about_domain", mock_about_fail), \
             patch("app.prospect.service.ads_transparency", AsyncMock(return_value={"ad_creatives": []})), \
             patch("app.prospect.service.meta_page_search", AsyncMock(return_value={"page_results": []})), \
             patch("app.prospect.service.google_news_search", AsyncMock(return_value={"organic_results": []})), \
             patch("app.prospect.service.google_jobs_search", AsyncMock(return_value={"jobs": []})), \
             patch("app.prospect.service.ads_transparency_historical", AsyncMock(return_value={})), \
             patch("app.prospect.service.meta_ads", AsyncMock(return_value={})):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    result = asyncio.run(_run())
    assert result["sections"]["about_domain"] is None
    errs = [e for e in result["errors"] if e["section"] == "about_domain"]
    assert len(errs) == 1
    assert "timeout" in errs[0]["message"]
    # Jobs still skipped (low confidence since about_domain failed)
    # Actually: no about_data -> low confidence -> jobs skipped
    assert result["derived"]["confidence"] == "low"


def test_partial_failure_wave1_engine():
    """A wave-1 engine failure sets its section to None and records an error."""
    mocks = _patch_all(
        ads_transparency=AsyncMock(side_effect=RuntimeError("429 rate limit"))
    )

    async def _run():
        with patch("app.prospect.service.about_domain", mocks["about_domain"]), \
             patch("app.prospect.service.ads_transparency", mocks["ads_transparency"]), \
             patch("app.prospect.service.ads_transparency_historical", mocks["ads_transparency_historical"]), \
             patch("app.prospect.service.meta_page_search", mocks["meta_page_search"]), \
             patch("app.prospect.service.meta_ads", mocks["meta_ads"]), \
             patch("app.prospect.service.google_news_search", mocks["google_news_search"]), \
             patch("app.prospect.service.google_jobs_search", mocks["google_jobs_search"]):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    result = asyncio.run(_run())
    assert result["sections"]["ads_transparency"] is None
    errs = [e for e in result["errors"] if e["section"] == "ads_transparency"]
    assert len(errs) == 1
    assert "429" in errs[0]["message"]


def test_all_wave1_engines_fail():
    """If all wave-1 engines fail, sections are null and errors list has 5 entries."""
    exc = RuntimeError("service down")
    mocks = _patch_all(
        ads_transparency=AsyncMock(side_effect=exc),
        meta_page_search=AsyncMock(side_effect=exc),
        google_news_search=AsyncMock(side_effect=exc),
        google_jobs_search=AsyncMock(side_effect=exc),
    )

    async def _run():
        with patch("app.prospect.service.about_domain", mocks["about_domain"]), \
             patch("app.prospect.service.ads_transparency", mocks["ads_transparency"]), \
             patch("app.prospect.service.ads_transparency_historical", mocks["ads_transparency_historical"]), \
             patch("app.prospect.service.meta_page_search", mocks["meta_page_search"]), \
             patch("app.prospect.service.meta_ads", mocks["meta_ads"]), \
             patch("app.prospect.service.google_news_search", mocks["google_news_search"]), \
             patch("app.prospect.service.google_jobs_search", mocks["google_jobs_search"]):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    result = asyncio.run(_run())

    for name in ["ads_transparency", "meta_page_search", "google_news"]:
        assert result["sections"][name] is None
    # Wave 2 skipped cleanly (no advertiser_id, no page_id)
    assert result["sections"]["ads_transparency_historical"] is None
    assert result["sections"]["meta_ads"] is None
    # about_domain succeeded, so no error for it
    assert all(e["section"] != "about_domain" for e in result["errors"])


# ---------------------------------------------------------------------------
# Meta page selection (Fix 1)
# ---------------------------------------------------------------------------

def test_meta_page_selection_rejects_bpi_for_bp():
    """BPI must not be selected as the Meta page for bp.com."""
    from app.prospect.resolver import resolve_identity, CompanyIdentity
    from app.prospect.service import _select_meta_page
    from unittest.mock import patch as _patch

    try:
        from rapidfuzz.fuzz import partial_ratio
        real_ratio = partial_ratio
    except ImportError:
        def real_ratio(a, b):
            a, b = a.lower(), b.lower()
            return 100 if a == b else (90 if a in b or b in a else 10)

    identity = resolve_identity("bp.com", _load("about_domain_bp_com.json"))

    pages = _load("meta_page_search_bp.json").get("page_results", [])
    with _patch("app.prospect.service._HAVE_RAPIDFUZZ", True), \
         _patch("app.prospect.service._partial_ratio", real_ratio):
        selected = _select_meta_page(pages, identity)

    assert selected is not None
    # Must not be BPI (Bank of the Philippine Islands)
    assert "bpi" not in (selected.get("name") or "").lower()
    # Must be an energy/oil company page
    assert "bp" in (selected.get("name") or "").lower()


def test_meta_page_selection_hp_picks_hp_not_harry_potter():
    """HP page must be selected for hp.com, not Harry Potter pages."""
    from app.prospect.resolver import resolve_identity
    from app.prospect.service import _select_meta_page
    from unittest.mock import patch as _patch

    try:
        from rapidfuzz.fuzz import partial_ratio
        real_ratio = partial_ratio
    except ImportError:
        def real_ratio(a, b):
            a, b = a.lower(), b.lower()
            return 100 if a == b else (90 if a in b or b in a else 10)

    identity = resolve_identity("hp.com", _load("about_domain_hp_com.json"))

    pages = _load("meta_page_search_hp.json").get("page_results", [])
    with _patch("app.prospect.service._HAVE_RAPIDFUZZ", True), \
         _patch("app.prospect.service._partial_ratio", real_ratio):
        selected = _select_meta_page(pages, identity)

    assert selected is not None
    name = (selected.get("name") or "").lower()
    assert "harry" not in name
    assert "potter" not in name
    assert "hp" in name


def test_meta_page_selection_returns_none_when_no_match():
    """When no pages match the identity, return None (no fallback to unfiltered)."""
    from app.prospect.resolver import CompanyIdentity
    from app.prospect.service import _select_meta_page
    from unittest.mock import patch as _patch

    identity = CompanyIdentity(
        display_name="XYZNONEXISTENTCO",
        canonical_name="XYZNONEXISTENTCO Inc.",
        aliases=["XYZNONEXISTENTCO"],
        confidence="high",
        source="knowledge_graph",
    )

    pages = [
        {"name": "Random Page A", "likes": 500000, "category": "Tech"},
        {"name": "Another Page B", "likes": 300000, "category": "Retail"},
    ]

    try:
        from rapidfuzz.fuzz import partial_ratio
        real_ratio = partial_ratio
    except ImportError:
        def real_ratio(a, b):
            a, b = a.lower(), b.lower()
            return 100 if a == b else (90 if a in b or b in a else 10)

    with _patch("app.prospect.service._HAVE_RAPIDFUZZ", True), \
         _patch("app.prospect.service._partial_ratio", real_ratio):
        selected = _select_meta_page(pages, identity)

    assert selected is None


# ---------------------------------------------------------------------------
# Multi-advertiser (Fix 3)
# ---------------------------------------------------------------------------

def test_multi_advertiser_enriches_ads_section():
    """When ads have multiple advertisers, _advertisers list is added to ads section."""
    multi_adv_creatives = [
        {"advertiser": {"id": "ADV001", "name": "HP Inc.", "location": "US"}, "format": "text"},
        {"advertiser": {"id": "ADV001", "name": "HP Inc.", "location": "US"}, "format": "image"},
        {"advertiser": {"id": "ADV002", "name": "HP International", "location": "CH"}, "format": "text"},
    ]

    mocks = _patch_all(
        ads_transparency=AsyncMock(return_value={"ad_creatives": multi_adv_creatives}),
        ads_transparency_historical=AsyncMock(return_value={"search_information": {}}),
    )

    async def _run():
        with patch("app.prospect.service.about_domain", mocks["about_domain"]), \
             patch("app.prospect.service.ads_transparency", mocks["ads_transparency"]), \
             patch("app.prospect.service.ads_transparency_historical", mocks["ads_transparency_historical"]), \
             patch("app.prospect.service.meta_page_search", mocks["meta_page_search"]), \
             patch("app.prospect.service.meta_ads", mocks["meta_ads"]), \
             patch("app.prospect.service.google_news_search", mocks["google_news_search"]), \
             patch("app.prospect.service.google_jobs_search", mocks["google_jobs_search"]):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    result = asyncio.run(_run())
    ads_sec = result["sections"]["ads_transparency"]
    assert ads_sec is not None
    advertisers = ads_sec.get("_advertisers", [])
    assert len(advertisers) == 2
    assert advertisers[0]["id"] == "ADV001"  # most ads first
    assert advertisers[0]["count"] == 2
    assert advertisers[1]["id"] == "ADV002"


def test_multi_advertiser_calls_historical_for_top3():
    """ads_historical is called once per unique advertiser (up to 3)."""
    captured_ids = []

    async def mock_hist(client, advertiser_id):
        captured_ids.append(advertiser_id)
        return {}

    creatives = []
    for i, (adv_id, n) in enumerate([("A1", 10), ("A2", 8), ("A3", 5), ("A4", 2)]):
        for _ in range(n):
            creatives.append({"advertiser": {"id": adv_id, "name": f"Adv{i}"}})

    mocks = _patch_all(
        ads_transparency=AsyncMock(return_value={"ad_creatives": creatives}),
        ads_transparency_historical=mock_hist,
    )

    async def _run():
        with patch("app.prospect.service.about_domain", mocks["about_domain"]), \
             patch("app.prospect.service.ads_transparency", mocks["ads_transparency"]), \
             patch("app.prospect.service.ads_transparency_historical", mock_hist), \
             patch("app.prospect.service.meta_page_search", mocks["meta_page_search"]), \
             patch("app.prospect.service.meta_ads", mocks["meta_ads"]), \
             patch("app.prospect.service.google_news_search", mocks["google_news_search"]), \
             patch("app.prospect.service.google_jobs_search", mocks["google_jobs_search"]):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    asyncio.run(_run())
    # Only top 3 advertisers get historical calls
    assert len(captured_ids) == 3
    assert set(captured_ids) == {"A1", "A2", "A3"}


def test_multi_advertiser_historical_stored_as_dict():
    """ads_transparency_historical section is a dict keyed by advertiser_id."""
    creatives = [
        {"advertiser": {"id": "ADV001", "name": "HP Inc."}},
        {"advertiser": {"id": "ADV002", "name": "HP International"}},
    ]

    async def mock_hist(client, advertiser_id):
        return {"search_information": {"total_results": 99, "based_in": "US"}}

    mocks = _patch_all(
        ads_transparency=AsyncMock(return_value={"ad_creatives": creatives}),
        ads_transparency_historical=mock_hist,
    )

    async def _run():
        with patch("app.prospect.service.about_domain", mocks["about_domain"]), \
             patch("app.prospect.service.ads_transparency", mocks["ads_transparency"]), \
             patch("app.prospect.service.ads_transparency_historical", mock_hist), \
             patch("app.prospect.service.meta_page_search", mocks["meta_page_search"]), \
             patch("app.prospect.service.meta_ads", mocks["meta_ads"]), \
             patch("app.prospect.service.google_news_search", mocks["google_news_search"]), \
             patch("app.prospect.service.google_jobs_search", mocks["google_jobs_search"]):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    result = asyncio.run(_run())
    hist = result["sections"]["ads_transparency_historical"]
    assert isinstance(hist, dict)
    assert "ADV001" in hist
    assert "ADV002" in hist
    assert hist["ADV001"]["search_information"]["total_results"] == 99


# ---------------------------------------------------------------------------
# hp.com: ai_overview resolver path
# ---------------------------------------------------------------------------

def test_hp_resolver_extracts_hewlett_packard():
    """hp.com with only ai_overview should resolve to Hewlett-Packard (medium confidence)."""
    from app.prospect.resolver import resolve_identity
    about = _load("about_domain_hp_com.json")
    identity = resolve_identity("hp.com", about)
    assert "hewlett" in identity.canonical_name.lower()
    assert identity.confidence == "medium"
    assert identity.source == "ai_overview"
    assert identity.display_name == "HP"
