"""
Tests for build_dossier() and derive_company_name().
Engine functions are mocked with fixtures captured from live SearchAPI responses.
Uses asyncio.run() — no pytest-asyncio required.
"""
import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# ---------------------------------------------------------------------------
# derive_company_name
# ---------------------------------------------------------------------------

def test_derive_company_name_from_knowledge_graph():
    from app.prospect.service import derive_company_name
    about = _load("about_domain_stripe.json")
    assert derive_company_name("stripe.com", about) == "Stripe, Inc."


def test_derive_company_name_fallback_to_domain_root():
    from app.prospect.service import derive_company_name
    assert derive_company_name("acme.io", None) == "Acme"
    assert derive_company_name("example.com", {}) == "Example"


def test_derive_company_name_about_this_result_fallback():
    from app.prospect.service import derive_company_name
    about_data = {"about_this_result": {"title": "ACME Corp."}}
    # No knowledge_graph, falls through to about_this_result
    name = derive_company_name("acme.com", about_data)
    # Suffix stripped by _SUFFIX_RE
    assert "ACME" in name


# ---------------------------------------------------------------------------
# Full happy path — all 7 sections succeed
# ---------------------------------------------------------------------------

def test_build_dossier_all_succeed():
    """All 7 engine calls succeed: all sections populated, errors empty, derived.company_name set."""
    about = _load("about_domain_stripe.json")
    ads30d = _load("ads_transparency_stripe.json")
    ads_hist = _load("ads_transparency_advertiser_stripe.json")
    meta_search = _load("meta_page_search_stripe.json")
    meta_ads = _load("meta_ads_stripe.json")
    news = _load("news_stripe.json")
    jobs = _load("jobs_stripe.json")

    async def mock_about(client, domain):
        return about

    async def mock_ads(client, domain, **kwargs):
        return ads30d

    async def mock_ads_hist(client, advertiser_id):
        return ads_hist

    async def mock_meta_search(client, query, **kwargs):
        return meta_search

    async def mock_meta_ads(client, page_id, **kwargs):
        return meta_ads

    async def mock_news(client, query, **kwargs):
        return news

    async def mock_jobs(client, query):
        return jobs

    async def _run():
        with patch("app.prospect.service.about_domain", mock_about), \
             patch("app.prospect.service.ads_transparency", mock_ads), \
             patch("app.prospect.service.ads_transparency_historical", mock_ads_hist), \
             patch("app.prospect.service.meta_page_search", mock_meta_search), \
             patch("app.prospect.service.meta_ads", mock_meta_ads), \
             patch("app.prospect.service.google_news_search", mock_news), \
             patch("app.prospect.service.google_jobs_search", mock_jobs):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    result = asyncio.run(_run())

    assert result["domain"] == "stripe.com"
    assert result["errors"] == []
    assert result["generated_at"]

    s = result["sections"]
    assert s["about_domain"] == about
    assert s["ads_transparency"] == ads30d
    assert s["ads_transparency_historical"] == ads_hist
    assert s["meta_page_search"] == meta_search
    assert s["meta_ads"] == meta_ads
    assert s["google_news"] == news
    assert s["google_jobs"] == jobs

    # Company name derived from knowledge_graph.title
    assert result["derived"]["company_name"] == "Stripe, Inc."


def test_build_dossier_wave2_uses_advertiser_id():
    """Wave 2 ads_historical is called with the advertiser ID from wave 1 ads response."""
    ads30d = _load("ads_transparency_stripe.json")
    captured_id = []

    async def mock_about(client, domain):
        return {}

    async def mock_ads(client, domain, **kwargs):
        return ads30d

    async def mock_ads_hist(client, advertiser_id):
        captured_id.append(advertiser_id)
        return {"search_information": {"total_results": 8000}}

    async def mock_meta_search(client, query, **kwargs):
        return {"page_results": []}

    async def mock_news(client, query, **kwargs):
        return {"organic_results": []}

    async def mock_jobs(client, query):
        return {"jobs": []}

    async def _run():
        with patch("app.prospect.service.about_domain", mock_about), \
             patch("app.prospect.service.ads_transparency", mock_ads), \
             patch("app.prospect.service.ads_transparency_historical", mock_ads_hist), \
             patch("app.prospect.service.meta_page_search", mock_meta_search), \
             patch("app.prospect.service.meta_ads", AsyncMock(return_value={})), \
             patch("app.prospect.service.google_news_search", mock_news), \
             patch("app.prospect.service.google_jobs_search", mock_jobs):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    asyncio.run(_run())
    # The advertiser ID from the fixture's first creative
    assert len(captured_id) == 1
    assert captured_id[0] == "AR16951989901585285121"


def test_build_dossier_wave2_uses_page_id():
    """Wave 2 meta_ads is called with the page_id from the first meta_page_search result."""
    meta_search = _load("meta_page_search_stripe.json")
    captured_page_id = []

    async def mock_about(client, domain):
        return {}

    async def mock_ads(client, domain, **kwargs):
        return {"ad_creatives": []}

    async def mock_meta_search(client, query, **kwargs):
        return meta_search

    async def mock_meta_ads(client, page_id, **kwargs):
        captured_page_id.append(page_id)
        return {"ads": []}

    async def mock_news(client, query, **kwargs):
        return {"organic_results": []}

    async def mock_jobs(client, query):
        return {"jobs": []}

    async def _run():
        with patch("app.prospect.service.about_domain", mock_about), \
             patch("app.prospect.service.ads_transparency", mock_ads), \
             patch("app.prospect.service.ads_transparency_historical", AsyncMock(return_value={})), \
             patch("app.prospect.service.meta_page_search", mock_meta_search), \
             patch("app.prospect.service.meta_ads", mock_meta_ads), \
             patch("app.prospect.service.google_news_search", mock_news), \
             patch("app.prospect.service.google_jobs_search", mock_jobs):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    asyncio.run(_run())
    assert len(captured_page_id) == 1
    assert captured_page_id[0] == "175383762511776"


def test_build_dossier_wave2_skipped_when_no_advertiser_id():
    """If wave 1 ads returns no creatives, wave 2 historical is not called."""
    hist_called = []

    async def mock_about(client, domain):
        return {}

    async def mock_ads(client, domain, **kwargs):
        return {"ad_creatives": []}  # no advertiser ID

    async def mock_ads_hist(client, advertiser_id):
        hist_called.append(True)
        return {}

    async def mock_meta_search(client, query, **kwargs):
        return {"page_results": []}

    async def mock_news(client, query, **kwargs):
        return {"organic_results": []}

    async def mock_jobs(client, query):
        return {"jobs": []}

    async def _run():
        with patch("app.prospect.service.about_domain", mock_about), \
             patch("app.prospect.service.ads_transparency", mock_ads), \
             patch("app.prospect.service.ads_transparency_historical", mock_ads_hist), \
             patch("app.prospect.service.meta_page_search", mock_meta_search), \
             patch("app.prospect.service.meta_ads", AsyncMock(return_value={})), \
             patch("app.prospect.service.google_news_search", mock_news), \
             patch("app.prospect.service.google_jobs_search", mock_jobs):
            from app.prospect.service import build_dossier
            return await build_dossier("noads.com")

    result = asyncio.run(_run())
    assert not hist_called, "historical engine must not be called when no advertiser_id"
    assert result["sections"]["ads_transparency_historical"] is None
    assert not any(e["section"] == "ads_transparency_historical" for e in result["errors"])


# ---------------------------------------------------------------------------
# Partial failures
# ---------------------------------------------------------------------------

def _all_succeed_mocks(overrides: dict):
    """Return a dict of mock coroutines for all 7 engines, with specific overrides."""
    defaults = {
        "about_domain": AsyncMock(return_value={"knowledge_graph": {"title": "Test Co"}}),
        "ads_transparency": AsyncMock(return_value={"ad_creatives": []}),
        "ads_transparency_historical": AsyncMock(return_value={}),
        "meta_page_search": AsyncMock(return_value={"page_results": []}),
        "meta_ads": AsyncMock(return_value={"ads": []}),
        "google_news_search": AsyncMock(return_value={"organic_results": []}),
        "google_jobs_search": AsyncMock(return_value={"jobs": []}),
    }
    defaults.update(overrides)
    return defaults


def _partial_run(engine_name: str, exc: Exception):
    """Run build_dossier with one engine raising exc, rest succeed. Returns dossier."""
    override_key = engine_name
    # Map section names to engine function names (they match for these engines)
    mocks = _all_succeed_mocks({override_key: AsyncMock(side_effect=exc)})

    async def _run():
        patches = [
            patch(f"app.prospect.service.{k}", v) for k, v in mocks.items()
        ]
        ctx = __import__("contextlib").ExitStack()
        for p in patches:
            ctx.enter_context(p)
        with ctx:
            from app.prospect.service import build_dossier
            return await build_dossier("example.com")

    return asyncio.run(_run())


def test_partial_failure_about_domain():
    result = _partial_run("about_domain", RuntimeError("timeout"))
    assert result["sections"]["about_domain"] is None
    errs = [e for e in result["errors"] if e["section"] == "about_domain"]
    assert len(errs) == 1
    assert "timeout" in errs[0]["message"]


def test_partial_failure_ads_transparency():
    result = _partial_run("ads_transparency", RuntimeError("429"))
    assert result["sections"]["ads_transparency"] is None
    errs = [e for e in result["errors"] if e["section"] == "ads_transparency"]
    assert len(errs) == 1


def test_partial_failure_meta_page_search():
    result = _partial_run("meta_page_search", ConnectionError("upstream down"))
    assert result["sections"]["meta_page_search"] is None
    errs = [e for e in result["errors"] if e["section"] == "meta_page_search"]
    assert len(errs) == 1


def test_partial_failure_google_news_search():
    result = _partial_run("google_news_search", RuntimeError("rate limited"))
    assert result["sections"]["google_news"] is None
    errs = [e for e in result["errors"] if e["section"] == "google_news"]
    assert len(errs) == 1


def test_partial_failure_google_jobs_search():
    result = _partial_run("google_jobs_search", RuntimeError("timeout"))
    assert result["sections"]["google_jobs"] is None
    errs = [e for e in result["errors"] if e["section"] == "google_jobs"]
    assert len(errs) == 1


def test_all_engines_fail():
    """Every engine raises: all sections null, 5+ errors, no exception propagated."""
    exc = RuntimeError("service down")

    mocks = {
        "about_domain": AsyncMock(side_effect=exc),
        "ads_transparency": AsyncMock(side_effect=exc),
        "ads_transparency_historical": AsyncMock(side_effect=exc),
        "meta_page_search": AsyncMock(side_effect=exc),
        "meta_ads": AsyncMock(side_effect=exc),
        "google_news_search": AsyncMock(side_effect=exc),
        "google_jobs_search": AsyncMock(side_effect=exc),
    }

    async def _run():
        with patch("app.prospect.service.about_domain", mocks["about_domain"]), \
             patch("app.prospect.service.ads_transparency", mocks["ads_transparency"]), \
             patch("app.prospect.service.ads_transparency_historical", mocks["ads_transparency_historical"]), \
             patch("app.prospect.service.meta_page_search", mocks["meta_page_search"]), \
             patch("app.prospect.service.meta_ads", mocks["meta_ads"]), \
             patch("app.prospect.service.google_news_search", mocks["google_news_search"]), \
             patch("app.prospect.service.google_jobs_search", mocks["google_jobs_search"]):
            from app.prospect.service import build_dossier
            return await build_dossier("broken.com")

    result = asyncio.run(_run())

    for section_name in [
        "about_domain", "ads_transparency",
        "meta_page_search", "google_news", "google_jobs",
    ]:
        assert result["sections"][section_name] is None

    # Wave 1 failures mean wave 2 is skipped (no advertiser_id or page_id)
    assert result["sections"]["ads_transparency_historical"] is None
    assert result["sections"]["meta_ads"] is None

    # Only wave 1 engines produce errors; wave 2 is skipped cleanly
    assert len(result["errors"]) == 5
    assert result["derived"]["company_name"] == "Broken"  # domain root fallback
