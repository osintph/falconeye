"""
Tests for build_dossier().
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
# Happy path — both engines succeed
# ---------------------------------------------------------------------------

def test_build_dossier_both_succeed():
    """Both engines succeed: sections populated, errors empty, metadata present."""
    about = _load("about_domain_stripe.json")
    ads = _load("ads_transparency_stripe.json")

    async def mock_about(client, domain):
        return about

    async def mock_ads(client, domain, **kwargs):
        return ads

    async def _run():
        with patch("app.prospect.service.about_domain", mock_about), \
             patch("app.prospect.service.ads_transparency", mock_ads):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    result = asyncio.run(_run())

    assert result["domain"] == "stripe.com"
    assert result["sections"]["about_domain"] == about
    assert result["sections"]["ads_transparency"] == ads
    assert result["errors"] == []
    assert result["generated_at"]  # ISO timestamp present


def test_build_dossier_concurrent():
    """Both engine calls are issued concurrently via asyncio.gather."""
    started = []
    finished = []
    barrier = asyncio.Event()

    async def mock_about(client, domain):
        started.append("about")
        await asyncio.sleep(0)  # yield to allow both to start
        finished.append("about")
        return {"about": True}

    async def mock_ads(client, domain, **kwargs):
        started.append("ads")
        await asyncio.sleep(0)
        finished.append("ads")
        return {"ads": True}

    async def _run():
        with patch("app.prospect.service.about_domain", mock_about), \
             patch("app.prospect.service.ads_transparency", mock_ads):
            from app.prospect.service import build_dossier
            return await build_dossier("example.com")

    asyncio.run(_run())
    # Both were started before either finished (concurrent, not sequential)
    assert set(started) == {"about", "ads"}


# ---------------------------------------------------------------------------
# Partial failure — one engine raises
# ---------------------------------------------------------------------------

def test_partial_dossier_on_ads_failure():
    """Ads engine failure: about_domain populated, ads_transparency null, error logged."""
    about = _load("about_domain_stripe.json")

    async def mock_about(client, domain):
        return about

    async def mock_ads_fail(client, domain, **kwargs):
        raise RuntimeError("SearchAPI timeout")

    async def _run():
        with patch("app.prospect.service.about_domain", mock_about), \
             patch("app.prospect.service.ads_transparency", mock_ads_fail):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    result = asyncio.run(_run())

    assert result["sections"]["about_domain"] == about
    assert result["sections"]["ads_transparency"] is None
    assert len(result["errors"]) == 1
    assert result["errors"][0]["section"] == "ads_transparency"
    assert "SearchAPI timeout" in result["errors"][0]["message"]


def test_partial_dossier_on_about_failure():
    """About-domain engine failure: about_domain null, ads section populated."""
    ads = _load("ads_transparency_stripe.json")

    async def mock_about_fail(client, domain):
        raise ConnectionError("upstream unreachable")

    async def mock_ads(client, domain, **kwargs):
        return ads

    async def _run():
        with patch("app.prospect.service.about_domain", mock_about_fail), \
             patch("app.prospect.service.ads_transparency", mock_ads):
            from app.prospect.service import build_dossier
            return await build_dossier("stripe.com")

    result = asyncio.run(_run())

    assert result["sections"]["about_domain"] is None
    assert result["sections"]["ads_transparency"] == ads
    assert len(result["errors"]) == 1
    assert result["errors"][0]["section"] == "about_domain"


def test_both_engines_fail():
    """Both engines fail: both sections null, two errors, no exception raised."""
    async def mock_about_fail(client, domain):
        raise RuntimeError("down")

    async def mock_ads_fail(client, domain, **kwargs):
        raise RuntimeError("down")

    async def _run():
        with patch("app.prospect.service.about_domain", mock_about_fail), \
             patch("app.prospect.service.ads_transparency", mock_ads_fail):
            from app.prospect.service import build_dossier
            return await build_dossier("example.com")

    result = asyncio.run(_run())

    assert result["sections"]["about_domain"] is None
    assert result["sections"]["ads_transparency"] is None
    assert len(result["errors"]) == 2
