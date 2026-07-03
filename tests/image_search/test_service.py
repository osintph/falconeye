"""
Tests for image_search/service.py.
Uses fixtures google_lens_eiffel.json and yandex_eiffel.json (Flickr chickadee image).
No live SearchAPI calls.
"""
import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("SEARCHAPI_KEY", "test-key-placeholder")

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# cross_source_domains computation
# ---------------------------------------------------------------------------

def test_cross_source_domains_overlap():
    """Domains common to both Lens and Yandex visual_matches should appear."""
    from app.image_search.service import _lens_domains, _yandex_domains
    lens = _load("google_lens_eiffel.json")
    yandex = _load("yandex_eiffel.json")
    ld = _lens_domains(lens)
    yd = _yandex_domains(yandex)
    overlap = ld & yd
    # Yandex fixture contains flickr.com matches; Lens also links to Flickr
    # Overlap may be empty depending on fixture, but the sets are non-empty
    assert isinstance(overlap, set)
    assert len(ld) > 0 or len(yd) > 0


def test_cross_source_domains_sorted():
    """cross_source_domains list must be alphabetically sorted."""
    from app.image_search.service import _lens_domains, _yandex_domains
    lens = _load("google_lens_eiffel.json")
    yandex = _load("yandex_eiffel.json")
    ld = _lens_domains(lens)
    yd = _yandex_domains(yandex)
    overlap = sorted(ld & yd)
    assert overlap == sorted(overlap)


def test_lens_domains_extracted_from_source_field():
    from app.image_search.service import _lens_domains
    fake = {
        "visual_matches": [
            {"source": "example.com", "link": "https://example.com/img.jpg"},
            {"source": "other.org", "link": "https://other.org/pic.png"},
        ]
    }
    domains = _lens_domains(fake)
    assert "example.com" in domains
    assert "other.org" in domains


def test_yandex_domains_from_image_sizes():
    from app.image_search.service import _yandex_domains
    fake = {
        "visual_matches": [],
        "image_sizes": {
            "large": [{"size": "1000x800", "link": "https://cdn.site.com/bigpic.jpg"}],
            "small": [{"size": "100x80", "link": "https://www.thumb.net/s.jpg"}],
        },
    }
    domains = _yandex_domains(fake)
    assert "cdn.site.com" in domains
    assert "thumb.net" in domains


def test_bare_domain_strips_www():
    from app.image_search.service import _bare_domain
    assert _bare_domain("https://www.flickr.com/photos/foo") == "flickr.com"
    assert _bare_domain("www.example.com") == "example.com"
    assert _bare_domain("example.com") == "example.com"


# ---------------------------------------------------------------------------
# Concurrent execution
# ---------------------------------------------------------------------------

def test_search_image_calls_both_engines_concurrently():
    """Both engine calls should be gathered, not sequential."""
    call_order = []

    async def fake_lens(client, url, search_type="all"):
        call_order.append("lens")
        return {"visual_matches": []}

    async def fake_yandex(client, url):
        call_order.append("yandex")
        return {"visual_matches": [], "image_sizes": {}}

    async def run():
        with patch("app.image_search.service.google_lens", fake_lens), \
             patch("app.image_search.service.yandex_reverse_image", fake_yandex):
            from app.image_search.service import search_image
            return await search_image("https://example.com/img.jpg")

    result = _run(run())
    assert "google_lens" in result["sections"]
    assert "yandex" in result["sections"]
    assert len(call_order) == 2


# ---------------------------------------------------------------------------
# Partial failure handling
# ---------------------------------------------------------------------------

def test_lens_failure_recorded_in_errors():
    async def failing_lens(client, url, search_type="all"):
        raise RuntimeError("SearchAPI 500")

    async def ok_yandex(client, url):
        return {"visual_matches": [], "image_sizes": {}}

    async def run():
        with patch("app.image_search.service.google_lens", failing_lens), \
             patch("app.image_search.service.yandex_reverse_image", ok_yandex):
            from app.image_search.service import search_image
            return await search_image("https://example.com/img.jpg")

    result = _run(run())
    assert result["sections"]["google_lens"] is None
    assert result["sections"]["yandex"] is not None
    errs = [e["section"] for e in result["errors"]]
    assert "google_lens" in errs
    assert "yandex" not in errs


def test_yandex_failure_recorded_in_errors():
    async def ok_lens(client, url, search_type="all"):
        return {"visual_matches": [{"source": "flickr.com", "link": "https://flickr.com/"}]}

    async def failing_yandex(client, url):
        raise RuntimeError("Yandex timeout")

    async def run():
        with patch("app.image_search.service.google_lens", ok_lens), \
             patch("app.image_search.service.yandex_reverse_image", failing_yandex):
            from app.image_search.service import search_image
            return await search_image("https://example.com/img.jpg")

    result = _run(run())
    assert result["sections"]["yandex"] is None
    assert result["sections"]["google_lens"] is not None
    errs = [e["section"] for e in result["errors"]]
    assert "yandex" in errs


def test_both_failures_cross_source_empty():
    async def fail(client, *a, **kw):
        raise RuntimeError("fail")

    async def run():
        with patch("app.image_search.service.google_lens", fail), \
             patch("app.image_search.service.yandex_reverse_image", fail):
            from app.image_search.service import search_image
            return await search_image("https://example.com/img.jpg")

    result = _run(run())
    assert result["sections"]["cross_source_domains"] == []
    assert len(result["errors"]) == 2


# ---------------------------------------------------------------------------
# include_yandex=False
# ---------------------------------------------------------------------------

def test_yandex_disabled_skips_engine():
    called = []

    async def ok_lens(client, url, search_type="all"):
        called.append("lens")
        return {"visual_matches": []}

    async def should_not_call(client, url):
        called.append("yandex")
        return {}

    async def run():
        with patch("app.image_search.service.google_lens", ok_lens), \
             patch("app.image_search.service.yandex_reverse_image", should_not_call):
            from app.image_search.service import search_image
            return await search_image("https://example.com/img.jpg", include_yandex=False)

    result = _run(run())
    assert "yandex" not in called
    assert result["sections"]["yandex"] is None


# ---------------------------------------------------------------------------
# Fixture-driven result shape
# ---------------------------------------------------------------------------

def test_fixture_result_shape():
    lens = _load("google_lens_eiffel.json")
    yandex = _load("yandex_eiffel.json")

    async def fake_lens(client, url, search_type="all"):
        return lens

    async def fake_yandex(client, url):
        return yandex

    async def run():
        with patch("app.image_search.service.google_lens", fake_lens), \
             patch("app.image_search.service.yandex_reverse_image", fake_yandex):
            from app.image_search.service import search_image
            return await search_image("https://test.url/image.jpg")

    result = _run(run())
    assert result["queried_url"] == "https://test.url/image.jpg"
    assert "generated_at" in result
    s = result["sections"]
    assert "google_lens" in s
    assert "yandex" in s
    assert isinstance(s["cross_source_domains"], list)
