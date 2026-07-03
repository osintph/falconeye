"""
Tests for image_search/routes.py: kill switch, rate limit, cache hit, upload flow.
"""
import hashlib
import io
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("IMAGE_UPLOAD_SECRET", "testsecret1234567890abcdef1234567890abcdef1234567890abcdef1234")
os.environ.setdefault("FALCONEYE_DATA_DIR", "/tmp/falconeye_test_data")

from app.main import app

client = TestClient(app, raise_server_exceptions=True)

_JPEG = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xd9"
)
_PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x00IEND\xaeB`\x82"

_GOOD_SEARCH_RESULT = {
    "queried_url": "https://example.com/img.jpg",
    "generated_at": "2026-01-01T00:00:00+00:00",
    "sections": {"google_lens": None, "yandex": None, "cross_source_domains": [], "exif": None},
    "errors": [],
}


class TestKillSwitch:
    def test_upload_disabled(self):
        with patch("app.image_search.routes._ENABLED", False):
            resp = client.post(
                "/api/image/upload",
                files={"file": ("test.jpg", io.BytesIO(_JPEG), "image/jpeg")},
            )
        assert resp.status_code == 503

    def test_search_disabled(self):
        with patch("app.image_search.routes._ENABLED", False):
            resp = client.post(
                "/api/image/search",
                json={"image_url": "https://example.com/img.jpg"},
            )
        assert resp.status_code == 503


class TestSearchEndpoint:
    def test_missing_url_returns_400(self):
        resp = client.post("/api/image/search", json={})
        assert resp.status_code == 400

    def test_empty_url_returns_400(self):
        resp = client.post("/api/image/search", json={"image_url": ""})
        assert resp.status_code == 400

    def test_search_returns_result(self):
        async def fake_search(url, include_yandex=True):
            return dict(_GOOD_SEARCH_RESULT, queried_url=url)

        with patch("app.image_search.routes.search_image", fake_search), \
             patch("app.image_search.routes._redis", None):
            resp = client.post(
                "/api/image/search",
                json={"image_url": "https://example.com/img.jpg"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["queried_url"] == "https://example.com/img.jpg"

    def test_cache_hit_returns_cached_flag(self):
        cached_data = json.dumps(dict(_GOOD_SEARCH_RESULT))

        class FakeRedis:
            async def get(self, key): return cached_data
            async def setex(self, key, ttl, val): pass

        with patch("app.image_search.routes._redis", FakeRedis()):
            resp = client.post(
                "/api/image/search",
                json={"image_url": "https://example.com/img.jpg"},
            )
        assert resp.status_code == 200
        assert resp.json()["cached"] is True

    def test_search_result_stored_in_cache(self):
        stored = {}

        async def fake_search(url, include_yandex=True):
            return dict(_GOOD_SEARCH_RESULT, queried_url=url)

        class FakeRedis:
            async def get(self, key): return None
            async def setex(self, key, ttl, val):
                stored["key"] = key
                stored["val"] = val

        with patch("app.image_search.routes.search_image", fake_search), \
             patch("app.image_search.routes._redis", FakeRedis()):
            resp = client.post(
                "/api/image/search",
                json={"image_url": "https://example.com/store.jpg"},
            )
        assert resp.status_code == 200
        assert "key" in stored
        expected_key = (
            "image_search:"
            + hashlib.sha256(b"https://example.com/store.jpg").hexdigest()
        )
        assert stored["key"] == expected_key


class TestUploadEndpoint:
    def test_jpeg_upload_returns_signed_url(self, tmp_path):
        with patch("app.image_search.upload._UPLOAD_DIR", tmp_path), \
             patch("app.image_search.routes._UPLOAD_DIR", tmp_path):
            resp = client.post(
                "/api/image/upload",
                files={"file": ("photo.jpg", io.BytesIO(_JPEG), "image/jpeg")},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "signed_url" in data
        assert "sha256" in data
        assert "/api/image/temp/" in data["signed_url"]
        assert "token=" in data["signed_url"]

    def test_wrong_mime_rejected(self, tmp_path):
        with patch("app.image_search.upload._UPLOAD_DIR", tmp_path):
            resp = client.post(
                "/api/image/upload",
                files={"file": ("doc.pdf", io.BytesIO(b"%PDF-1.4"), "application/pdf")},
            )
        assert resp.status_code == 400

    def test_mime_mismatch_rejected(self, tmp_path):
        with patch("app.image_search.upload._UPLOAD_DIR", tmp_path):
            resp = client.post(
                "/api/image/upload",
                files={"file": ("fake.jpg", io.BytesIO(_PNG), "image/jpeg")},
            )
        assert resp.status_code == 400

    def test_signed_url_with_invalid_token_rejected(self, tmp_path):
        async def fake_search(url, include_yandex=True):
            return dict(_GOOD_SEARCH_RESULT, queried_url=url)

        with patch("app.image_search.routes.search_image", fake_search), \
             patch("app.image_search.routes._redis", None):
            resp = client.post(
                "/api/image/search",
                json={"signed_url": "https://falconeye.osintph.info/api/image/temp/abc.jpg?token=bad:0"},
            )
        assert resp.status_code == 403


class TestTempServe:
    def test_valid_token_serves_file(self, tmp_path):
        from app.image_search.upload import make_token
        sha256 = hashlib.sha256(_JPEG).hexdigest()
        (tmp_path / f"{sha256}.jpg").write_bytes(_JPEG)
        token = make_token(sha256)

        with patch("app.image_search.routes._UPLOAD_DIR", tmp_path):
            resp = client.get(f"/api/image/temp/{sha256}.jpg?token={token}")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "image/jpeg"

    def test_invalid_token_rejected(self, tmp_path):
        sha256 = "a" * 64
        with patch("app.image_search.routes._UPLOAD_DIR", tmp_path):
            resp = client.get(f"/api/image/temp/{sha256}.jpg?token=bad:0")
        assert resp.status_code == 403

    def test_missing_file_404(self, tmp_path):
        from app.image_search.upload import make_token
        sha256 = "b" * 64
        token = make_token(sha256)
        with patch("app.image_search.routes._UPLOAD_DIR", tmp_path):
            resp = client.get(f"/api/image/temp/{sha256}.jpg?token={token}")
        assert resp.status_code == 404
