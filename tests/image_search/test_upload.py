"""
Tests for upload.py: MIME validation, size cap, HMAC token, expiry, cleanup scheduling.
"""
import asyncio
import hashlib
import hmac
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

os.environ.setdefault("IMAGE_UPLOAD_SECRET", "testsecret1234567890abcdef1234567890abcdef1234567890abcdef1234")
os.environ.setdefault("FALCONEYE_DATA_DIR", "/tmp/falconeye_test_data")

from app.image_search.upload import (
    ALLOWED_MIME,
    _TOKEN_TTL,
    make_token,
    save_upload,
    validate_token,
)

# Minimal valid JPEG: SOI + EOI
_JPEG_BYTES = b"\xff\xd8\xff\xe0" + b"\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\xff\xd9"
# Minimal PNG: signature + IEND chunk
_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_PNG_BYTES = _PNG_SIG + b"\x00\x00\x00\x00IEND\xaeB`\x82"
# WebP: RIFF + size + WEBP
_WEBP_BYTES = b"RIFF\x00\x00\x00\x00WEBP"


class TestMimeValidation:
    def test_jpeg_accepted(self, tmp_path):
        with patch("app.image_search.upload._UPLOAD_DIR", tmp_path):
            sha, path = save_upload(_JPEG_BYTES, "image/jpeg")
        assert sha == hashlib.sha256(_JPEG_BYTES).hexdigest()
        assert path.endswith(".jpg")

    def test_png_accepted(self, tmp_path):
        with patch("app.image_search.upload._UPLOAD_DIR", tmp_path):
            sha, path = save_upload(_PNG_BYTES, "image/png")
        assert path.endswith(".png")

    def test_webp_accepted(self, tmp_path):
        with patch("app.image_search.upload._UPLOAD_DIR", tmp_path):
            sha, path = save_upload(_WEBP_BYTES, "image/webp")
        assert path.endswith(".webp")

    def test_disallowed_mime_type(self, tmp_path):
        with patch("app.image_search.upload._UPLOAD_DIR", tmp_path):
            with pytest.raises(ValueError, match="Unsupported file type"):
                save_upload(b"<html>", "text/html")

    def test_mime_mismatch_rejected(self, tmp_path):
        with patch("app.image_search.upload._UPLOAD_DIR", tmp_path):
            with pytest.raises(ValueError, match="does not match actual"):
                save_upload(_PNG_BYTES, "image/jpeg")

    def test_unrecognized_bytes_rejected(self, tmp_path):
        with patch("app.image_search.upload._UPLOAD_DIR", tmp_path):
            with pytest.raises(ValueError, match="does not match any supported image format"):
                save_upload(b"\x00\x01\x02\x03plain garbage", "image/jpeg")


class TestSizeCap:
    def test_oversized_rejected(self, tmp_path):
        big = b"\xff\xd8\xff" + b"\x00" * (10 * 1024 * 1024 + 1)
        with patch("app.image_search.upload._UPLOAD_DIR", tmp_path):
            with pytest.raises(ValueError, match="too large"):
                save_upload(big, "image/jpeg")

    def test_exactly_at_limit_accepted(self, tmp_path):
        limit = 10 * 1024 * 1024
        data = b"\xff\xd8\xff\xe0" + b"\x00" * (limit - len(_JPEG_BYTES)) + _JPEG_BYTES[4:]
        jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * (limit - 4)
        with patch("app.image_search.upload._UPLOAD_DIR", tmp_path):
            sha, _ = save_upload(jpeg, "image/jpeg")
        assert sha


class TestHmacToken:
    def test_make_and_validate(self):
        sha256 = "a" * 64
        token = make_token(sha256)
        assert validate_token(sha256, token)

    def test_wrong_sha256_rejected(self):
        token = make_token("a" * 64)
        assert not validate_token("b" * 64, token)

    def test_tampered_sig_rejected(self):
        sha256 = "c" * 64
        token = make_token(sha256)
        parts = token.split(":")
        bad = "0" * 64 + ":" + parts[1]
        assert not validate_token(sha256, bad)

    def test_malformed_token_rejected(self):
        assert not validate_token("a" * 64, "notavalidtoken")

    def test_token_expiry(self):
        sha256 = "d" * 64
        past_ts = int(time.time()) - (_TOKEN_TTL + 5)
        secret = os.environ["IMAGE_UPLOAD_SECRET"].encode()
        msg = f"{sha256}:{past_ts}".encode()
        sig = hmac.new(secret, msg, "sha256").hexdigest()
        expired_token = f"{sig}:{past_ts}"
        assert not validate_token(sha256, expired_token)

    def test_fresh_token_accepted(self):
        sha256 = "e" * 64
        token = make_token(sha256)
        assert validate_token(sha256, token)


class TestFileCleanup:
    def test_cleanup_removes_file(self, tmp_path):
        from app.image_search.upload import schedule_cleanup
        test_file = tmp_path / "test.jpg"
        test_file.write_bytes(b"data")

        async def run():
            with patch("app.image_search.upload._CLEANUP_DELAY", 0):
                await schedule_cleanup(str(test_file))

        asyncio.run(run())
        assert not test_file.exists()

    def test_cleanup_missing_file_no_error(self, tmp_path):
        from app.image_search.upload import schedule_cleanup
        missing = str(tmp_path / "gone.jpg")

        async def run():
            with patch("app.image_search.upload._CLEANUP_DELAY", 0):
                await schedule_cleanup(missing)

        asyncio.run(run())  # should not raise
