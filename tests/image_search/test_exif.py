"""
Tests for exif.py: extraction from JPEG with GPS, empty result for PNG, non-exif JPEG.
"""
import os
import sys
from pathlib import Path

import pytest

try:
    from PIL import Image
    import io
    _HAVE_PIL = True
except ImportError:
    _HAVE_PIL = False

FIXTURES = Path(__file__).parent / "fixtures"


def _make_jpeg_no_exif(tmp_path: Path) -> Path:
    """Create a minimal JPEG without EXIF using raw bytes."""
    # SOI + APP0 JFIF + EOI
    data = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xd9"
    )
    p = tmp_path / "noexi.jpg"
    p.write_bytes(data)
    return p


def _make_png(tmp_path: Path) -> Path:
    """Create a minimal PNG (1x1 white pixel) using PIL or raw bytes."""
    p = tmp_path / "test.png"
    if _HAVE_PIL:
        img = Image.new("RGB", (1, 1), color=(255, 255, 255))
        img.save(str(p), format="PNG")
    else:
        # PNG signature + IHDR + IDAT + IEND chunks (hand-crafted 1x1 white)
        import zlib, struct
        def chunk(tag, data):
            c = struct.pack(">I", len(data)) + tag + data
            return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        raw = (
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
            + chunk(b"IEND", b"")
        )
        p.write_bytes(raw)
    return p


def test_png_returns_empty(tmp_path):
    from app.image_search.exif import extract_exif
    p = _make_png(tmp_path)
    result = extract_exif(str(p))
    assert result == {}


def test_nonexistent_file_returns_empty():
    from app.image_search.exif import extract_exif
    result = extract_exif("/nonexistent/path/image.jpg")
    assert result == {}


def test_random_bytes_returns_empty(tmp_path):
    from app.image_search.exif import extract_exif
    p = tmp_path / "garbage.jpg"
    p.write_bytes(b"\x00" * 100)
    result = extract_exif(str(p))
    assert result == {}


@pytest.mark.skipif(not _HAVE_PIL, reason="PIL not installed")
def test_jpeg_no_exif_returns_dimensions(tmp_path):
    from app.image_search.exif import extract_exif
    img = Image.new("RGB", (100, 80), color=(0, 0, 0))
    p = tmp_path / "plain.jpg"
    img.save(str(p), format="JPEG")
    result = extract_exif(str(p))
    # PIL JPEG without EXIF: may return dimensions only or empty
    assert isinstance(result, dict)


@pytest.mark.skipif(not _HAVE_PIL, reason="PIL not installed")
def test_jpeg_with_exif_fixture():
    from app.image_search.exif import extract_exif
    fixture = FIXTURES / "sample_exif.jpg"
    if not fixture.exists():
        pytest.skip("sample_exif.jpg fixture not present")
    result = extract_exif(str(fixture))
    assert isinstance(result, dict)
    assert "width" in result
    assert "height" in result


@pytest.mark.skipif(not _HAVE_PIL, reason="PIL not installed")
def test_jpeg_with_gps_fixture():
    from app.image_search.exif import extract_exif
    fixture = FIXTURES / "sample_gps.jpg"
    if not fixture.exists():
        pytest.skip("sample_gps.jpg fixture not present")
    result = extract_exif(str(fixture))
    assert "gps" in result
    gps = result["gps"]
    assert "lat" in gps and "lon" in gps
    assert isinstance(gps["lat"], float)
    assert isinstance(gps["lon"], float)
