import asyncio
import hashlib
import hmac
import logging
import os
import time
from pathlib import Path

log = logging.getLogger("falconeye.image_search.upload")

_UPLOAD_DIR = Path(os.getenv("FALCONEYE_DATA_DIR", "/opt/falconeye/data")) / "image_temp"
_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
_TOKEN_TTL = 300        # 5 minutes
_CLEANUP_DELAY = 900    # 15 minutes

ALLOWED_MIME = frozenset({
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
})

_EXT_MAP = {
    "image/jpeg": "jpg",
    "image/png":  "png",
    "image/webp": "webp",
    "image/gif":  "gif",
}

_MAGIC_BYTES = [
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
]


def _sniff_mime(data: bytes):
    for magic, mime in _MAGIC_BYTES:
        if data[:len(magic)] == magic:
            return mime
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _get_secret() -> bytes:
    return os.environ["IMAGE_UPLOAD_SECRET"].encode()


def save_upload(file_bytes: bytes, declared_mime: str) -> tuple:
    """Validate, save, and return (sha256_hex, abs_file_path). Raises ValueError on invalid input."""
    if len(file_bytes) > _MAX_FILE_SIZE:
        raise ValueError(f"File too large ({len(file_bytes) // 1024} KB). Maximum is 10 MB.")

    if declared_mime not in ALLOWED_MIME:
        raise ValueError(f"Unsupported file type: {declared_mime!r}. Allowed: jpeg, png, webp, gif.")

    actual_mime = _sniff_mime(file_bytes)
    if actual_mime is None:
        raise ValueError("File content does not match any supported image format.")

    if actual_mime != declared_mime:
        raise ValueError(
            f"Declared content type {declared_mime!r} does not match actual {actual_mime!r}."
        )

    sha256 = hashlib.sha256(file_bytes).hexdigest()
    ext = _EXT_MAP[actual_mime]

    _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = _UPLOAD_DIR / f"{sha256}.{ext}"
    dest.write_bytes(file_bytes)
    log.info("upload.saved sha256=%.12s ext=%s bytes=%d", sha256, ext, len(file_bytes))
    return sha256, str(dest)


def make_token(sha256: str) -> str:
    """Return a signed token string of the form '{hmac_hex}:{timestamp}'."""
    ts = int(time.time())
    msg = f"{sha256}:{ts}".encode()
    sig = hmac.new(_get_secret(), msg, "sha256").hexdigest()
    return f"{sig}:{ts}"


def validate_token(sha256: str, token: str) -> bool:
    """Return True if token is valid (correct signature and within TTL)."""
    try:
        parts = token.split(":")
        if len(parts) != 2:
            return False
        sig, ts_str = parts
        ts = int(ts_str)
        if abs(time.time() - ts) > _TOKEN_TTL:
            return False
        msg = f"{sha256}:{ts}".encode()
        expected = hmac.new(_get_secret(), msg, "sha256").hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


async def schedule_cleanup(file_path: str) -> None:
    """Delete file after _CLEANUP_DELAY seconds."""
    await asyncio.sleep(_CLEANUP_DELAY)
    try:
        Path(file_path).unlink(missing_ok=True)
        log.info("upload.cleaned path=%s", file_path)
    except Exception as exc:
        log.warning("upload.cleanup_failed path=%s error=%s", file_path, exc)
