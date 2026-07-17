"""
QR Code Analyzer.

Decodes one or more QR codes from an uploaded image (multipart file="image") or
a base64 data URI (JSON {"data_uri": ...}). Processing is fully in-memory: the
image bytes are never written to disk. This endpoint NEVER fetches a URL — if a
decoded payload is a URL, the frontend forwards it to /api/url/expand separately
(which runs its own SSRF checks and rate limit).
"""
import base64
import io
import logging
import sqlite3

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from PIL import Image
from pyzbar.pyzbar import decode as zbar_decode
from slowapi import Limiter

from app.config import DB_PATH, QR_DECODE_RATE_LIMIT_PER_DAY
from app.utils.client_ip import get_client_ip, get_client_ip_key

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/qr", tags=["qr_analyzer"])
limiter = Limiter(key_func=get_client_ip_key)

MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5 MB


# ---------- rate limit (10 / IP / 24h, mirrors dork_generator pattern) ----------

def _init_rl():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS qr_decode_rate_limit (
            source_ip TEXT NOT NULL,
            called_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_qr_decode_rate_ip ON qr_decode_rate_limit(source_ip, called_at)"
    )
    conn.commit()
    conn.close()


_init_rl()


def _check_rate_limit(source_ip: str) -> tuple[bool, int]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "SELECT COUNT(*) FROM qr_decode_rate_limit WHERE source_ip = ? AND called_at > datetime('now', '-24 hours')",
        (source_ip,),
    )
    count = cur.fetchone()[0]
    conn.close()
    return (count < QR_DECODE_RATE_LIMIT_PER_DAY, count)


def _record_call(source_ip: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO qr_decode_rate_limit (source_ip) VALUES (?)", (source_ip,))
        conn.execute("DELETE FROM qr_decode_rate_limit WHERE called_at < datetime('now', '-48 hours')")
        conn.commit()
        conn.close()
    except Exception as exc:
        log.error("Failed to write qr_decode_rate_limit row for ip=%s: %s", source_ip, exc)


# ---------- decoding ----------

def _categorize(content: str) -> tuple[str, bool]:
    """Return (kind, is_url)."""
    low = content.strip().lower()
    if low.startswith(("http://", "https://")):
        return "http", True
    if low.startswith("bitcoin:"):
        return "bitcoin", False
    if low.startswith("ethereum:"):
        return "ethereum", False
    if low.startswith("upi:"):
        return "upi", False
    if low.startswith("geo:"):
        return "geo", False
    if low.startswith(("sms:", "smsto:")):
        return "sms", False
    if low.startswith("tel:"):
        return "tel", False
    if low.startswith("wifi:"):
        return "wifi", False
    return "text", False


def decode_qr(image_bytes: bytes) -> dict:
    """Decode every QR code in *image_bytes*. In-memory only."""
    if len(image_bytes) > MAX_IMAGE_BYTES:
        return {"count": 0, "codes": [], "error": "Image exceeds the 5 MB limit."}
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.load()  # force a real decode so we reject non-image / corrupt input
    except Exception:
        return {"count": 0, "codes": [], "error": "Not a valid image file."}

    try:
        results = zbar_decode(img)
    except Exception as exc:
        return {"count": 0, "codes": [], "error": f"QR decode error: {type(exc).__name__}"}

    codes = []
    for idx, result in enumerate(results, start=1):
        content = result.data.decode("utf-8", errors="replace")
        kind, is_url = _categorize(content)
        codes.append({"index": idx, "data": content, "is_url": is_url, "kind": kind})

    return {
        "count": len(codes),
        "codes": codes,
        "error": None if codes else "No QR code detected. Try a higher-resolution image.",
    }


def _decode_data_uri(data_uri: str) -> bytes:
    raw = data_uri.strip()
    if raw.startswith("data:"):
        comma = raw.find(",")
        if comma == -1:
            raise ValueError("malformed data URI")
        header, raw = raw[:comma], raw[comma + 1:]
        if "base64" not in header:
            raise ValueError("only base64 data URIs are supported")
    try:
        return base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise ValueError(f"invalid base64 payload: {exc}")


# ---------- endpoint ----------

@router.post("/decode")
@limiter.limit("10/minute")
async def decode(request: Request, image: UploadFile | None = File(default=None)):
    source_ip = get_client_ip(request)
    allowed, used = _check_rate_limit(source_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Daily limit reached ({used}/{QR_DECODE_RATE_LIMIT_PER_DAY} QR decodes per 24 hours). Try again later.",
        )

    if image is not None:
        image_bytes = await image.read()
    else:
        try:
            body = await request.json()
        except Exception:
            body = {}
        data_uri = (body or {}).get("data_uri")
        if not data_uri:
            raise HTTPException(status_code=400, detail="Provide an image file or a data_uri.")
        try:
            image_bytes = _decode_data_uri(data_uri)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    if not image_bytes:
        raise HTTPException(status_code=400, detail="Empty image payload.")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="Image exceeds the 5 MB limit.")

    _record_call(source_ip)
    return decode_qr(image_bytes)
