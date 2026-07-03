import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.image_search.exif import extract_exif
from app.image_search.service import search_image
from app.image_search.upload import (
    _UPLOAD_DIR,
    make_token,
    save_upload,
    schedule_cleanup,
    validate_token,
)

log = logging.getLogger("falconeye.image_search")
router = APIRouter(prefix="/api/image", tags=["image_search"])
limiter = Limiter(key_func=get_remote_address)

_ENABLED = os.getenv("IMAGE_SEARCH_ENABLED", "true").lower() == "true"
_YANDEX_ENABLED = os.getenv("IMAGE_SEARCH_YANDEX_ENABLED", "true").lower() == "true"
_SITE_ORIGIN = os.getenv("SITE_ORIGIN", "https://falconeye.osintph.info")
_CACHE_TTL = 24 * 3600

try:
    import redis.asyncio as _aioredis
    _redis = _aioredis.from_url(
        os.getenv("REDIS_URL", "redis://localhost:6379"),
        decode_responses=True,
    )
except ImportError:
    _redis = None
    log.warning("redis not available; image search caching disabled")

_MEDIA_TYPE = {
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "webp": "image/webp",
    "gif": "image/gif",
}


class SearchRequest(BaseModel):
    image_url: str = ""
    signed_url: str = ""


@router.post("/upload")
@limiter.limit("10/minute")
async def upload_image(request: Request, file: UploadFile = File(...)):
    if not _ENABLED:
        raise HTTPException(status_code=503, detail="Image search is currently disabled.")

    file_bytes = await file.read()
    declared_mime = (file.content_type or "").split(";")[0].strip()

    try:
        sha256, file_path = save_upload(file_bytes, declared_mime)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    ext = Path(file_path).suffix.lstrip(".")
    token = make_token(sha256)
    signed_url = f"{_SITE_ORIGIN}/api/image/temp/{sha256}.{ext}?token={token}"

    asyncio.create_task(schedule_cleanup(file_path))

    return {"signed_url": signed_url, "sha256": sha256}


@router.get("/temp/{filename}")
async def serve_temp_image(filename: str, token: str = ""):
    parts = filename.split(".", 1)
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail="Invalid filename.")

    sha256, ext = parts
    if not validate_token(sha256, token):
        raise HTTPException(status_code=403, detail="Invalid or expired token.")

    file_path = _UPLOAD_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found or already expired.")

    media_type = _MEDIA_TYPE.get(ext.lower(), "application/octet-stream")
    return FileResponse(str(file_path), media_type=media_type)


@router.post("/search")
@limiter.limit("20/minute")
async def image_search_endpoint(request: Request, body: SearchRequest):
    if not _ENABLED:
        raise HTTPException(status_code=503, detail="Image search is currently disabled.")

    image_url = (body.image_url or body.signed_url or "").strip()
    if not image_url:
        raise HTTPException(status_code=400, detail="Provide image_url or signed_url.")

    is_upload = bool(body.signed_url)

    if is_upload:
        try:
            parsed = urlparse(body.signed_url)
            token_param = parse_qs(parsed.query).get("token", [""])[0]
            filename = parsed.path.rstrip("/").split("/")[-1]
            sha256 = filename.split(".")[0]
            if not validate_token(sha256, token_param):
                raise HTTPException(status_code=403, detail="Invalid or expired signed URL.")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=400, detail="Malformed signed URL.")

    cache_key = f"image_search:{hashlib.sha256(image_url.encode()).hexdigest()}"

    if _redis is not None:
        try:
            raw = await _redis.get(cache_key)
            if raw:
                data = json.loads(raw)
                data["cached"] = True
                return data
        except Exception as exc:
            log.warning("redis.get failed: %s", exc)

    result = await search_image(image_url, include_yandex=_YANDEX_ENABLED)

    if is_upload:
        try:
            parsed = urlparse(body.signed_url)
            filename = parsed.path.rstrip("/").split("/")[-1].split("?")[0]
            file_path = _UPLOAD_DIR / filename
            exif_data = extract_exif(str(file_path)) if file_path.exists() else {}
            result["sections"]["exif"] = exif_data if exif_data else None
        except Exception as exc:
            log.warning("EXIF extraction failed: %s", exc)
            result["sections"]["exif"] = None
    else:
        result["sections"]["exif"] = None

    if _redis is not None:
        try:
            await _redis.setex(cache_key, _CACHE_TTL, json.dumps(result))
        except Exception as exc:
            log.warning("redis.set failed: %s", exc)

    result["cached"] = False
    return result
