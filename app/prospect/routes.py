import json
import logging
import os

from fastapi import APIRouter, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.prospect.investigations import write_investigation
from app.prospect.service import build_dossier
from app.utils.domain import normalize_domain

log = logging.getLogger("falconeye.prospect")
router = APIRouter(prefix="/api/prospect", tags=["prospect"])
limiter = Limiter(key_func=get_remote_address)

PROSPECT_ENABLED = os.getenv("PROSPECT_ENABLED", "true").lower() == "true"
_CACHE_TTL = 6 * 3600

try:
    import redis.asyncio as _aioredis
    _redis = _aioredis.from_url(
        os.getenv("REDIS_URL", "redis://localhost:6379"),
        decode_responses=True,
    )
except ImportError:
    _redis = None
    log.warning("redis package not installed; prospect response caching disabled")


@router.get("/{domain}")
@limiter.limit("20/minute")
async def get_prospect(request: Request, domain: str):
    if not PROSPECT_ENABLED:
        raise HTTPException(status_code=503, detail="Prospect tab is currently disabled.")

    normalized = normalize_domain(domain)
    if not normalized:
        raise HTTPException(
            status_code=400,
            detail="Invalid domain format. Provide a hostname like example.com (no protocol or path).",
        )

    cache_key = f"prospect:{normalized}"

    if _redis is not None:
        try:
            raw = await _redis.get(cache_key)
            if raw:
                data = json.loads(raw)
                data["cached"] = True
                return data
        except Exception as e:
            log.warning("Redis get error for %s: %s", normalized, e)

    dossier = await build_dossier(normalized)

    client_ip = request.client.host if request.client else "unknown"
    write_investigation(
        domain=normalized,
        generated_at=dossier.get("generated_at", ""),
        dossier=dossier,
        client_ip=client_ip,
    )

    if _redis is not None:
        try:
            await _redis.setex(cache_key, _CACHE_TTL, json.dumps(dossier))
        except Exception as e:
            log.warning("Redis set error for %s: %s", normalized, e)

    dossier["cached"] = False
    return dossier
