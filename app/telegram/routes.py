"""
Telegram Intelligence API.

  POST /api/telegram/lookup
    Body: {"query": str}   — @handle, bare username, or any t.me link
    Auth: none (public tool)
    Rate limit: 10/minute per IP (burst only; results cache 6h)

Tier 1 (free scrape) always runs first. If it can't resolve the identifier at
all (t.me shows the same generic fallback page for "doesn't exist" and "exists
but no public page" — see tier1_scrape's docstring), tier 3 gets a chance to
resolve it via MTProto before this returns a 404 — the free tier's ambiguity
should never produce a false "not found" when a better tier is available and
authenticated. Tier 2 and tier 3 run concurrently once an entity type is known.
"""
import asyncio
import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from slowapi import Limiter

from app.telegram import entity, store, tier1_scrape, tier2_bot, tier3_mtproto
from app.utils.client_ip import get_client_ip_key

router = APIRouter(prefix="/api/telegram", tags=["telegram"])
limiter = Limiter(key_func=get_client_ip_key)
log = logging.getLogger("falconeye.telegram")


class LookupRequest(BaseModel):
    query: str


def _pick(*candidates: tuple) -> dict:
    for value, source in candidates:
        if value not in (None, "", []):
            return {"value": value, "source": source}
    return {"value": None, "source": None}


def _merge_header(identifier: str, t1: dict, t2: dict, t3: dict) -> dict:
    t1d = t1.get("data") or {}
    t2d = t2.get("data") or {}
    t3d = t3.get("data") or {}

    entity_type = t3d.get("entity_type") or t1d.get("entity_type") or "unknown"

    return {
        "entity_type": entity_type,
        "handle": f"@{identifier}",
        "canonical_url": f"https://t.me/{identifier}",
        "display_name": _pick((t3d.get("display_name"), "mtproto"), (t2d.get("title"), "bot_api"), (t1d.get("display_name"), "scrape")),
        "bio": _pick((t3d.get("bio"), "mtproto"), (t2d.get("description") or t2d.get("bio"), "bot_api"), (t1d.get("description"), "scrape")),
        "verified": _pick((t3d.get("verified"), "mtproto"), (t1d.get("verified"), "scrape")),
        "scam": _pick((t3d.get("scam"), "mtproto")),
        "fake": _pick((t3d.get("fake"), "mtproto")),
        "member_count": _pick((t3d.get("member_count"), "mtproto"), (t2d.get("member_count"), "bot_api"), (t1d.get("member_count"), "scrape")),
        "photo_url": _pick((t1d.get("photo_url"), "scrape")),
        "dc_location": _pick((t3d.get("dc_location"), "mtproto")),
        "account_era_estimate": _pick((t3d.get("account_era_estimate"), "mtproto")),
        "premium": _pick((t3d.get("premium"), "mtproto")),
    }


@router.post("/lookup")
@limiter.limit("10/minute")
async def lookup(req: LookupRequest, request: Request):
    identifier = entity.normalize_query(req.query or "")
    if not identifier:
        raise HTTPException(status_code=400, detail="Invalid input. Provide a username, @handle, or t.me link.")

    cached = store.get_cached(identifier)
    if cached:
        return cached

    t1 = await tier1_scrape.run(identifier)

    if t1["state"] == tier1_scrape.UNRESOLVED:
        # Ambiguous at the free tier (t.me can't tell us "doesn't exist" from
        # "exists but no public page") — give MTProto a chance before 404ing.
        t3 = await tier3_mtproto.run(identifier)
        if t3["state"] == tier3_mtproto.NOT_FOUND:
            raise HTTPException(status_code=404, detail="No Telegram entity found for this username.")
        if t3["state"] != tier3_mtproto.OK:
            raise HTTPException(
                status_code=404,
                detail=f"No public t.me page found, and MTProto could not verify further ({t3['error']}). "
                       "It may be private, deleted, or nonexistent.",
            )
        entity_type = t3["data"]["entity_type"]
        t2 = await tier2_bot.run(identifier, entity_type)
    else:
        entity_type = t1["data"]["entity_type"]
        t2, t3 = await asyncio.gather(
            tier2_bot.run(identifier, entity_type),
            tier3_mtproto.run(identifier),
        )

    header = _merge_header(identifier, t1, t2, t3)

    messages = t1["data"].get("messages", []) if t1.get("ok") else []
    text_blobs = [header["bio"]["value"] or ""] + [m.get("body", "") for m in messages]
    iocs = entity.aggregate_iocs(text_blobs, exclude_handle=identifier)

    result = {
        "query": req.query,
        "identifier": identifier,
        "header": header,
        "tiers": {"tier1": t1, "tier2": t2, "tier3": t3},
        "messages": messages,
        "iocs": iocs,
        "cache_hit": False,
    }
    store.store_cache(identifier, result)
    return result
