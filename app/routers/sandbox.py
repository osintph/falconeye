import asyncio
import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import DB_PATH, ABUSECH_AUTH_KEY
from app.database import get_db
from app.utils.indicator import classify_indicator

router = APIRouter(prefix="/api/sandbox", tags=["sandbox"])
limiter = Limiter(key_func=get_remote_address)
log = logging.getLogger("falconeye.sandbox")

CACHE_TTL_HOURS = 6
FETCH_TIMEOUT = 10.0
USER_AGENT = "FalconEye/3.0 (osintph.info)"


def get_cached(db: sqlite3.Connection, key: str) -> dict | None:
    row = db.execute(
        "SELECT response_json, fetched_at FROM sandbox_cache WHERE indicator_key = ?", (key,)
    ).fetchone()
    if not row:
        return None
    fetched = datetime.fromisoformat(row["fetched_at"])
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - fetched > timedelta(hours=CACHE_TTL_HOURS):
        return None
    data = json.loads(row["response_json"])
    data["cache_hit"] = True
    data["fetched_at"] = row["fetched_at"]
    return data


def store_cache(db: sqlite3.Connection, key: str, response: dict) -> None:
    db.execute(
        "INSERT OR REPLACE INTO sandbox_cache (indicator_key, response_json, fetched_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
        (key, json.dumps(response)),
    )
    db.commit()


async def fetch_urlhaus_url(client: httpx.AsyncClient, url: str) -> dict | None:
    if not ABUSECH_AUTH_KEY:
        return None
    try:
        r = await client.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=FETCH_TIMEOUT,
            headers={"Auth-Key": ABUSECH_AUTH_KEY, "User-Agent": USER_AGENT},
        )
        if r.status_code == 200:
            return r.json()
        return None
    except Exception as e:
        log.warning(f"URLhaus URL exception: {e}")
        return None


async def fetch_urlhaus_payload(client: httpx.AsyncClient, hash_type: str, hash_value: str) -> dict | None:
    if not ABUSECH_AUTH_KEY:
        return None
    if hash_type not in ("md5", "sha256"):
        return None
    try:
        r = await client.post(
            "https://urlhaus-api.abuse.ch/v1/payload/",
            data={f"{hash_type}_hash": hash_value},
            timeout=FETCH_TIMEOUT,
            headers={"Auth-Key": ABUSECH_AUTH_KEY, "User-Agent": USER_AGENT},
        )
        if r.status_code == 200:
            return r.json()
        return None
    except Exception as e:
        log.warning(f"URLhaus payload exception: {e}")
        return None


async def fetch_malwarebazaar(client: httpx.AsyncClient, hash_value: str) -> dict | None:
    """MalwareBazaar accepts md5, sha1, or sha256 in a single `hash` field."""
    if not ABUSECH_AUTH_KEY:
        return None
    try:
        r = await client.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": hash_value},
            timeout=FETCH_TIMEOUT,
            headers={"Auth-Key": ABUSECH_AUTH_KEY, "User-Agent": USER_AGENT},
        )
        if r.status_code == 200:
            return r.json()
        return None
    except Exception as e:
        log.warning(f"MalwareBazaar exception: {e}")
        return None


@router.get("/lookup")
@limiter.limit("20/minute")
async def lookup_indicator(request: Request, indicator: str, db: sqlite3.Connection = Depends(get_db)):
    ind_type, normalized = classify_indicator(indicator)
    if not ind_type:
        raise HTTPException(
            status_code=400,
            detail="Unrecognized indicator. Provide a URL (http:// or https://) or a hash (MD5/SHA1/SHA256).",
        )

    cache_key = f"{ind_type}:{normalized}"
    cached = get_cached(db, cache_key)
    if cached:
        return cached

    response = {
        "indicator": normalized,
        "indicator_type": ind_type,
        "urlhaus_url": None,
        "urlhaus_payload": None,
        "malwarebazaar": None,
        "cache_hit": False,
    }

    async with httpx.AsyncClient() as client:
        if ind_type == "url":
            response["urlhaus_url"] = await fetch_urlhaus_url(client, normalized)
        else:
            tasks = [fetch_malwarebazaar(client, normalized)]
            if ind_type in ("md5", "sha256"):
                tasks.insert(0, fetch_urlhaus_payload(client, ind_type, normalized))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, r in enumerate(results):
                if isinstance(r, Exception):
                    results[i] = None

            if ind_type in ("md5", "sha256"):
                response["urlhaus_payload"] = results[0]
                response["malwarebazaar"] = results[1]
            else:
                response["malwarebazaar"] = results[0]

    store_cache(db, cache_key, response)
    return response
