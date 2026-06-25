import csv
import io
import json
import logging
import re
import sqlite3
import zipfile
from datetime import datetime, timezone, timedelta

import httpx
from fastapi import APIRouter, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import DB_PATH, ABUSECH_AUTH_KEY
from app.database import get_db

router = APIRouter(prefix="/api/threat-pulse", tags=["threat-pulse"])
limiter = Limiter(key_func=get_remote_address)
log = logging.getLogger("falconeye.threat_pulse")

CACHE_TTL_MINUTES = 60  # URLhaus PH feed updates roughly hourly
FETCH_TIMEOUT = 20.0
USER_AGENT = "FalconEye/3.0 (osintph.info; threat research)"

BRAND_PATTERNS = {
    "GCash": ["gcash", "g-cash", "gcsh"],
    "Maya": ["paymaya", "maya"],
    "BPI": ["bpi-", "-bpi.", "bpi.", "bpiexpress", "bankofphilippine"],
    "BDO": ["bdo-", "-bdo.", "bdo.", "bancodeoro"],
    "Landbank": ["landbank", "land-bank", "lbp-"],
    "UnionBank": ["unionbank", "union-bank"],
    "RCBC": ["rcbc"],
    "Metrobank": ["metrobank", "metro-bank"],
    "Shopee": ["shopee"],
    "Lazada": ["lazada"],
}


def detect_brand(url: str) -> str:
    url_lower = url.lower()
    for brand, patterns in BRAND_PATTERNS.items():
        if any(p in url_lower for p in patterns):
            return brand
    return "Other"


def get_cached(db: sqlite3.Connection) -> dict | None:
    """Single-row cache keyed by a fixed string."""
    row = db.execute(
        "SELECT response_json, fetched_at FROM threat_pulse_cache WHERE id = 'ph' LIMIT 1"
    ).fetchone()
    if not row:
        return None
    fetched = datetime.fromisoformat(row["fetched_at"])
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - fetched > timedelta(minutes=CACHE_TTL_MINUTES):
        return None
    data = json.loads(row["response_json"])
    data["cache_hit"] = True
    data["fetched_at"] = row["fetched_at"]
    return data


def store_cache(db: sqlite3.Connection, response: dict) -> None:
    db.execute(
        "INSERT OR REPLACE INTO threat_pulse_cache (id, response_json, fetched_at) VALUES ('ph', ?, CURRENT_TIMESTAMP)",
        (json.dumps(response),),
    )
    db.commit()


async def fetch_urlhaus_ph_feed() -> list[dict]:
    """
    Fetch the URLhaus PH country feed. Returns a list of dicts with url, status,
    dateadded, threat, tags, urlhaus_link.
    The feed at /feeds/country/PH/ returns CSV (or zip-wrapped CSV).
    """
    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT, follow_redirects=True) as client:
            r = await client.get(
                "https://urlhaus.abuse.ch/feeds/country/PH/",
                headers={"User-Agent": USER_AGENT},
            )
            r.raise_for_status()
    except Exception as e:
        log.warning(f"URLhaus PH feed fetch failed: {e}")
        return []

    raw = r.content
    csv_text = None

    if raw[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                name = z.namelist()[0]
                csv_text = z.read(name).decode("utf-8", errors="replace")
        except Exception as e:
            log.warning(f"URLhaus zip decompress failed: {e}")
            return []
    else:
        csv_text = r.text

    if not csv_text:
        return []

    # Feed columns: Dateadded (UTC),URL,URL_status,Threat,Host,IPaddress,ASnumber,Country
    # The header line starts with '#' and is filtered below; data rows start with '"'.
    lines = [l for l in csv_text.splitlines() if not l.startswith("#") and l.strip()]
    reader = csv.DictReader(
        io.StringIO("\n".join(lines)),
        fieldnames=["dateadded", "url", "url_status", "threat", "host", "ip", "asn", "country"],
    )

    entries = []
    for row in reader:
        url = (row.get("url") or "").strip().strip('"')
        if not url or not url.startswith("http"):
            continue
        entries.append({
            "url": url,
            "url_status": (row.get("url_status") or "").strip().strip('"').lower(),
            "dateadded": (row.get("dateadded") or "").strip().strip('"'),
            "threat": (row.get("threat") or "").strip().strip('"'),
            "urlhaus_link": "",
        })
    return entries


def aggregate(entries: list[dict]) -> dict:
    """Compute aggregate stats from the raw URLhaus PH entries."""
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    count_24h = 0
    count_7d = 0
    live_count = 0
    brand_counts = {}

    for e in entries:
        try:
            added = datetime.fromisoformat(e["dateadded"].replace(" ", "T") + "+00:00")
        except Exception:
            added = None

        if added:
            if added >= last_24h:
                count_24h += 1
            if added >= last_7d:
                count_7d += 1

        if e["url_status"] == "online":
            live_count += 1

        brand = detect_brand(e["url"])
        brand_counts[brand] = brand_counts.get(brand, 0) + 1

    # Sort brands by count, move "Other" to end if it would otherwise top the list
    top_brands = sorted(brand_counts.items(), key=lambda x: x[1], reverse=True)
    if len(top_brands) > 1 and top_brands[0][0] == "Other":
        other = top_brands.pop(0)
        top_brands.append(other)

    # Latest 5 entries by dateadded
    sorted_entries = sorted(
        entries,
        key=lambda e: e.get("dateadded") or "",
        reverse=True,
    )[:5]

    latest = []
    for e in sorted_entries:
        latest.append({
            "url": e["url"],
            "url_status": e["url_status"],
            "dateadded": e["dateadded"],
            "brand": detect_brand(e["url"]),
            "threat": e["threat"],
            "urlhaus_link": e["urlhaus_link"],
        })

    return {
        "total_tracked": len(entries),
        "count_24h": count_24h,
        "count_7d": count_7d,
        "live_count": live_count,
        "top_brands": top_brands[:8],
        "latest": latest,
        "cache_hit": False,
    }


@router.get("")
@limiter.limit("30/minute")
async def threat_pulse(request: Request, db: sqlite3.Connection = Depends(get_db)):
    cached = get_cached(db)
    if cached:
        return cached

    entries = await fetch_urlhaus_ph_feed()
    if not entries:
        # Return last-known cache if fetch failed, even if stale
        row = db.execute(
            "SELECT response_json, fetched_at FROM threat_pulse_cache WHERE id = 'ph' LIMIT 1"
        ).fetchone()
        if row:
            data = json.loads(row["response_json"])
            data["cache_hit"] = True
            data["stale"] = True
            data["fetched_at"] = row["fetched_at"]
            return data
        # No cache at all
        return {
            "total_tracked": 0,
            "count_24h": 0,
            "count_7d": 0,
            "live_count": 0,
            "top_brands": [],
            "latest": [],
            "error": "URLhaus PH feed temporarily unavailable.",
            "cache_hit": False,
        }

    result = aggregate(entries)
    store_cache(db, result)
    return result
