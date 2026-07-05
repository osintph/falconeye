import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta

import httpx
from bs4 import BeautifulSoup
from fastapi import APIRouter, Depends, HTTPException, Request
from slowapi import Limiter

from app.config import DB_PATH
from app.database import get_db
from app.utils.client_ip import get_client_ip_key
from app.utils.telegram import (
    normalize_channel,
    extract_iocs,
    detect_brands,
    aggregate_iocs,
)

router = APIRouter(prefix="/api/telegram", tags=["telegram"])
limiter = Limiter(key_func=get_client_ip_key)
log = logging.getLogger("falconeye.telegram")

CACHE_TTL_HOURS = 6
FETCH_TIMEOUT = 15.0
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


# ---- Cache helpers ----

def get_cached(db: sqlite3.Connection, channel: str) -> dict | None:
    row = db.execute(
        "SELECT response_json, fetched_at FROM telegram_cache WHERE channel = ?", (channel,)
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


def store_cache(db: sqlite3.Connection, channel: str, response: dict) -> None:
    db.execute(
        "INSERT OR REPLACE INTO telegram_cache (channel, response_json, fetched_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
        (channel, json.dumps(response)),
    )
    db.commit()


# ---- Telegram preview parser ----

def parse_telegram_preview(html: str, channel: str) -> dict:
    """
    Parse the t.me/s/{channel} HTML preview page.
    Returns channel metadata and a list of messages with extracted IOCs.
    """
    soup = BeautifulSoup(html, "lxml")

    title_el = soup.select_one(".tgme_channel_info_header_title span")
    title = title_el.get_text(strip=True) if title_el else channel

    username_el = soup.select_one(".tgme_channel_info_header_username a")
    username = username_el.get_text(strip=True) if username_el else f"@{channel}"

    desc_el = soup.select_one(".tgme_channel_info_description")
    description = desc_el.get_text(strip=True) if desc_el else ""

    counters = {}
    for counter in soup.select(".tgme_channel_info_counter"):
        value_el = counter.select_one(".counter_value")
        type_el = counter.select_one(".counter_type")
        if value_el and type_el:
            counters[type_el.get_text(strip=True).lower()] = value_el.get_text(strip=True)

    photo_el = soup.select_one(".tgme_page_photo_image, .tgme_channel_info_header img")
    photo_url = photo_el.get("src") if photo_el else None

    messages = []
    for msg_el in soup.select(".tgme_widget_message"):
        data_post = msg_el.get("data-post", "")
        msg_id = data_post.split("/")[-1] if data_post else None
        msg_link = f"https://t.me/{data_post}" if data_post else None

        body_el = msg_el.select_one(".tgme_widget_message_text")
        body_text = body_el.get_text(separator="\n", strip=True) if body_el else ""

        time_el = msg_el.select_one(".tgme_widget_message_date time")
        timestamp = time_el.get("datetime") if time_el else None

        views_el = msg_el.select_one(".tgme_widget_message_views")
        views = views_el.get_text(strip=True) if views_el else None

        forward_el = msg_el.select_one(".tgme_widget_message_forwarded_from_name")
        forwarded_from = forward_el.get_text(strip=True) if forward_el else None

        media_descriptions = []
        for media in msg_el.select(".tgme_widget_message_document_title, .tgme_widget_message_video_title, .tgme_widget_message_photo_wrap"):
            label = media.get_text(strip=True) if hasattr(media, "get_text") else ""
            if label:
                media_descriptions.append(label)
            alt = media.get("alt") if hasattr(media, "get") else None
            if alt:
                media_descriptions.append(alt)

        inline_links = []
        if body_el:
            for a in body_el.select("a[href]"):
                href = a.get("href", "").strip()
                if href.startswith("http"):
                    inline_links.append(href)

        combined_text = body_text + "\n" + "\n".join(inline_links) + "\n" + "\n".join(media_descriptions)
        iocs = extract_iocs(combined_text)
        brands = detect_brands(combined_text)

        messages.append({
            "id": msg_id,
            "link": msg_link,
            "timestamp": timestamp,
            "body": body_text[:2000],
            "views": views,
            "forwarded_from": forwarded_from,
            "media_descriptions": media_descriptions[:10],
            "inline_links": inline_links[:20],
            "iocs": iocs,
            "brands": brands,
        })

    aggregated = aggregate_iocs(messages)

    return {
        "channel": channel,
        "title": title,
        "username": username,
        "description": description[:2000],
        "subscribers": counters.get("subscribers", ""),
        "photos": counters.get("photos", ""),
        "videos": counters.get("videos", ""),
        "files": counters.get("files", ""),
        "links": counters.get("links", ""),
        "photo_url": photo_url,
        "message_count": len(messages),
        "messages": messages,
        "aggregated_iocs": aggregated,
        "cache_hit": False,
    }


# ---- Endpoint ----

@router.get("/lookup/{channel}")
@limiter.limit("10/minute")
async def lookup_channel(request: Request, channel: str, db: sqlite3.Connection = Depends(get_db)):
    normalized = normalize_channel(channel)
    if not normalized:
        raise HTTPException(
            status_code=400,
            detail="Invalid channel format. Provide @channelname, channelname, or a t.me/ URL.",
        )

    cached = get_cached(db, normalized)
    if cached:
        return cached

    url = f"https://t.me/s/{normalized}"
    try:
        async with httpx.AsyncClient(
            timeout=FETCH_TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"},
        ) as client:
            r = await client.get(url)
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Telegram request timed out. Try again in a moment.")
    except Exception as e:
        log.warning("Telegram fetch failed for %s: %s", normalized, e)
        raise HTTPException(status_code=502, detail="Telegram fetch error. Try again in a moment.")

    if r.status_code == 404:
        raise HTTPException(status_code=404, detail="Channel not found or has no public preview.")
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Telegram returned {r.status_code}.")

    html = r.text

    if "tgme_channel_info" not in html and ".tgme_widget_message" not in html:
        raise HTTPException(
            status_code=404,
            detail="Channel has no public preview, is private, or does not exist.",
        )

    parsed = parse_telegram_preview(html, normalized)

    if parsed["message_count"] == 0 and not parsed["title"]:
        raise HTTPException(
            status_code=404,
            detail="No messages or metadata found for this channel.",
        )

    store_cache(db, normalized, parsed)
    return parsed
