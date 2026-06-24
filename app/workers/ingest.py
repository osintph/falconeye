import csv
import hashlib
import io
import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Optional

import httpx

from app.config import DB_PATH, HTTPX_TIMEOUT
from app.utils.ssrf import validate_url

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("falconeye.ingest")

FETCH_TIMEOUT = 15.0  # Feed fetches only — per-URL fingerprinting uses HTTPX_TIMEOUT (3.0s)

BRAND_MAP = {
    "GCash": ["gcash", "g-cash"],
    "Maya": ["maya", "paymaya"],
    "BPI": ["bpi", "bank of the philippine islands"],
    "BDO": ["bdo", "banco de oro"],
    "Landbank": ["landbank", "land bank"],
    "UnionBank": ["unionbank", "union bank"],
    "RCBC": ["rcbc"],
    "Metrobank": ["metrobank", "metro bank"],
    "LBC": ["lbc-express", "lbcexpress"],
    "PHLPost": ["phlpost", "philpost"],
    "PSBank": ["psbank"],
    "EastWest": ["eastwestbank", "eastwest bank"],
}

PH_KEYWORDS = [kw for keywords in BRAND_MAP.values() for kw in keywords] + [
    ".ph/", ".ph?", "-ph.", "-ph/", "philipp", "pilipinas",
]

INDICATORS = [
    {"id": "telegram_exfil", "pattern": "api.telegram.org/bot", "description": "Telegram bot exfiltration endpoint"},
    {"id": "bpi_asset_dir", "pattern": "/BPI_files/", "description": "Cloned BPI asset directory"},
    {"id": "bdo_asset_dir", "pattern": "/cms/bdo/", "description": "Cloned BDO asset directory"},
    {"id": "landbank_dir", "pattern": "/landbank_files/", "description": "Cloned Landbank asset directory"},
    {"id": "gcash_dir", "pattern": "/gcash_files/", "description": "Cloned GCash asset directory"},
    {"id": "php_submit", "pattern": "login_submit.php", "description": "PHP credential capture endpoint"},
    {"id": "php_save_card", "pattern": "save_card.php", "description": "PHP card data capture endpoint"},
    {"id": "otp_capture", "pattern": "otp_verify.php", "description": "PHP OTP capture endpoint"},
]


def detect_brand(url: str) -> str:
    url_lower = url.lower()
    for brand, keywords in BRAND_MAP.items():
        if any(kw in url_lower for kw in keywords):
            return brand
    return "Unknown"


def is_ph_relevant(url: str) -> bool:
    url_lower = url.lower()
    return any(kw in url_lower for kw in PH_KEYWORDS)


def url_hash(url: str) -> str:
    return hashlib.sha256(url.strip().lower().encode()).hexdigest()


def already_stored(db: sqlite3.Connection, url: str) -> bool:
    h = url_hash(url)
    row = db.execute(
        "SELECT id FROM phishing_scans WHERE url_hash = ?", (h,)
    ).fetchone()
    return row is not None


def store_entry(
    db: sqlite3.Connection,
    url: str,
    brand: str,
    source: str,
    indicators: list,
    telegram_bot_id: Optional[str],
    is_live: int,
) -> None:
    h = url_hash(url)
    db.execute(
        """
        INSERT OR IGNORE INTO phishing_scans
            (url_hash, target_brand, phishing_url, telegram_bot_id, kit_indicators, is_live, ingest_source)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (h, brand, url, telegram_bot_id, json.dumps(indicators), is_live, source),
    )
    db.commit()


def extract_telegram_bot_id(html: str) -> Optional[str]:
    marker = "api.telegram.org/bot"
    idx = html.find(marker)
    if idx == -1:
        return None
    start = idx + len(marker)
    end = html.find("/", start)
    if end == -1:
        end = start + 60
    token = html[start:end].strip()
    return token if token else None


async def passive_fingerprint(url: str) -> tuple[list, Optional[str], int]:
    """
    Attempt a passive fetch of the URL and fingerprint it.
    Returns (indicators, telegram_bot_id, is_live).
    Uses HTTPX_TIMEOUT (3.0s) — same as user-initiated scans.
    Silently returns empty results on timeout or error — never raises.
    """
    safe, _ = validate_url(url)
    if not safe:
        return [], None, 0

    try:
        async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT, follow_redirects=True, verify=False) as client:
            response = await client.get(url)
            html = response.text
    except Exception:
        return [], None, 0

    matched = [i for i in INDICATORS if i["pattern"].lower() in html.lower()]
    telegram_bot_id = extract_telegram_bot_id(html)
    return matched, telegram_bot_id, 1


async def ingest_openphish(db: sqlite3.Connection) -> int:
    log.info("Fetching OpenPhish community feed...")
    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as client:
            r = await client.get(
                "https://openphish.com/feed.txt",
                headers={"User-Agent": "FalconEye/2.0 (osintph.info; research)"},
            )
            r.raise_for_status()
    except Exception as e:
        log.error(f"OpenPhish fetch failed: {e}")
        return 0

    urls = [line.strip() for line in r.text.splitlines() if line.strip().startswith("http")]
    ph_urls = [u for u in urls if is_ph_relevant(u)]
    log.info(f"OpenPhish: {len(urls)} total, {len(ph_urls)} PH-relevant")

    stored = 0
    for url in ph_urls:
        if already_stored(db, url):
            continue
        brand = detect_brand(url)
        indicators, telegram_bot_id, is_live = await passive_fingerprint(url)
        store_entry(db, url, brand, "openphish", indicators, telegram_bot_id, is_live)
        stored += 1

    log.info(f"OpenPhish: stored {stored} new entries")
    return stored


async def ingest_urlhaus_ph(db: sqlite3.Connection) -> int:
    log.info("Fetching URLhaus PH country feed...")
    try:
        async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as client:
            r = await client.get(
                "https://urlhaus.abuse.ch/feeds/country/PH/",
                headers={"User-Agent": "FalconEye/2.0 (osintph.info; research)"},
            )
            r.raise_for_status()
    except Exception as e:
        log.error(f"URLhaus PH fetch failed: {e}")
        return 0

    lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
    stored = 0

    reader = csv.DictReader(
        io.StringIO("\n".join(lines)),
        fieldnames=["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"],
    )

    for row in reader:
        url = row.get("url", "").strip()
        if not url or not url.startswith("http"):
            continue
        if already_stored(db, url):
            continue
        brand = detect_brand(url)
        is_live = 1 if row.get("url_status", "").lower() == "online" else 0
        indicators, telegram_bot_id, _ = await passive_fingerprint(url) if is_live else ([], None, 0)
        store_entry(db, url, brand, "urlhaus_ph", indicators, telegram_bot_id, is_live)
        stored += 1

    log.info(f"URLhaus PH: stored {stored} new entries")
    return stored


async def run_all_feeds() -> dict:
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")

    try:
        openphish_count = await ingest_openphish(db)
        urlhaus_count = await ingest_urlhaus_ph(db)
    finally:
        db.close()

    return {
        "openphish": openphish_count,
        "urlhaus_ph": urlhaus_count,
        "total_new": openphish_count + urlhaus_count,
        "ran_at": datetime.now(timezone.utc).isoformat(),
    }
