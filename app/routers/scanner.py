import uuid
import json
import sqlite3
import httpx
from fastapi import APIRouter, Request, Depends, HTTPException
from bs4 import BeautifulSoup
from pydantic import BaseModel
from app.utils.ssrf import validate_url
from app.utils.ratelimit import limiter
from app.database import get_db
from app.config import HTTPX_TIMEOUT

router = APIRouter(prefix="/api/scanner", tags=["scanner"])

# PH phishing kit fingerprint signatures
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

BRAND_KEYWORDS = {
    "BPI": ["bpi", "bank of the philippine islands"],
    "BDO": ["bdo", "banco de oro"],
    "GCash": ["gcash", "g-cash"],
    "Maya": ["maya", "paymaya"],
    "Landbank": ["landbank", "land bank"],
    "UnionBank": ["unionbank", "union bank"],
    "RCBC": ["rcbc"],
    "Metrobank": ["metrobank", "metro bank"],
}


def extract_telegram_bot_id(html: str) -> str | None:
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


def detect_brand(html: str, url: str) -> str:
    combined = (html + url).lower()
    for brand, keywords in BRAND_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            return brand
    return "Unknown"


class ScanRequest(BaseModel):
    url: str | None = None
    raw_html: str | None = None


@router.post("/scan")
@limiter.limit("10/minute")
async def scan_phishing(request: Request, payload: ScanRequest, db: sqlite3.Connection = Depends(get_db)):
    if not payload.url and not payload.raw_html:
        raise HTTPException(status_code=400, detail="Provide either a URL or raw HTML.")

    html_content = ""
    phishing_url = payload.url or ""
    fetch_error = None

    if payload.url:
        safe, reason = validate_url(payload.url)
        if not safe:
            raise HTTPException(status_code=400, detail=f"URL blocked: {reason}")

        try:
            async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT, follow_redirects=True, verify=False) as client:
                response = await client.get(payload.url)
                html_content = response.text
        except httpx.TimeoutException:
            fetch_error = "Request timed out after 3 seconds. Site may be offline."
            html_content = ""
        except Exception as e:
            fetch_error = f"Fetch error: {str(e)}"
            html_content = ""

    if payload.raw_html:
        html_content = payload.raw_html

    matched_indicators = []
    for indicator in INDICATORS:
        if indicator["pattern"].lower() in html_content.lower():
            matched_indicators.append({
                "id": indicator["id"],
                "description": indicator["description"],
                "pattern": indicator["pattern"],
            })

    telegram_bot_id = extract_telegram_bot_id(html_content)
    target_brand = detect_brand(html_content, phishing_url)
    is_live = 1 if html_content and not fetch_error else 0

    job_id = uuid.uuid4().hex

    if phishing_url or matched_indicators:
        db.execute(
            """
            INSERT INTO phishing_scans (target_brand, phishing_url, telegram_bot_id, kit_indicators, is_live)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                target_brand,
                phishing_url,
                telegram_bot_id,
                json.dumps(matched_indicators),
                is_live,
            ),
        )
        db.commit()

    return {
        "job_id": job_id,
        "url": phishing_url,
        "is_live": bool(is_live),
        "target_brand": target_brand,
        "telegram_bot_id": telegram_bot_id,
        "indicators_matched": len(matched_indicators),
        "indicators": matched_indicators,
        "fetch_error": fetch_error,
    }


@router.get("/history")
@limiter.limit("30/minute")
async def scan_history(request: Request, db: sqlite3.Connection = Depends(get_db)):
    rows = db.execute(
        "SELECT * FROM phishing_scans ORDER BY date_scanned DESC LIMIT 50"
    ).fetchall()
    return [dict(row) for row in rows]
