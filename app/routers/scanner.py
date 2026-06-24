import json
import sqlite3
import hashlib
import httpx
from fastapi import APIRouter, Request, Depends, HTTPException
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.utils.ssrf import validate_url
from app.database import get_db
from app.config import HTTPX_TIMEOUT

router = APIRouter(prefix="/api/scanner", tags=["scanner"])
limiter = Limiter(key_func=get_remote_address)

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
    "BPI": ["bpi-", "-bpi.", "bpiexpressonline", "bankofphilippine"],
    "BDO": ["bdo-", "-bdo.", "bancodeoro", "bdoonline"],
    "GCash": ["gcash", "g-cash"],
    "Maya": ["maya", "paymaya"],
    "Landbank": ["landbank", "land-bank"],
    "UnionBank": ["unionbank", "union-bank"],
    "RCBC": ["rcbc"],
    "Metrobank": ["metrobank"],
}


def detect_brand(html: str, url: str) -> str:
    combined = (html + url).lower()
    for brand, keywords in BRAND_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            return brand
    return "Unknown"


def extract_telegram_bot_id(html: str) -> str | None:
    marker = "api.telegram.org/bot"
    idx = html.find(marker)
    if idx == -1:
        return None
    start = idx + len(marker)
    end = html.find("/", start)
    token = html[start:end if end != -1 else start + 60].strip()
    return token if token else None


class ScanRequest(BaseModel):
    url: str | None = None
    raw_html: str | None = None


@router.post("/scan")
@limiter.limit("10/minute")
async def scan_phishing(request: Request, payload: ScanRequest, db: sqlite3.Connection = Depends(get_db)):
    if not payload.url and not payload.raw_html:
        raise HTTPException(status_code=400, detail="Provide a URL or raw HTML.")

    html_content = ""
    phishing_url = payload.url or ""
    fetch_error = None

    if payload.url:
        safe, reason = validate_url(payload.url)
        if not safe:
            raise HTTPException(status_code=400, detail=f"URL blocked: {reason}")
        try:
            async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT, follow_redirects=True, verify=False) as client:
                response = await client.get(payload.url, headers={"User-Agent": "Mozilla/5.0 (compatible; FalconEye/3.0)"})
                html_content = response.text
        except httpx.TimeoutException:
            fetch_error = "Request timed out. Site may be offline or blocking automated requests."
        except Exception as e:
            fetch_error = f"Fetch error: {str(e)}"

    if payload.raw_html:
        html_content = payload.raw_html

    matched_indicators = [i for i in INDICATORS if i["pattern"].lower() in html_content.lower()]
    telegram_bot_id = extract_telegram_bot_id(html_content)
    target_brand = detect_brand(html_content, phishing_url)
    is_live = 1 if html_content and not fetch_error else 0

    if phishing_url:
        h = hashlib.sha256(phishing_url.strip().lower().encode()).hexdigest()
        db.execute(
            "INSERT OR IGNORE INTO phishing_scans (url_hash, target_brand, phishing_url, telegram_bot_id, kit_indicators, is_live) VALUES (?,?,?,?,?,?)",
            (h, target_brand, phishing_url, telegram_bot_id, json.dumps(matched_indicators), is_live),
        )
        db.commit()

    return {
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
