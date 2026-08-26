import asyncio
import json
import sqlite3
import hashlib
import httpx
from urllib.parse import urlparse
from fastapi import APIRouter, Request, Depends, HTTPException
from pydantic import BaseModel
from slowapi import Limiter
from app.utils.client_ip import get_client_ip, get_client_ip_key
from app.utils.safe_fetch import safe_fetch, SafeFetchError
from app.database import get_db
from app.config import HTTPX_TIMEOUT, KIT_REPORT_RATE_LIMIT_PER_DAY
from app.scanner.ph_bank_indicators import match_ph_indicators, match_age_indicators
from app.scanner.cloudflare_detect import detect_cloudflare_challenge
from app.scanner import kit_report
from app.utils import rate_limit
from app.utils.urlscan import check_urlscan
from app.utils.domain_age import check_domain_age

router = APIRouter(prefix="/api/scanner", tags=["scanner"])
limiter = Limiter(key_func=get_client_ip_key)

_KIT_RL_TABLE = "kit_report_rate_limit"
rate_limit.init_table(_KIT_RL_TABLE)

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
        try:
            result = await safe_fetch(
                payload.url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; FalconEye/3.0)"},
                timeout=HTTPX_TIMEOUT,
            )
            html_content = result["body"]
        except SafeFetchError as e:
            raise HTTPException(status_code=400, detail=f"URL blocked: {e}")
        except httpx.TimeoutException:
            fetch_error = "Request timed out. Site may be offline or blocking automated requests."
        except Exception:
            fetch_error = "Fetch error: could not retrieve the URL."

    if payload.raw_html:
        html_content = payload.raw_html

    matched_indicators = [i for i in INDICATORS if i["pattern"].lower() in html_content.lower()]
    matched_indicators += match_ph_indicators(html_content, phishing_url)
    cf_indicator = detect_cloudflare_challenge(html_content)
    if cf_indicator:
        matched_indicators.append(cf_indicator)
    telegram_bot_id = extract_telegram_bot_id(html_content)
    target_brand = detect_brand(html_content, phishing_url)
    is_live = 1 if html_content and not fetch_error else 0

    urlscan_result: dict = {}
    domain_age_result: dict = {}
    if phishing_url:
        host = urlparse(phishing_url).hostname or ""
        urlscan_result, domain_age_result = await asyncio.gather(
            check_urlscan(phishing_url),
            check_domain_age(host, db),
        )
        matched_indicators += match_age_indicators(domain_age_result)

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
        "urlscan": urlscan_result,
        "domain_age": domain_age_result,
    }


class KitReportRequest(BaseModel):
    url: str | None = None
    raw_html: str | None = None


@router.post("/kit-report")
@limiter.limit("4/minute")
async def kit_report_endpoint(request: Request, payload: KitReportRequest):
    """Deep kit report: acquire, deobfuscate, probe, enrich, score.

    Live mode when a URL is given. Offline mode when the pasted text is a
    JavaScript bundle rather than an HTML page, which is detected here so the
    tab keeps a single textarea for both.

    This is far heavier than /scan (many outbound fetches plus a full bundle
    teardown), so it carries a daily per-IP budget on top of the burst limit.
    """
    url = (payload.url or "").strip()
    pasted = (payload.raw_html or "").strip()

    if not url and not pasted:
        raise HTTPException(status_code=400, detail="Provide a URL or paste a bundle.")

    source_ip = get_client_ip(request)
    allowed, used = rate_limit.check(_KIT_RL_TABLE, source_ip, KIT_REPORT_RATE_LIMIT_PER_DAY)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Daily limit reached ({used}/{KIT_REPORT_RATE_LIMIT_PER_DAY} deep kit "
                "reports per 24 hours). Try again later."
            ),
        )
    rate_limit.record(_KIT_RL_TABLE, source_ip)

    # A pasted bundle wins over a URL: it is the more specific instruction, and
    # it is the offline path for a target that is already dead.
    if pasted and kit_report.looks_like_javascript(pasted):
        return kit_report.build_offline_report(pasted)

    if not url:
        raise HTTPException(
            status_code=400,
            detail=(
                "Pasted text looks like an HTML page, not a JavaScript bundle. "
                "Add the URL it came from and it will be analyzed as that "
                "target's page, or paste the JavaScript bundle instead."
            ),
        )

    if not urlparse(url).scheme:
        url = f"https://{url}"

    try:
        # A URL plus pasted HTML means the operator could reach the target and
        # FalconEye could not, which is the normal case for a kit geofenced to
        # its victim country. Use their body, keep our enrichment.
        return await kit_report.build_live_report(url, pasted_html=pasted)
    except SafeFetchError as exc:
        raise HTTPException(status_code=400, detail=f"URL blocked: {exc}")


@router.get("/history")
@limiter.limit("30/minute")
async def scan_history(request: Request, db: sqlite3.Connection = Depends(get_db)):
    rows = db.execute(
        "SELECT * FROM phishing_scans ORDER BY date_scanned DESC LIMIT 50"
    ).fetchall()
    return [dict(row) for row in rows]
