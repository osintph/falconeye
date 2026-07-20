"""AbuseIPDB — abuse-confidence scoring. Free tier 1000 checks/day."""
import httpx

from app.utils.env import getenv_clean
from app.ip_sources.base import SourceResult, FETCH_TIMEOUT, USER_AGENT, OK, NO_KEY, QUOTA, ERROR

# AbuseIPDB report category IDs -> labels
_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


async def fetch(ip: str, client: httpx.AsyncClient) -> SourceResult:
    key = getenv_clean("ABUSEIPDB_KEY")
    if not key:
        return SourceResult("abuseipdb", False, NO_KEY, {}, "no API key configured")
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": key, "Accept": "application/json", "User-Agent": USER_AGENT},
            timeout=FETCH_TIMEOUT,
        )
    except Exception as exc:
        return SourceResult("abuseipdb", False, ERROR, {}, type(exc).__name__)

    if r.status_code == 429:
        return SourceResult("abuseipdb", False, QUOTA, {}, "daily quota reached")
    if r.status_code in (401, 403):
        return SourceResult("abuseipdb", False, ERROR, {}, "authentication failed")
    if r.status_code != 200:
        return SourceResult("abuseipdb", False, ERROR, {}, f"HTTP {r.status_code}")

    try:
        d = r.json().get("data", {})
    except Exception:
        return SourceResult("abuseipdb", False, ERROR, {}, "malformed response")

    cat_ids = sorted({c for rep in (d.get("reports") or []) for c in (rep.get("categories") or [])})
    data = {
        "confidence": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "distinct_users": d.get("numDistinctUsers"),
        "last_reported": d.get("lastReportedAt"),
        "usage_type": d.get("usageType"),
        "isp": d.get("isp"),
        "categories": [_CATEGORIES.get(c, f"Category {c}") for c in cat_ids][:12],
    }
    return SourceResult("abuseipdb", True, OK, data, None, d.get("countryCode"))
