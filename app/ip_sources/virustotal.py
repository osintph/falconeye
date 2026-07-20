"""VirusTotal v3 — multi-vendor detection. Free tier 500/day, 4/min."""
import httpx

from app.utils.env import getenv_clean
from app.ip_sources.base import SourceResult, FETCH_TIMEOUT, USER_AGENT, OK, NO_KEY, QUOTA, ERROR


async def fetch(ip: str, client: httpx.AsyncClient) -> SourceResult:
    key = getenv_clean("VT_KEY")
    if not key:
        return SourceResult("virustotal", False, NO_KEY, {}, "no API key configured")
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key, "Accept": "application/json", "User-Agent": USER_AGENT},
            timeout=FETCH_TIMEOUT,
        )
    except Exception as exc:
        return SourceResult("virustotal", False, ERROR, {}, type(exc).__name__)

    if r.status_code == 429:
        return SourceResult("virustotal", False, QUOTA, {}, "rate limit reached (500/day or 4/min)")
    if r.status_code in (401, 403):
        return SourceResult("virustotal", False, ERROR, {}, "authentication failed")
    if r.status_code != 200:
        return SourceResult("virustotal", False, ERROR, {}, f"HTTP {r.status_code}")

    try:
        attrs = r.json().get("data", {}).get("attributes", {})
    except Exception:
        return SourceResult("virustotal", False, ERROR, {}, "malformed response")

    stats = attrs.get("last_analysis_stats", {}) or {}
    results = attrs.get("last_analysis_results", {}) or {}
    flagged = sorted(
        v.get("engine_name", name)
        for name, v in results.items()
        if isinstance(v, dict) and v.get("category") == "malicious"
    )
    data = {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": sum(v for v in stats.values() if isinstance(v, int)),
        "flagged_vendors": flagged[:20],
        "as_owner": attrs.get("as_owner"),
    }
    return SourceResult("virustotal", True, OK, data, None, attrs.get("country"))
