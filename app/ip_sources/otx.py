"""AlienVault OTX — community pulses. Free with API key."""
import httpx

from app.utils.env import getenv_clean
from app.ip_sources.base import SourceResult, FETCH_TIMEOUT, USER_AGENT, OK, NO_KEY, QUOTA, ERROR


async def fetch(ip: str, client: httpx.AsyncClient) -> SourceResult:
    key = getenv_clean("OTX_API_KEY")
    if not key:
        return SourceResult("otx", False, NO_KEY, {}, "no API key configured")
    try:
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": key, "Accept": "application/json", "User-Agent": USER_AGENT},
            timeout=FETCH_TIMEOUT,
        )
    except Exception as exc:
        return SourceResult("otx", False, ERROR, {}, type(exc).__name__)

    if r.status_code == 429:
        return SourceResult("otx", False, QUOTA, {}, "rate limit reached")
    if r.status_code in (401, 403):
        return SourceResult("otx", False, ERROR, {}, "authentication failed")
    if r.status_code != 200:
        return SourceResult("otx", False, ERROR, {}, f"HTTP {r.status_code}")

    try:
        d = r.json()
    except Exception:
        return SourceResult("otx", False, ERROR, {}, "malformed response")

    pinfo = d.get("pulse_info", {}) or {}
    pulses = pinfo.get("pulses", []) or []
    families = sorted({
        m for p in pulses for m in (p.get("malware_families") or [])
        if isinstance(m, str)
    })
    data = {
        "pulse_count": pinfo.get("count", len(pulses)),
        "pulse_names": [p.get("name") for p in pulses if p.get("name")][:8],
        "malware_families": families[:10],
        "tags": sorted({t for p in pulses for t in (p.get("tags") or [])})[:12],
    }
    return SourceResult("otx", True, OK, data, None, d.get("country_code"))
