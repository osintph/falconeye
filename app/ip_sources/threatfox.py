"""
ThreatFox (abuse.ch) — IOC matches with malware family. Free.

abuse.ch made Auth-Key mandatory in 2024; ThreatFox uses the same auth.abuse.ch
key as URLhaus, so we reuse the existing ABUSECH_AUTH_KEY.
"""
import json

import httpx

from app.utils.env import getenv_clean
from app.ip_sources.base import SourceResult, FETCH_TIMEOUT, USER_AGENT, OK, NO_KEY, ERROR, NOT_FOUND


async def fetch(ip: str, client: httpx.AsyncClient) -> SourceResult:
    key = getenv_clean("ABUSECH_AUTH_KEY")
    if not key:
        return SourceResult("threatfox", False, NO_KEY, {}, "no abuse.ch Auth-Key configured")
    try:
        r = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": key, "Accept": "application/json", "User-Agent": USER_AGENT},
            content=json.dumps({"query": "search_ioc", "search_term": ip}),
            timeout=FETCH_TIMEOUT,
        )
    except Exception as exc:
        return SourceResult("threatfox", False, ERROR, {}, type(exc).__name__)

    if r.status_code in (401, 403):
        return SourceResult("threatfox", False, ERROR, {}, "authentication failed")
    if r.status_code != 200:
        return SourceResult("threatfox", False, ERROR, {}, f"HTTP {r.status_code}")

    try:
        d = r.json()
    except Exception:
        return SourceResult("threatfox", False, ERROR, {}, "malformed response")

    status = d.get("query_status")
    if status == "no_result":
        return SourceResult("threatfox", True, NOT_FOUND, {"matched": False, "iocs": []}, None)
    if status != "ok":
        return SourceResult("threatfox", False, ERROR, {}, str(status)[:80])

    rows = d.get("data") if isinstance(d.get("data"), list) else []
    iocs = [{
        "malware": row.get("malware_printable") or row.get("malware"),
        "threat_type": row.get("threat_type"),
        "confidence": row.get("confidence_level"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
    } for row in rows[:10]]
    return SourceResult("threatfox", True, OK, {"matched": bool(iocs), "iocs": iocs}, None)
