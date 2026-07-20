"""
Censys Platform — host services / ports. Free tier includes host lookup.

Auth: Personal Access Token as `Authorization: Bearer`. The PAT is org-scoped,
so no organization_id is needed (a bad/placeholder org id returns 422). We send
`X-Organization-ID` ONLY if CENSYS_ORG_ID is a real UUID, so it "just works" if
a valid one is configured later; otherwise PAT-only.
"""
import re

import httpx

from app.utils.env import getenv_clean
from app.ip_sources.base import SourceResult, FETCH_TIMEOUT, USER_AGENT, OK, NO_KEY, QUOTA, ERROR, NOT_FOUND

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


async def fetch(ip: str, client: httpx.AsyncClient) -> SourceResult:
    pat = getenv_clean("CENSYS_PAT")
    if not pat:
        return SourceResult("censys", False, NO_KEY, {}, "no PAT configured")

    headers = {"Authorization": f"Bearer {pat}", "Accept": "application/json", "User-Agent": USER_AGENT}
    org = getenv_clean("CENSYS_ORG_ID")
    if org and _UUID_RE.match(org):
        headers["X-Organization-ID"] = org

    try:
        r = await client.get(
            f"https://api.platform.censys.io/v3/global/asset/host/{ip}",
            headers=headers, timeout=FETCH_TIMEOUT,
        )
    except Exception as exc:
        return SourceResult("censys", False, ERROR, {}, type(exc).__name__)

    if r.status_code == 429:
        return SourceResult("censys", False, QUOTA, {}, "rate limit reached")
    if r.status_code in (401, 403):
        return SourceResult("censys", False, ERROR, {}, "authentication failed")
    if r.status_code == 404:
        return SourceResult("censys", True, NOT_FOUND, {"ports": []}, None)
    if r.status_code != 200:
        return SourceResult("censys", False, ERROR, {}, f"HTTP {r.status_code}")

    try:
        res = r.json().get("result", {}).get("resource", {})
    except Exception:
        return SourceResult("censys", False, ERROR, {}, "malformed response")

    ports = []
    for s in (res.get("services") or []):
        if s.get("port") is not None:
            ports.append({
                "port": s.get("port"),
                "service": s.get("protocol") or s.get("extended_service_name") or s.get("service_name"),
                "transport": s.get("transport_protocol"),
            })
    loc = res.get("location") or {}
    asys = res.get("autonomous_system") or {}
    os_info = res.get("operating_system") or {}
    data = {
        "ports": ports,
        "os": " ".join(filter(None, [os_info.get("vendor"), os_info.get("product")])) or None,
        "asn": asys.get("asn"),
        "asn_name": asys.get("name"),
        "asn_country": asys.get("country_code"),
        "last_updated": (res.get("services") or [{}])[0].get("scan_time") if ports else None,
    }
    return SourceResult("censys", True, OK, data, None, loc.get("country_code"))
