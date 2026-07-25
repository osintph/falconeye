"""Shared abuse.ch client.

Centralizes the ABUSECH_AUTH_KEY, the User-Agent, and the POST-with-Auth-Key +
error-handling that were hand-rolled separately in the Sandbox, IP Reputation,
and PH Threat Pulse tabs. Each lookup returns the parsed JSON dict, or None on a
missing key / non-200 / transport error (callers already treat None as
"source unavailable").

The auth-keyed endpoints take an httpx.AsyncClient from the caller (so several
lookups can share one connection pool, as the callers already do). The keyless
country feed manages its own client since it is a standalone fetch.

ThreatFox (also abuse.ch, also ABUSECH_AUTH_KEY) is intentionally NOT routed
through here: it lives in app/ip_sources/threatfox.py with the SourceResult
state model and the ip_sources aggregation contract, which this thin client
doesn't model.
"""
import logging

import httpx

from app.config import ABUSECH_AUTH_KEY

log = logging.getLogger("falconeye.abusech")

_URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"
_MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
_URLHAUS_FEED = "https://urlhaus.abuse.ch/feeds"
USER_AGENT = "FalconEye/3.0 (osintph.info)"
TIMEOUT = 10.0


def configured() -> bool:
    """True if ABUSECH_AUTH_KEY is set (the auth-keyed lookups need it)."""
    return bool(ABUSECH_AUTH_KEY)


async def _post(client: httpx.AsyncClient, url: str, data: dict) -> dict | None:
    if not ABUSECH_AUTH_KEY:
        return None
    try:
        r = await client.post(
            url, data=data, timeout=TIMEOUT,
            headers={"Auth-Key": ABUSECH_AUTH_KEY, "User-Agent": USER_AGENT},
        )
    except Exception as exc:
        log.warning("abuse.ch POST %s exception: %s", url, exc)
        return None
    if r.status_code == 200:
        return r.json()
    log.warning("abuse.ch POST %s returned %s", url, r.status_code)
    return None


async def urlhaus_host(client: httpx.AsyncClient, host: str) -> dict | None:
    """URLhaus host (IP/domain) history lookup."""
    return await _post(client, f"{_URLHAUS_API}/host/", {"host": host})


async def urlhaus_url(client: httpx.AsyncClient, url: str) -> dict | None:
    """URLhaus URL lookup."""
    return await _post(client, f"{_URLHAUS_API}/url/", {"url": url})


async def urlhaus_payload(client: httpx.AsyncClient, hash_type: str, hash_value: str) -> dict | None:
    """URLhaus payload (file-hash) lookup. hash_type must be md5 or sha256."""
    if hash_type not in ("md5", "sha256"):
        return None
    return await _post(client, f"{_URLHAUS_API}/payload/", {f"{hash_type}_hash": hash_value})


async def malwarebazaar(client: httpx.AsyncClient, hash_value: str) -> dict | None:
    """MalwareBazaar get_info by md5/sha1/sha256 hash."""
    return await _post(client, _MALWAREBAZAAR_API, {"query": "get_info", "hash": hash_value})


async def urlhaus_country_feed(cc: str, timeout: float = 20.0) -> httpx.Response | None:
    """GET the keyless URLhaus per-country feed (CSV, sometimes zip-wrapped).

    Returns the raw httpx.Response (caller decodes CSV/zip from .content), or
    None on any transport/HTTP error.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            r = await client.get(
                f"{_URLHAUS_FEED}/country/{cc}/",
                headers={"User-Agent": "FalconEye/3.0 (osintph.info; threat research)"},
            )
            r.raise_for_status()
            return r
    except Exception as exc:
        log.warning("URLhaus %s feed fetch failed: %s", cc, exc)
        return None
