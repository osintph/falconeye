"""
v3.17.0: on-demand ransomware.live PRO calls, made at request time.

This is the ONLY module that calls an upstream from a request-serving path -
everything else in Ransomware Watch (the original v3.16.0 panels) is
collector-only, per Part 1 of that brief. v3.17.0 deliberately carves out two
guarded exceptions: an out-of-scope country lookup (rare, cached 24h, rate
limited) and company search (always live, since local coverage is a small
fraction of upstream - see Part 2 of the v3.17.0 brief for why a cache would
produce confident false negatives there).

No v2 fallback here (unlike the collector) - Part 4 of the brief is explicit
that a PRO outage degrades to the *local* cache for these two features, not
to the v2 API.

Query privacy: the search string is never logged, in any log line in this
module. The in-memory cache below is deliberately NOT a SQLite table -
"never persisted, in any table" (Part 2) - so it holds only process memory,
cleared on every restart, leaving no forensic trace of what was searched.
"""
import logging
import time

import httpx

from app.config import RANSOMWARE_LIVE_API_KEY

log = logging.getLogger("falconeye.ransomware.live")

PRO_BASE = "https://api-pro.ransomware.live"
HTTP_TIMEOUT = 10.0
SEARCH_CACHE_TTL_SECONDS = 3600
SEARCH_RESULT_CAP = 100

def _headers() -> dict:
    # Built per-call (not a module-level constant) so a test can
    # monkeypatch RANSOMWARE_LIVE_API_KEY and have it actually take effect.
    return {"X-API-KEY": RANSOMWARE_LIVE_API_KEY, "User-Agent": "FalconEye/3.17 (osintph.info; on-demand lookup)"}


def normalize_query(q: str) -> str:
    """Lowercased, whitespace-collapsed - used only as a cache key, never
    persisted, never logged."""
    return " ".join((q or "").split()).lower()


def _get(d: dict, *keys, default=None):
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return default


def extract_pro_victim_fields(raw: dict) -> dict:
    """/victims/search uses different field names than /victims/recent and
    /victims/?country= (post_title/group_name/published vs
    victim/group/attackdate) - confirmed live, not a one-off. This extractor
    checks both."""
    return {
        "group_name": _get(raw, "group", "group_name", default=""),
        "victim_name": _get(raw, "victim", "post_title", default=""),
        "country": _get(raw, "country", default=""),
        "sector": _get(raw, "activity", default=""),
        "discovered": _get(raw, "discovered"),
        "attackdate": _get(raw, "attackdate", "published"),
        "infostealer": raw.get("infostealer") if isinstance(raw.get("infostealer"), dict) else None,
        "permalink": raw.get("permalink"),
    }


async def fetch_country_live(country: str, client: httpx.AsyncClient | None = None) -> tuple[list[dict] | None, str]:
    """Returns (victims, status). victims is None (not empty) on any
    failure, so callers can distinguish "fetched, zero results" from
    "couldn't fetch". status is 'ok' or 'unavailable', for the response
    label - never raises. `client` is injectable for tests; production call
    sites omit it and get a fresh one."""
    if not RANSOMWARE_LIVE_API_KEY:
        log.error("ransomware live: RANSOMWARE_LIVE_API_KEY not set, country lookup unavailable")
        return None, "unavailable"
    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=HTTP_TIMEOUT)
    try:
        resp = await client.get(f"{PRO_BASE}/victims/", headers=_headers(), params={"country": country})
    except httpx.HTTPError as exc:
        log.warning("ransomware live: country=%s request failed (%s)", country, type(exc).__name__)
        return None, "unavailable"
    finally:
        if owns_client:
            await client.aclose()
    if resp.status_code == 200:
        return resp.json().get("victims", []), "ok"
    log.warning("ransomware live: country=%s HTTP %s", country, resp.status_code)
    return None, "unavailable"


async def fetch_search_live(query: str, client: httpx.AsyncClient | None = None) -> tuple[list[dict] | None, str]:
    """Returns (victims, status). `query` is passed to PRO and otherwise
    untouched - never logged here, on success or failure. `client` is
    injectable for tests."""
    if not RANSOMWARE_LIVE_API_KEY:
        log.error("ransomware live: RANSOMWARE_LIVE_API_KEY not set, search unavailable")
        return None, "unavailable"
    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=HTTP_TIMEOUT)
    try:
        resp = await client.get(f"{PRO_BASE}/victims/search", headers=_headers(), params={"q": query})
    except httpx.HTTPError as exc:
        log.warning("ransomware live: search request failed (%s)", type(exc).__name__)
        return None, "unavailable"
    finally:
        if owns_client:
            await client.aclose()
    if resp.status_code == 200:
        return resp.json().get("victims", []), "ok"
    log.warning("ransomware live: search HTTP %s", resp.status_code)
    return None, "unavailable"


# ---------- in-memory search result cache (deliberately not a DB table) ----------

_search_cache: dict[str, tuple[float, list[dict]]] = {}


def get_cached_search(normalized_query: str) -> list[dict] | None:
    entry = _search_cache.get(normalized_query)
    if not entry:
        return None
    stored_at, results = entry
    if time.time() - stored_at > SEARCH_CACHE_TTL_SECONDS:
        del _search_cache[normalized_query]
        return None
    return results


def set_cached_search(normalized_query: str, results: list[dict]) -> None:
    _search_cache[normalized_query] = (time.time(), results)
    # Opportunistic cleanup so a long-running process doesn't accumulate
    # unbounded stale entries - cheap since this only runs on a cache miss.
    if len(_search_cache) > 500:
        cutoff = time.time() - SEARCH_CACHE_TTL_SECONDS
        for k in [k for k, (t, _) in _search_cache.items() if t < cutoff]:
            del _search_cache[k]
