"""
Hudson Rock infostealer intelligence, domain and email only.

Added in v3.33.0 after Hudson Rock offered their complimentary data in GitHub
issue #1. Scope is deliberately narrower than what they offered: the issue also
lists search-by-username and search-by-phone, and neither is implemented. On a
public, unauthenticated tool those two turn a compromise-notification feature
into a people-search one, and that is not what this is for.

WHAT THIS MODULE WILL AND WILL NOT RETURN
-----------------------------------------
Hudson Rock's stealer records are extremely sensitive. Their own published
schema (https://docs.hudsonrock.com/docs/stealers-schema) includes plaintext
``credentials`` (url, username, password), ``employee_session_cookies``,
``malware_path``, ``ip``, ``computer_name``, ``operating_system``,
``installed_software`` and ``search_data`` (the victim's search history).

None of that is ever returned from here. The sanitisers below are
**allowlists**: they build a fresh dict out of a fixed set of known-safe keys
rather than deleting known-bad ones. A denylist would leak the first time
Hudson Rock adds a field, which is exactly the kind of change we cannot see
coming. What survives is what the feature needs and no more: stealer family
names, compromise dates, and counts.

The free "osint-tools" endpoints appear to return a reduced record already, but
that is not something to rely on. Strip here, at the boundary, not in the
template.

BEST EFFORT, BY DESIGN
----------------------
These endpoints need no API key, publish no rate limit, and publish no terms of
use (verified 2026-09-21, see docs/deploy-runbook.md). So the source is
off by default, capped per client IP, cached, and every failure path degrades to
"no data" rather than an error. If Hudson Rock changes or withdraws the
endpoints, the tabs that use it look exactly as they do with it disabled.
"""
import json
import logging

from app.config import (
    HUDSONROCK_CACHE_TTL_HOURS,
    HUDSONROCK_ENABLED,
    HUDSONROCK_PER_DAY,
    OPERATOR_CONTACT_UA,
)
from app.utils import cache, rate_limit
from app.utils.safe_fetch import SafeFetchError, safe_fetch

log = logging.getLogger("falconeye.hudsonrock")

BASE_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
USER_AGENT = f"FalconEye/3.33 ({OPERATOR_CONTACT_UA}; infostealer exposure check)"
TIMEOUT = 12.0

CACHE_TABLE = "hudsonrock_cache"
RATE_LIMIT_TABLE = "hudsonrock_rate_limit"

# Cap the number of distinct families echoed back. Real answers have well under
# 20; a much longer list means the shape changed and is not worth rendering.
_MAX_FAMILIES = 25


def init() -> None:
    """Create this source's own tables. Idempotent, safe at import."""
    cache.init_table(CACHE_TABLE, key_col="query_key")
    rate_limit.init_table(RATE_LIMIT_TABLE)


def _quota_ok(source_ip: str) -> bool:
    """Per-IP daily cap, checked only when we are about to call upstream.

    Hudson Rock's quota is not ours to spend, so a public instance treats this
    the same way it treats the paid LLM endpoints: capped per client IP. A
    cache hit never consumes quota, and being over the cap is not an error, it
    just means this one enrichment is absent.
    """
    try:
        allowed, _used = rate_limit.check(RATE_LIMIT_TABLE, source_ip, HUDSONROCK_PER_DAY)
        if allowed:
            rate_limit.record(RATE_LIMIT_TABLE, source_ip)
        return allowed
    except Exception as exc:  # noqa: BLE001 - never break a tab over bookkeeping
        log.warning("hudsonrock rate-limit check failed, skipping lookup: %s", exc)
        return False


def _safe_int(value) -> int:
    """Coerce an upstream count to a non-negative int, or 0."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    try:
        return max(0, int(value))
    except (ValueError, OverflowError):
        return 0


def _safe_date(value) -> str | None:
    """Pass through an ISO-8601-looking date string, else None.

    Deliberately not parsed into a datetime: it is rendered as text and never
    computed on, so the least we can do to it the better. Anything that is not
    a short plain string is dropped rather than forwarded.
    """
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not (10 <= len(value) <= 40):
        return None
    # Must start YYYY-MM-DD. Anything else is not a date we recognise.
    if not (value[:4].isdigit() and value[4] == "-" and value[5:7].isdigit()
            and value[7] == "-" and value[8:10].isdigit()):
        return None
    return value


def _safe_family(value) -> str | None:
    """A stealer family name: short, printable, no separators."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > 60:
        return None
    # Family names are things like "RedLine", "Lumma", "Generic Stealer".
    # Anything carrying a path, URL or control character is not a family name.
    if any(c in value for c in "\\/:@\r\n\t<>\"'"):
        return None
    return value


def _families_from_mapping(raw) -> dict:
    """Domain endpoint: stealerFamilies is {family: count, "total": n}."""
    if not isinstance(raw, dict):
        return {}
    out = {}
    for name, count in raw.items():
        if name == "total":
            continue
        family = _safe_family(name)
        if family is None:
            continue
        n = _safe_int(count)
        if n:
            out[family] = n
    return dict(sorted(out.items(), key=lambda kv: -kv[1])[:_MAX_FAMILIES])


def sanitize_domain(payload) -> dict | None:
    """Allowlist the domain response down to families, dates and counts."""
    if not isinstance(payload, dict):
        return None

    families = _families_from_mapping(payload.get("stealerFamilies"))
    result = {
        "total": _safe_int(payload.get("total")),
        "employees": _safe_int(payload.get("employees")),
        "users": _safe_int(payload.get("users")),
        "third_parties": _safe_int(payload.get("third_parties")),
        "stealer_families": families,
        "last_employee_compromised": _safe_date(payload.get("last_employee_compromised")),
        "last_user_compromised": _safe_date(payload.get("last_user_compromised")),
    }
    # Nothing to show and nothing to say: treat as a clean miss, not a result.
    if not result["total"] and not families:
        result["found"] = False
    else:
        result["found"] = True
    return result


def sanitize_email(payload) -> dict | None:
    """Allowlist the email response down to families, dates and counts.

    Each entry in ``stealers`` is a full stealer record upstream. Only
    ``stealer_family`` and ``date_compromised`` are read out of it; the record
    itself is never carried forward.
    """
    if not isinstance(payload, dict):
        return None

    stealers = payload.get("stealers")
    if not isinstance(stealers, list):
        stealers = []

    families: dict = {}
    dates: list = []
    for entry in stealers:
        if not isinstance(entry, dict):
            continue
        family = _safe_family(entry.get("stealer_family"))
        if family:
            families[family] = families.get(family, 0) + 1
        date = _safe_date(entry.get("date_compromised"))
        if date:
            dates.append(date)

    dates.sort()

    # "found" means "we have something worth rendering", not "the list was
    # non-empty". A record we cannot read a family or a date out of would
    # otherwise produce a card saying "appears in 1 infostealer log" with
    # nothing under it, which is the partial render this source must never do.
    usable = bool(families or dates)
    if not usable:
        return {
            "found": False,
            "total": 0,
            "stealer_families": {},
            "first_compromised": None,
            "last_compromised": None,
            "total_corporate_services": _safe_int(payload.get("total_corporate_services")),
            "total_user_services": _safe_int(payload.get("total_user_services")),
        }

    return {
        "found": True,
        "total": len(stealers),
        "stealer_families": dict(sorted(families.items(), key=lambda kv: -kv[1])[:_MAX_FAMILIES]),
        "first_compromised": dates[0] if dates else None,
        "last_compromised": dates[-1] if dates else None,
        "total_corporate_services": _safe_int(payload.get("total_corporate_services")),
        "total_user_services": _safe_int(payload.get("total_user_services")),
    }


async def _fetch(path: str, param: str, value: str) -> dict | None:
    """One upstream call. Returns parsed JSON, or None on ANY failure.

    Never raises. A timeout, a 429, a 5xx, a non-JSON body and an unreachable
    host all land on the same branch on purpose: the caller cannot tell them
    apart and must not render differently for any of them.
    """
    import urllib.parse

    url = f"{BASE_URL}/{path}?{urllib.parse.urlencode({param: value})}"
    try:
        res = await safe_fetch(
            url,
            method="GET",
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            timeout=TIMEOUT,
        )
    except SafeFetchError as exc:
        log.warning("hudsonrock %s unavailable: %s", path, exc)
        return None
    except Exception as exc:  # noqa: BLE001 - this source must never break a tab
        log.warning("hudsonrock %s failed: %s", path, exc)
        return None

    status = res.get("status")
    if status != 200:
        log.warning("hudsonrock %s returned HTTP %s", path, status)
        return None

    try:
        return json.loads(res.get("body") or "")
    except (ValueError, TypeError) as exc:
        log.warning("hudsonrock %s returned unparseable JSON: %s", path, exc)
        return None


async def _lookup(kind: str, path: str, param: str, value: str, sanitizer,
                  source_ip: str) -> dict | None:
    """Cached, sanitised lookup. Returns None when the source has nothing."""
    if not HUDSONROCK_ENABLED:
        return None
    value = (value or "").strip().lower()
    if not value:
        return None

    key = f"{kind}:{value}"
    try:
        hit = cache.get(CACHE_TABLE, key, HUDSONROCK_CACHE_TTL_HOURS, key_col="query_key")
    except Exception as exc:  # noqa: BLE001 - a cache problem must not break the tab
        log.warning("hudsonrock cache read failed: %s", exc)
        hit = None
    if hit is not None:
        hit.pop("cache_hit", None)
        hit.pop("fetched_at", None)
        return hit

    if not _quota_ok(source_ip or "unknown"):
        return None

    payload = await _fetch(path, param, value)
    if payload is None:
        return None

    try:
        clean = sanitizer(payload)
    except Exception as exc:  # noqa: BLE001 - a shape we did not expect
        log.warning("hudsonrock %s schema not understood: %s", path, exc)
        return None
    if clean is None:
        log.warning("hudsonrock %s returned an unexpected shape", path)
        return None

    try:
        cache.set(CACHE_TABLE, key, clean, key_col="query_key")
    except Exception as exc:  # noqa: BLE001
        log.warning("hudsonrock cache write failed: %s", exc)
    return clean


async def lookup_domain(domain: str, source_ip: str = "") -> dict | None:
    """Domain exposure, or None when the source has nothing to add."""
    return await _lookup("domain", "search-by-domain", "domain", domain,
                         sanitize_domain, source_ip)


async def lookup_email(email: str, source_ip: str = "") -> dict | None:
    """Email exposure, or None when the source has nothing to add."""
    return await _lookup("email", "search-by-email", "email", email,
                         sanitize_email, source_ip)


# Self-create on import, like the other sources. Guarded because import must
# never fail on a box where the data directory is not writable yet (a fresh
# provision runs db_init.py after the venv is built, and the test suite imports
# this module without a database at all).
try:
    init()
except Exception as _exc:  # noqa: BLE001
    log.warning("hudsonrock tables not initialised at import: %s", _exc)
