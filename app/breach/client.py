"""
Have I Been Pwned (HIBP) API v3 client.

Every outbound call goes through `app.utils.safe_fetch` — the HIBP hosts are
fixed and trusted, but this keeps the app to its one SSRF primitive by policy
(the same choice `app.abuse.lookup` makes for rdap.org). See safe_fetch's
docstring: fixed-host calls may use httpx directly, but consistency here is a
deliberate, not accidental, exception.

Endpoint 1 (breachedaccount) and endpoint 2 (pasteaccount) require
`HIBP_API_KEY` and count against HIBP's 10 requests/minute ceiling. Endpoints
3-6 (breach metadata, breaches-by-domain, all breaches, latest breach, data
classes) are free and unauthenticated, and do NOT send the key header.

Retry-After handling: on a 429, every call sleeps for the header's value (or
_DEFAULT_RETRY_AFTER if absent/invalid) then retries, doubling the wait on
each subsequent 429, up to _MAX_RETRIES attempts. Pwned Passwords (K-anonymity)
is deliberately NOT here — that call is made directly by the browser so it is
verifiable via DevTools that the password never reaches our server.
"""
import asyncio
import html
import json
import logging
import re
import urllib.parse

from app.config import HIBP_API_KEY
from app.utils.safe_fetch import safe_fetch, SafeFetchError

log = logging.getLogger("falconeye.breach")

BASE_URL = "https://haveibeenpwned.com/api/v3"
USER_AGENT = "FalconEye"
TIMEOUT = 15.0

_MAX_RETRIES = 3
_DEFAULT_RETRY_AFTER = 6  # ~= 60s / 10rpm, used when HIBP omits Retry-After


class HibpError(Exception):
    """Raised when HIBP returns an unexpected (non-200, non-404) status, or
    the request could not complete at all. Callers turn this into a
    structured JSON error — never propagate raw exception text to the client
    beyond a short, safe message."""


def _headers(use_key: bool) -> dict:
    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if use_key:
        h["hibp-api-key"] = HIBP_API_KEY
    return h


async def _get(path: str, params: dict | None = None, use_key: bool = False):
    """GET one HIBP endpoint. Returns the parsed JSON body, or None for a 404
    (HIBP's "nothing found" response — a normal, expected state, not an
    error). Raises HibpError on anything else after exhausting retries."""
    url = f"{BASE_URL}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)

    wait = _DEFAULT_RETRY_AFTER
    last_status = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            res = await safe_fetch(url, method="GET", headers=_headers(use_key), timeout=TIMEOUT)
        except SafeFetchError as exc:
            raise HibpError(f"could not reach HIBP: {exc}") from exc

        status = res.get("status")
        last_status = status

        if status == 200:
            body = res.get("body") or ""
            if not body:
                return None
            try:
                return json.loads(body)
            except (ValueError, TypeError) as exc:
                raise HibpError("HIBP returned a non-JSON body") from exc

        if status == 404:
            return None

        if status == 429:
            resp_headers = {k.lower(): v for k, v in (res.get("headers") or {}).items()}
            retry_after = resp_headers.get("retry-after")
            try:
                wait = max(1, int(float(retry_after)))
            except (TypeError, ValueError):
                pass  # keep the running `wait` (doubles below on repeat 429s)
            if attempt >= _MAX_RETRIES:
                break
            log.warning("breach: HIBP 429 on %s, retry %d/%d after %ss", path, attempt + 1, _MAX_RETRIES, wait)
            await asyncio.sleep(wait)
            wait = min(wait * 2, 120)
            continue

        raise HibpError(f"HIBP returned HTTP {status} for {path}")

    raise HibpError(f"HIBP rate limit (429) not cleared after {_MAX_RETRIES} retries (last status {last_status})")


# ---------- paid endpoints (count toward the 10 RPM ceiling) ----------

async def fetch_breached_account(email: str):
    """List of breach hits for *email* (name + full context — truncateResponse=false).
    Returns [] if the email has no known breaches (HIBP 404)."""
    data = await _get(f"/breachedaccount/{urllib.parse.quote(email)}",
                       params={"truncateResponse": "false"}, use_key=True)
    return data or []


async def fetch_paste_account(email: str):
    """List of paste-site appearances for *email*. Returns [] if none."""
    data = await _get(f"/pasteaccount/{urllib.parse.quote(email)}", use_key=True)
    return data or []


# ---------- free endpoints (no key, don't count toward the 10 RPM) ----------

async def fetch_breach_metadata(name: str):
    """Full metadata for one breach by its HIBP `Name` identifier, or None if unknown."""
    return await _get(f"/breach/{urllib.parse.quote(name)}", use_key=False)


async def fetch_breaches_by_domain(domain: str):
    """Every breach that included addresses at *domain*. Returns [] if none."""
    data = await _get("/breaches", params={"domain": domain}, use_key=False)
    return data or []


async def fetch_all_breaches():
    data = await _get("/breaches", use_key=False)
    return data or []


async def fetch_latest_breach():
    return await _get("/latestbreach", use_key=False)


async def fetch_dataclasses():
    data = await _get("/dataclasses", use_key=False)
    return data or []


# ---------- shaping (HIBP's raw PascalCase model -> our snake_case, trimmed) ----------

_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(desc) -> str:
    """HIBP's Description field is 'HTML-safe' per their docs but still
    contains markup (mostly <a> links). Strip all tags to plain text — the
    frontend escapes again before rendering, so this is defense in depth,
    not the only safeguard."""
    if not isinstance(desc, str):
        return ""
    return html.unescape(_TAG_RE.sub("", desc)).strip()


def shape_breach(raw: dict) -> dict:
    """Normalize one HIBP breach object to the fields the UI needs."""
    raw = raw or {}
    return {
        "name": raw.get("Name"),
        "title": raw.get("Title"),
        "domain": raw.get("Domain"),
        "breach_date": raw.get("BreachDate"),
        "added_date": raw.get("AddedDate"),
        "pwn_count": raw.get("PwnCount"),
        "description": _strip_html(raw.get("Description"))[:600],
        "data_classes": raw.get("DataClasses") or [],
        "logo_path": raw.get("LogoPath"),
        "is_verified": bool(raw.get("IsVerified")),
        "is_fabricated": bool(raw.get("IsFabricated")),
        "is_sensitive": bool(raw.get("IsSensitive")),
        "is_retired": bool(raw.get("IsRetired")),
        "is_spam_list": bool(raw.get("IsSpamList")),
    }


def shape_paste(raw: dict) -> dict:
    raw = raw or {}
    return {
        "source": raw.get("Source"),
        "id": raw.get("Id"),
        "title": raw.get("Title"),
        "date": raw.get("Date"),
        "email_count": raw.get("EmailCount"),
    }
