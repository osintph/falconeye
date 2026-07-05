"""
urlscan.io enrichment for the phishing scanner.

Queries the urlscan.io search API for the most recent scan of a target domain.
Used as a separate enrichment pass — urlscan verdict is returned alongside
FalconEye's own indicator matching but does NOT overwrite indicators_matched,
so the two verdicts stay distinct in the response.

Free tier works without an API key (lower rate limit, no private scans).
Set URLSCAN_API_KEY to raise the rate limit.

TODO: Google Safe Browsing enrichment (GSB_API_KEY) — see
  https://developers.google.com/safe-browsing/v4/lookup-api
  Similar pattern: separate enrichment pass, returned as gsb_result alongside
  urlscan_result, does not overwrite indicators_matched.
"""

import logging
from urllib.parse import urlparse
from app.utils.safe_fetch import safe_fetch, SafeFetchError
from app.config import URLSCAN_API_KEY

log = logging.getLogger(__name__)

_URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
_EMPTY = {
    "found": False,
    "verdict": "",
    "malicious": False,
    "submitted_at": "",
    "screenshot_url": "",
    "live_url": "",
    "tags": [],
}


async def check_urlscan(url: str) -> dict:
    """
    Query urlscan.io for the most recent scan of the host in `url`.

    Returns a dict with keys: found, verdict, malicious, submitted_at,
    screenshot_url, live_url, tags.
    """
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return {**_EMPTY}

    if not host:
        return {**_EMPTY}

    headers = {"Content-Type": "application/json"}
    if URLSCAN_API_KEY:
        headers["API-Key"] = URLSCAN_API_KEY

    try:
        resp = await safe_fetch(
            f"{_URLSCAN_SEARCH}?q=domain:{host}&size=1",
            headers=headers,
            timeout=10.0,
        )
    except SafeFetchError as exc:
        log.warning("urlscan SSRF guard blocked request for host %s: %s", host, exc)
        return {**_EMPTY}
    except Exception:
        log.exception("urlscan fetch failed for host %s", host)
        return {**_EMPTY}

    status = resp.get("status", 0)
    if status == 429:
        log.warning("urlscan rate limit hit for host %s", host)
        return {**_EMPTY}
    if status != 200:
        log.warning("urlscan returned HTTP %s for host %s", status, host)
        return {**_EMPTY}

    try:
        body = resp.get("body", "")
        import json
        data = json.loads(body) if isinstance(body, str) else body
        results = data.get("results", [])
        if not results:
            return {**_EMPTY}

        hit = results[0]
        page = hit.get("page", {})
        task = hit.get("task", {})
        verdicts = hit.get("verdicts", {})
        overall = verdicts.get("overall", {})

        return {
            "found": True,
            "verdict": overall.get("verdict", ""),
            "malicious": bool(overall.get("malicious", False)),
            "submitted_at": task.get("time", ""),
            "screenshot_url": task.get("screenshotURL", ""),
            "live_url": page.get("url", ""),
            "tags": overall.get("tags", []),
        }
    except Exception:
        log.exception("urlscan response parse failed for host %s", host)
        return {**_EMPTY}
