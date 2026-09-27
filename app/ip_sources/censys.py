"""
Censys Platform, host services and ports. Enrichment only, and metered.

WHAT THIS SOURCE IS FOR
-----------------------
Ports, services, observed OS and the ASN Censys attributes the host to. It has
never produced a reputation signal: nothing in compute_verdict() reads a Censys
field, and there is no Censys equivalent of an abuse score. As of v3.34.0 it is
therefore outside the consensus, and its absence never makes a verdict
INCOMPLETE. The verdict is computed over the four unmetered sources.

WHAT IT COSTS (verified 2026-09-27)
-----------------------------------
The Platform API is credit-metered, including on the free tier:

- An entity lookup, which is what this module does, costs **1 credit**.
- **Censys Free** gets **100 credits a month** and they **expire at the end of
  the month**. Free accounts are limited to lookup endpoints, which is all this
  module uses.
- **Censys Starter** is a Free account that has bought credits (packages start
  at $100, valid 12 months); Search/Core tiers get full API access.
- Source: https://docs.censys.com/docs/platform-credits-free-starter and
  https://docs.censys.com/docs/data-access-tiers-entitlements

100 credits a month is roughly three host lookups a day. On a public instance
that is spent by mid-morning, which is why CENSYS_ENABLED defaults to off: an
operator opts in knowing each lookup spends their allowance.

WHEN THE BALANCE IS GONE
------------------------
The API answers **HTTP 422** with an "insufficient balance" style body. That is
not a fault: it is what running out of a monthly allowance looks like, so it maps
to NO_CREDITS and renders as a grey note, not a red error. A 422 that is *not*
about the balance (the known case is a malformed organization id) still maps to
ERROR, because that one does need an operator.

AUTH
----
Personal Access Token as ``Authorization: Bearer``. The PAT is org-scoped, so no
organization_id is needed (a bad/placeholder org id returns 422). We send
``X-Organization-ID`` ONLY if CENSYS_ORG_ID is a real UUID, so it "just works" if
a valid one is configured later; otherwise PAT-only.
"""
import re

import httpx

from app import config
from app.utils.env import getenv_clean
from app.ip_sources.base import (
    SourceResult, FETCH_TIMEOUT, USER_AGENT,
    OK, NO_KEY, QUOTA, NO_CREDITS, DISABLED, ERROR, NOT_FOUND,
)

# The credential this source needs. Declared here so availability can be
# reported before any lookup runs, without duplicating the name elsewhere.
KEY_ENV = "CENSYS_PAT"
LABEL = "Censys"

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

# The balance-exhausted 422 is matched on the body rather than on a documented
# error code, because Censys documents neither the code nor the body for it. Any
# 422 that talks about a balance or credits is the metering answer; every other
# 422 stays an error. Matching on substrings makes this survive a reworded
# message, which a stricter parse would not.
_NO_CREDIT_MARKERS = ("insufficient balance", "insufficient credit", "insufficient funds",
                      "balance", "credit")


def _is_balance_422(body: str) -> bool:
    low = (body or "").lower()
    return any(m in low for m in _NO_CREDIT_MARKERS)


async def fetch(ip: str, client: httpx.AsyncClient) -> SourceResult:
    # Read from the config module (not a from-import) so the flag is honoured at
    # call time: the tests flip it, and an operator reads it once at boot.
    if not config.CENSYS_ENABLED:
        return SourceResult("censys", False, DISABLED, {}, "CENSYS_ENABLED is not set")

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
    if r.status_code == 422:
        body = getattr(r, "text", "") or ""
        if not body:
            try:
                body = str(r.json())
            except Exception:
                body = ""
        if _is_balance_422(body):
            return SourceResult("censys", False, NO_CREDITS, {},
                                "monthly credits exhausted")
        return SourceResult("censys", False, ERROR, {}, "HTTP 422")
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
