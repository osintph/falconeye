"""
Username Enumeration API.

  POST /api/username/scan
    Body: {"username": str, "scope": "quick"|"full", "include_nsfw": bool}
    Auth: none (public tool, public feature)
    Rate limit: 3 scans / IP / hour, 20 / IP / day, 100 global / day,
                enforced BEFORE any outbound work is spawned.

Strict username validation is a security boundary: the value is substituted into
vendored URL templates, so anything outside [A-Za-z0-9._-]{1,40} is rejected at
the router before a single check runs (and it is URL-encoded again in the checker).
"""
import logging
import re
import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from slowapi import Limiter

from app.username import checker, merger, store
from app.username.parser import select_sites, get_all_sites
from app.utils.client_ip import get_client_ip, get_client_ip_key

log = logging.getLogger("falconeye.username")

router = APIRouter(prefix="/api/username", tags=["username"])
limiter = Limiter(key_func=get_client_ip_key)

USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,40}$")

SCAN_IP_PER_HOUR = 3
SCAN_IP_PER_DAY = 20
SCAN_GLOBAL_PER_DAY = 100
_HOUR = 3600
_DAY = 86400

CONCURRENCY = 25
_DEADLINE = {"quick": 25.0, "full": 50.0}


class ScanRequest(BaseModel):
    username: str
    scope: str = "quick"
    include_nsfw: bool = False


@router.post("/scan")
@limiter.limit("5/minute")
async def scan(req: ScanRequest, request: Request):
    username = (req.username or "").strip()
    if not USERNAME_RE.match(username):
        raise HTTPException(
            status_code=400,
            detail="Invalid username. Use 1-40 characters: letters, digits, and . _ - only.",
        )

    scope = (req.scope or "quick").strip().lower()
    if scope not in ("quick", "full"):
        scope = "quick"

    client_ip = get_client_ip(request)
    # Enforce the ceiling BEFORE spawning 200-800 outbound requests.
    if store.count_recent(f"ip:{client_ip}", _HOUR) >= SCAN_IP_PER_HOUR:
        raise HTTPException(status_code=429, detail=f"Scan limit reached ({SCAN_IP_PER_HOUR} per hour). Try again later.")
    if store.count_recent(f"ip:{client_ip}", _DAY) >= SCAN_IP_PER_DAY:
        raise HTTPException(status_code=429, detail=f"Scan limit reached ({SCAN_IP_PER_DAY} per day). Try again tomorrow.")
    if store.count_recent("global", _DAY) >= SCAN_GLOBAL_PER_DAY:
        raise HTTPException(status_code=429, detail="The service is at its global daily scan capacity. Try again later.")
    store.record_event(f"ip:{client_ip}")
    store.record_event("global")

    sites = select_sites(scope, req.include_nsfw)
    if not sites:
        raise HTTPException(status_code=503, detail="Username site data is not available on this server.")

    t0 = time.monotonic()
    results, unchecked = await checker.sweep(
        sites, username, concurrency=CONCURRENCY, deadline_s=_DEADLINE[scope],
    )
    duration_ms = int((time.monotonic() - t0) * 1000)

    return merger.build_result(
        results=results,
        username=username,
        scope=scope,
        checked_count=len(results),
        unchecked_count=unchecked,
        duration_ms=duration_ms,
    )


@router.get("/meta")
async def meta():
    """Lightweight introspection: site counts by scope (no scan)."""
    all_sites = get_all_sites()
    quick = sum(1 for s in all_sites if s.priority >= 2 and not s.is_nsfw)
    return {
        "total_sites": len(all_sites),
        "quick_sites": quick,
        "nsfw_sites": sum(1 for s in all_sites if s.is_nsfw),
        "dual_source_sites": sum(1 for s in all_sites if len(s.sources) > 1),
    }
