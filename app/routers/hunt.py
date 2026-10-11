"""Phishing Domain Hunt HTTP API (public, ungated).

It hunts attacker infrastructure impersonating a brand, so it needs no ownership
verification. Results are one-time: shown once, delivered as a PDF, then purged
(the shared serve module enforces that). A hunt runs on the same background job
runner as ASM. No em dashes in this module or any string it emits.
"""
from __future__ import annotations

import logging
import re
import secrets

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from slowapi import Limiter

from app import config
from app.asm import jobs, operator, serve, store
from app.utils.client_ip import get_client_ip, get_client_ip_key

log = logging.getLogger("falconeye.hunt")

router = APIRouter(prefix="/api/hunt", tags=["hunt"])
limiter = Limiter(key_func=get_client_ip_key)

# The Hunt shares the Attack Surface operator session (same cookie, same unlock
# endpoint): unlocking on either tab unlocks both.
_OP_COOKIE = "asm_operator"
_KEYWORD_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
_DAY = 86400
_MANILA = None


def _manila():
    global _MANILA
    if _MANILA is None:
        from zoneinfo import ZoneInfo
        _MANILA = ZoneInfo("Asia/Manila")
    return _MANILA


def _norm_keyword(raw: str) -> str:
    return (raw or "").strip().lower()


def _operator_session(request: Request):
    if not operator.configured():
        return None
    return operator.session_from_cookie(request.cookies.get(_OP_COOKIE, ""))


def _reset_message(ip: str) -> str:
    """Public daily cap message naming the Asia/Manila reset time (rolling 24h)."""
    import datetime as _dt
    oldest = store.rl_oldest_ts("hunt_ip", ip, _DAY)
    base = ((oldest + _DAY) if oldest else (int(__import__("time").time()) + _DAY))
    when = _dt.datetime.fromtimestamp(base, _manila()).strftime("%Y-%m-%d %H:%M")
    return (f"Daily hunt limit reached. The limit resets by {when} (Asia/Manila). "
            "Operators can unlock with an operator key to continue.")


class HuntReq(BaseModel):
    keyword: str
    legit_domain: str = ""
    engagement: str = ""


def _enabled() -> bool:
    return config.HUNT_ENABLED


@router.post("")
@limiter.limit("6/minute")
async def start_hunt(request: Request, payload: HuntReq):
    if not _enabled():
        return JSONResponse({"error": "The Phishing Hunt is not enabled on this server."},
                            status_code=503)
    keyword = _norm_keyword(payload.keyword)
    if "*" in keyword or "%" in keyword:
        return JSONResponse({"error": "Wildcards are not allowed; enter a plain brand keyword."},
                            status_code=400)
    if len(keyword) < 3 or not _KEYWORD_RE.match(keyword):
        return JSONResponse({"error": "Enter a brand keyword of at least 3 characters "
                                      "(letters, digits and hyphens)."}, status_code=400)
    legit = _norm_keyword(payload.legit_domain)
    from app.utils.domain import normalize_domain
    legit = normalize_domain(legit) or "" if legit else ""

    ip = get_client_ip(request)
    op = _operator_session(request)
    is_op = op is not None
    # An operator session bypasses the public cap under its own higher cap.
    if is_op:
        if store.rl_count("hunt_op_ip", ip, _DAY) >= config.HUNT_OPERATOR_PER_DAY:
            return JSONResponse({"error": "Operator daily hunt limit reached."}, status_code=429)
    elif store.rl_count("hunt_ip", ip, _DAY) >= config.HUNT_PER_DAY:
        return JSONResponse({"error": _reset_message(ip)}, status_code=429)

    serve.sweep()
    if not jobs.can_accept():
        return JSONResponse({"error": "The scanner is at capacity. Try again in a few minutes."},
                            status_code=503)
    store.rl_record("hunt_op_ip" if is_op else "hunt_ip", ip)
    scan_id = secrets.token_urlsafe(18)
    engagement_ref = (payload.engagement or "").strip()[:120] if is_op else ""
    # The hunt reuses the generic job row: keyword in domain, legit in engagement.
    # An operator hunt is marked operator=1 (raises caps) and carries its optional
    # engagement reference in grant_id for the PDF watermark.
    store.create_scan(scan_id, keyword, "Operator" if is_op else "Public", kind="hunt",
                      engagement=legit, operator=1 if is_op else 0, grant_id=engagement_ref)
    jobs.submit(scan_id)
    log.info("hunt start id=%s operator=%s", scan_id, is_op)
    return {"scan_id": scan_id, "state": "queued", "operator": is_op,
            "normalized": {"keyword": keyword, "legit_domain": legit},
            "capacity": jobs.capacity()}


@router.post("/mcp")
async def mcp_hunt(request: Request, payload: HuntReq):
    """Synchronous hunt for the local MCP server: runs inline, returns the result,
    stores nothing (no job row, no cache, no PDF). Same caps as the web path."""
    if not _enabled():
        return JSONResponse({"error": "The Phishing Hunt is not enabled on this server."},
                            status_code=503)
    keyword = _norm_keyword(payload.keyword)
    if "*" in keyword or "%" in keyword or len(keyword) < 3 or not _KEYWORD_RE.match(keyword):
        return JSONResponse({"error": "Enter a plain brand keyword of at least 3 characters, "
                                      "no wildcards."}, status_code=400)
    from app.utils.domain import normalize_domain
    legit = normalize_domain(_norm_keyword(payload.legit_domain)) or "" if payload.legit_domain else ""
    ip = get_client_ip(request)
    if store.rl_count("hunt_ip", ip, _DAY) >= config.HUNT_PER_DAY:
        return JSONResponse({"error": "Daily hunt limit reached."}, status_code=429)
    store.rl_record("hunt_ip", ip)
    from app.hunt import engine
    result = await engine.execute({"scan_id": "mcp-" + secrets.token_urlsafe(8),
                                   "domain": keyword, "engagement": legit})
    result.pop("scan_id", None)
    return result


def _hunt_scan(scan_id: str):
    scan = store.get_scan(scan_id)
    if not scan or (scan.get("kind") or "asm") != "hunt":
        return None
    return scan


@router.get("/{scan_id}")
async def get_hunt(scan_id: str):
    scan = _hunt_scan(scan_id)
    if not scan:
        return JSONResponse({"error": "Not found."}, status_code=404)
    return serve.payload_response(scan, scan_id)


@router.get("/{scan_id}/report.pdf")
async def hunt_pdf(scan_id: str):
    if not _hunt_scan(scan_id):
        return JSONResponse({"error": "Not found."}, status_code=404)
    return serve.pdf_response(scan_id)


@router.get("/{scan_id}/export.{fmt}")
async def hunt_export(scan_id: str, fmt: str):
    if not _hunt_scan(scan_id):
        return JSONResponse({"error": "Not found."}, status_code=404)
    return serve.export_response(scan_id, fmt)
