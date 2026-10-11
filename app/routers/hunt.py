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
from app.asm import jobs, serve, store
from app.utils.client_ip import get_client_ip, get_client_ip_key

log = logging.getLogger("falconeye.hunt")

router = APIRouter(prefix="/api/hunt", tags=["hunt"])
limiter = Limiter(key_func=get_client_ip_key)

_KEYWORD_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
_DAY = 86400


def _norm_keyword(raw: str) -> str:
    return (raw or "").strip().lower()


class HuntReq(BaseModel):
    keyword: str
    legit_domain: str = ""


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
    if store.rl_count("hunt_ip", ip, _DAY) >= config.HUNT_PER_DAY:
        return JSONResponse({"error": "Daily hunt limit reached. Try again later."}, status_code=429)

    serve.sweep()
    if not jobs.can_accept():
        return JSONResponse({"error": "The scanner is at capacity. Try again in a few minutes."},
                            status_code=503)
    store.rl_record("hunt_ip", ip)
    scan_id = secrets.token_urlsafe(18)
    # The hunt reuses the generic job row: keyword in domain, legit in engagement.
    store.create_scan(scan_id, keyword, "Public", kind="hunt", engagement=legit)
    jobs.submit(scan_id)
    log.info("hunt start id=%s", scan_id)
    return {"scan_id": scan_id, "state": "queued", "capacity": jobs.capacity()}


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
