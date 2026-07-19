"""
Abuse-reporting API.

Endpoints (all under /api/abuse):
  POST /lookup          — RDAP abuse contact for an IP or domain (no auth)
  POST /compose         — render a report from env reporter identity (no auth)
  POST /send            — send via Mailgun (HTTP Basic Auth, Option B only)
  GET  /send_available  — is the send path configured? (drives the UI button)

Compose and copy work with zero configuration. Send additionally requires the
MAILGUN_* env vars and admin Basic Auth (FALCONEYE_ABUSE_ADMIN_USER +
FALCONEYE_ABUSE_ADMIN_PASS_HASH, the latter a bcrypt hash).
"""
import logging
import os
import secrets
from datetime import datetime, timezone

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from slowapi import Limiter

from app.abuse import compose as compose_mod
from app.abuse import lookup as lookup_mod
from app.abuse import send as send_mod
from app.abuse import store
from app.utils.client_ip import get_client_ip, get_client_ip_key

log = logging.getLogger("falconeye.abuse")

router = APIRouter(prefix="/api/abuse", tags=["abuse"])
limiter = Limiter(key_func=get_client_ip_key)
security = HTTPBasic(auto_error=False)

# SQLite quota windows (the burst layer is the slowapi decorator below).
LOOKUP_PER_HOUR = 10
COMPOSE_PER_HOUR = 3
COMPOSE_PER_DAY = 10
_HOUR = 3600
_DAY = 86400


# ---------- request models ----------

class LookupRequest(BaseModel):
    target: str
    target_type: str  # "ip" | "domain"


class ComposeRequest(BaseModel):
    target: str
    target_type: str
    category: str
    evidence_text: str = ""
    observed_at_utc: str = ""


class SendRequest(BaseModel):
    composed: dict
    recipient_email: str


# ---------- admin auth ----------

def _admin_configured() -> bool:
    return bool(
        os.getenv("FALCONEYE_ABUSE_ADMIN_USER", "").strip()
        and os.getenv("FALCONEYE_ABUSE_ADMIN_PASS_HASH", "").strip()
    )


def require_admin(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    """FastAPI dependency: HTTP Basic Auth against the bcrypt admin hash."""
    user = os.getenv("FALCONEYE_ABUSE_ADMIN_USER", "").strip()
    pass_hash = os.getenv("FALCONEYE_ABUSE_ADMIN_PASS_HASH", "").strip()

    if not user or not pass_hash:
        raise HTTPException(
            status_code=503,
            detail="Send endpoint is not configured (admin auth env vars missing).",
        )

    unauthorized = HTTPException(
        status_code=401,
        detail="Admin authentication required.",
        headers={"WWW-Authenticate": 'Basic realm="FalconEye Admin"'},
    )
    if credentials is None:
        raise unauthorized

    user_ok = secrets.compare_digest(credentials.username or "", user)
    try:
        pass_ok = bcrypt.checkpw(
            (credentials.password or "").encode("utf-8"),
            pass_hash.encode("utf-8"),
        )
    except Exception:
        pass_ok = False

    # Evaluate both regardless of the username result to avoid short-circuit timing leaks.
    if not (user_ok and pass_ok):
        raise unauthorized
    return credentials.username


# ---------- endpoints ----------

@router.post("/lookup")
@limiter.limit("20/minute")
async def lookup(req: LookupRequest, request: Request):
    ttype = (req.target_type or "").strip().lower()
    target = (req.target or "").strip()

    if ttype not in ("ip", "domain"):
        raise HTTPException(status_code=400, detail="target_type must be 'ip' or 'domain'.")
    if not target:
        raise HTTPException(status_code=400, detail="target is required.")
    if len(target) > 255:
        raise HTTPException(status_code=400, detail="target too long (max 255 chars).")

    client_ip = get_client_ip(request)
    if store.count_recent("abuse_lookup_rate_limit", "client_ip", client_ip, _HOUR) >= LOOKUP_PER_HOUR:
        raise HTTPException(
            status_code=429,
            detail=f"Abuse-lookup limit reached ({LOOKUP_PER_HOUR} per hour). Try again later.",
        )
    store.record_event("abuse_lookup_rate_limit", "client_ip", client_ip)

    if ttype == "ip":
        return await lookup_mod.lookup_ip_abuse(target)
    return await lookup_mod.lookup_domain_abuse(target)


@router.post("/compose")
@limiter.limit("10/minute")
async def compose(req: ComposeRequest, request: Request):
    reporter_name = os.getenv("FALCONEYE_REPORTER_NAME", "").strip()
    reporter_email = os.getenv("FALCONEYE_REPORTER_EMAIL", "").strip()
    if not reporter_name or not reporter_email:
        raise HTTPException(
            status_code=503,
            detail=(
                "Reporter identity is not configured. The operator must set "
                "FALCONEYE_REPORTER_NAME and FALCONEYE_REPORTER_EMAIL."
            ),
        )

    target = (req.target or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required.")

    client_ip = get_client_ip(request)
    if store.count_recent("abuse_compose_rate_limit", "client_ip", client_ip, _HOUR) >= COMPOSE_PER_HOUR:
        raise HTTPException(
            status_code=429,
            detail=f"Compose limit reached ({COMPOSE_PER_HOUR} per hour). Try again later.",
        )
    if store.count_recent("abuse_compose_rate_limit", "client_ip", client_ip, _DAY) >= COMPOSE_PER_DAY:
        raise HTTPException(
            status_code=429,
            detail=f"Compose limit reached ({COMPOSE_PER_DAY} per day). Try again tomorrow.",
        )
    store.record_event("abuse_compose_rate_limit", "client_ip", client_ip)

    observed = (req.observed_at_utc or "").strip() or datetime.now(timezone.utc).isoformat()

    return compose_mod.compose_report(
        target=target,
        target_type=(req.target_type or "").strip(),
        category=(req.category or "other").strip(),
        evidence_text=req.evidence_text or "",
        observed_at_utc=observed,
        reporter_name=reporter_name,
        reporter_email=reporter_email,
    )


@router.post("/send")
@limiter.limit("10/minute")
async def send(req: SendRequest, request: Request, admin: str = Depends(require_admin)):
    client_ip = get_client_ip(request)
    # SendResult is returned as-is (200) even when rate_limited, so the caller
    # can read the structured {sent, rate_limited, error} fields.
    return await send_mod.send_via_mailgun(req.composed or {}, req.recipient_email or "", client_ip)


@router.get("/send_available")
async def send_available():
    return {"available": bool(_admin_configured() and send_mod.mailgun_configured())}
