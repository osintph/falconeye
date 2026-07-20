"""
Abuse-reporting API.

Endpoints (all under /api/abuse):
  POST /lookup          — RDAP abuse contact for an IP or domain (no auth)
  POST /compose         — render a report from env reporter identity (no auth)
  POST /send            — send via Mailgun (admin creds in JSON body, Option B only)
  GET  /send_available  — is the send path configured? (drives the UI button)

Compose and copy work with zero configuration. Send additionally requires the
MAILGUN_* env vars and admin credentials (FALCONEYE_ABUSE_ADMIN_USER +
FALCONEYE_ABUSE_ADMIN_PASS_HASH, the latter a bcrypt hash) supplied in the JSON
request body. It deliberately does NOT use HTTP Basic Auth: a 401 +
WWW-Authenticate response pops the browser's native auth dialog, which raced the
in-page credential form and rejected correct passwords (v3.8.1 fix).
"""
import logging
import secrets
import time
from datetime import datetime, timezone

import bcrypt
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from slowapi import Limiter

from app.abuse import compose as compose_mod
from app.abuse import lookup as lookup_mod
from app.abuse import send as send_mod
from app.abuse import store
from app.utils.client_ip import get_client_ip, get_client_ip_key
from app.utils.env import getenv_clean

log = logging.getLogger("falconeye.abuse")

router = APIRouter(prefix="/api/abuse", tags=["abuse"])
limiter = Limiter(key_func=get_client_ip_key)

# SQLite quota windows (the burst layer is the slowapi decorator below).
LOOKUP_PER_HOUR = 10
COMPOSE_PER_HOUR = 3
COMPOSE_PER_DAY = 10
_MINUTE = 60
_HOUR = 3600
_DAY = 86400

# Send throttle (M-1, reinstated v3.12.0). /send runs bcrypt on every request and
# always returns 200, so with no limit it is (a) an unauthenticated bcrypt
# CPU-exhaustion primitive and (b) an unthrottled online password-guessing oracle.
# All of these are checked BEFORE bcrypt. They reuse the pre-existing
# abuse_send_rate_limit table (scope column), keyed "ip:<ip>" / "global" for the
# rate caps and "fail:<ip>" for the consecutive-failure backoff.
_SEND_RL = "abuse_send_rate_limit"
SEND_PER_MINUTE = 5
SEND_PER_HOUR = 20
SEND_GLOBAL_PER_HOUR = 60
# Exponential backoff on consecutive failed auth from one IP (online guessing):
# the first SEND_FAIL_FREE failures cost nothing; each further failure requires a
# cooldown that doubles (SEND_BACKOFF_BASE, 2, 4, 8 ... seconds) up to the cap.
SEND_FAIL_FREE = 3
SEND_BACKOFF_BASE = 2
SEND_BACKOFF_MAX = 300


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
    admin_user: str = ""
    admin_password: str = ""


# ---------- admin auth ----------

def _admin_configured() -> bool:
    return bool(
        getenv_clean("FALCONEYE_ABUSE_ADMIN_USER")
        and getenv_clean("FALCONEYE_ABUSE_ADMIN_PASS_HASH")
    )


def _verify_admin(admin_user: str, admin_password: str) -> str | None:
    """Validate admin credentials (from the JSON body) against the bcrypt hash.

    Returns None on success, or a short error string on failure. It NEVER raises
    a 401 or emits WWW-Authenticate — doing so would pop the browser's native
    Basic Auth dialog and race the in-page form (the v3.8.1 bug). The password is
    never logged, returned, or stored.
    """
    # getenv_clean strips any inline comment / quotes systemd leaves in the value
    # (the v3.8.1 bcrypt-hash regression; see docs/regressions.md).
    user = getenv_clean("FALCONEYE_ABUSE_ADMIN_USER")
    pass_hash = getenv_clean("FALCONEYE_ABUSE_ADMIN_PASS_HASH")
    if not user or not pass_hash:
        return "send not configured on this server"

    user_ok = secrets.compare_digest(admin_user or "", user)
    try:
        pass_ok = bcrypt.checkpw((admin_password or "").encode("utf-8"), pass_hash.encode("utf-8"))
    except Exception:
        pass_ok = False

    # Evaluate both regardless of the username result to avoid short-circuit timing leaks.
    if not (user_ok and pass_ok):
        return "invalid credentials"
    return None


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
    reporter_name = getenv_clean("FALCONEYE_REPORTER_NAME")
    reporter_email = getenv_clean("FALCONEYE_REPORTER_EMAIL")
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


def _send_rate_error(message: str) -> dict:
    """Structured 200 body for a throttled/backed-off send (never 401, so the
    browser's Basic Auth dialog stays closed — v3.8.1). The frontend already
    surfaces {rate_limited: true}."""
    return {"sent": False, "mailgun_message_id": None, "error": message, "rate_limited": True}


@router.post("/send")
async def send(req: SendRequest, request: Request):
    # Credentials arrive in the JSON body and are validated here. This endpoint
    # ALWAYS returns HTTP 200 with a structured {sent, rate_limited, error} body —
    # never 401, never WWW-Authenticate — so the browser cannot open its native
    # Basic Auth dialog (v3.8.1). See test_send_endpoint_never_returns_401.
    client_ip = get_client_ip(request)

    # --- M-1: throttle BEFORE bcrypt so /send can't be a bcrypt CPU-exhaustion
    # primitive or an unthrottled guessing oracle. Per-IP burst + hourly cap and a
    # global hourly ceiling. ---
    if store.count_recent(_SEND_RL, "scope", f"ip:{client_ip}", _MINUTE) >= SEND_PER_MINUTE:
        return _send_rate_error("Rate limit exceeded: too many send attempts. Try again shortly.")
    if store.count_recent(_SEND_RL, "scope", f"ip:{client_ip}", _HOUR) >= SEND_PER_HOUR:
        return _send_rate_error("Hourly send limit reached. Try again later.")
    if store.count_recent(_SEND_RL, "scope", "global", _HOUR) >= SEND_GLOBAL_PER_HOUR:
        return _send_rate_error("The send endpoint is at its global hourly capacity. Try again later.")

    # Exponential backoff on consecutive failed auth from this IP (online guessing).
    fails = store.count_recent(_SEND_RL, "scope", f"fail:{client_ip}", _HOUR)
    if fails > SEND_FAIL_FREE:
        cooldown = min(SEND_BACKOFF_MAX, SEND_BACKOFF_BASE * (2 ** (fails - SEND_FAIL_FREE - 1)))
        last_fail = store.last_event_ts(_SEND_RL, "scope", f"fail:{client_ip}")
        if last_fail is not None and (int(time.time()) - last_fail) < cooldown:
            return _send_rate_error("Too many failed attempts; please slow down and try again shortly.")

    # Meter this attempt (every request that reaches bcrypt costs) against the
    # burst/global caps, then run auth.
    store.record_event(_SEND_RL, "scope", f"ip:{client_ip}")
    store.record_event(_SEND_RL, "scope", "global")

    auth_error = _verify_admin(req.admin_user, req.admin_password)
    if auth_error is not None:
        store.record_event(_SEND_RL, "scope", f"fail:{client_ip}")
        return {"sent": False, "mailgun_message_id": None, "error": auth_error, "rate_limited": False}

    # Successful auth clears this IP's failure backoff.
    store.clear_events(_SEND_RL, "scope", f"fail:{client_ip}")

    # SendResult is returned as-is (200) even when rate_limited, so the caller
    # can read the structured {sent, rate_limited, error} fields.
    return await send_mod.send_via_mailgun(req.composed or {}, req.recipient_email or "", client_ip)


@router.get("/send_available")
async def send_available():
    return {"available": bool(_admin_configured() and send_mod.mailgun_configured())}
