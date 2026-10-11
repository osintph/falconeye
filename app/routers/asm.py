"""Attack Surface Management HTTP API and its two served pages.

The router enforces the rule that governs the whole feature: no ASM output for an
unverified or blocked domain outside operator mode. Access is proven two ways,
never by a shareable link:

  grant cookie       a verified owner's browser holds a signed, expiring grant.
  operator session   a signed, short-lived session from the unlock route.

There are two routers. `router` carries the JSON API under /api/asm. `pages`
carries the two HTML pages the email links open (/asm/confirm, /asm/manage),
which must be top-level paths, not under /api. No em dashes in this module or in
any string it emits.
"""
from __future__ import annotations

import hashlib
import html
import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel
from slowapi import Limiter

from app import config
from app.asm import blocklist, jobs, mailer, operator, report, signing, store, verify
from app.asm.verify import GRANT_COOKIE, ROLE_PREFIXES
from app.utils.client_ip import get_client_ip, get_client_ip_key
from app.utils.domain import normalize_domain
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.asm")

# ASM is disabled unless a signing key is configured. There is no per-process key
# fallback, so a missing key never silently issues grants that die on restart.
if not signing.configured():
    log.error("ASM is disabled: ASM_SIGNING_KEY is unset. Set it (see .env.example) "
              "to enable the Attack Surface tab. Grants and management links need it.")


def _asm_guard() -> None:
    """Refuse every ASM request when the feature is not configured."""
    if not signing.configured():
        raise HTTPException(status_code=503,
                            detail="Attack Surface Management is not configured on this server.")


router = APIRouter(prefix="/api/asm", tags=["asm"], dependencies=[Depends(_asm_guard)])
pages = APIRouter(tags=["asm-pages"], dependencies=[Depends(_asm_guard)])
limiter = Limiter(key_func=get_client_ip_key)

OP_COOKIE = "asm_operator"
_HOUR = 3600
_DAY = 86400

# The response shown for a blocked domain, identical whatever the reason.
_BLOCK_BODY = {"assessable": False, "message": blocklist.BLOCK_MESSAGE}


# ---------------------------------------------------------------- context ----

def _ip(request: Request) -> str:
    return get_client_ip(request)


def _ip_hash(ip: str) -> str:
    return hashlib.sha256((ip or "").encode("utf-8")).hexdigest()[:32]


def _operator(request: Request):
    return operator.session_from_cookie(request.cookies.get(OP_COOKIE, ""))


def _grant_for(request: Request, domain: str):
    grant = verify.grant_from_cookie(request.cookies.get(GRANT_COOKIE, ""))
    if grant and grant.get("domain") == domain:
        return grant
    return None


def _rl_ok(scope: str, key: str, limit: int, window: int) -> bool:
    if store.rl_count(scope, key, window) >= limit:
        return False
    store.rl_record(scope, key)
    return True


def _norm(raw: str):
    return normalize_domain(raw or "")


def _set_cookie(resp: Response, name: str, value: str, max_age: int) -> None:
    resp.set_cookie(name, value, max_age=max_age, httponly=True, secure=True,
                    samesite="strict", path="/")


# ------------------------------------------------------------ verification ----

class StartReq(BaseModel):
    domain: str
    method: str = "dns"
    role: str = ""


@router.post("/verify/start")
@limiter.limit("10/minute")
async def verify_start(request: Request, payload: StartReq):
    domain = _norm(payload.domain)
    if not domain:
        return JSONResponse({"assessable": False, "message": "Enter a valid domain."}, status_code=400)
    if blocklist.is_blocked(domain):
        return JSONResponse(_BLOCK_BODY, status_code=200)

    ip = _ip(request)
    # Pre-checks are COUNT ONLY. The limit counters are incremented further down,
    # and only when a token is actually issued or an email is actually sent, so a
    # blocked domain, a bad role, an unconfigured mailer or a page reload never
    # consumes an attempt (the fix for the counters tripping on non-issuing calls).
    if store.rl_count("vstart_ip", ip, _HOUR) >= config.ASM_VERIFY_START_PER_HOUR:
        return JSONResponse({"error": "Too many verification attempts. Try again later."}, status_code=429)
    if store.rl_count("vstart_dom", domain, _DAY) >= config.ASM_VERIFY_START_PER_DOMAIN_PER_DAY:
        return JSONResponse({"error": "This domain has reached its verification attempts for today."}, status_code=429)

    if payload.method == "email":
        role = (payload.role or "").strip().lower()
        if role not in ROLE_PREFIXES:
            return JSONResponse({"error": "Choose a role address."}, status_code=400)
        if store.rl_count("vemail_dom", domain, _DAY) >= config.ASM_VERIFY_EMAIL_PER_DOMAIN_PER_DAY:
            return JSONResponse({"error": "This domain has reached its email verification limit for today."}, status_code=429)
        if not mailer.configured():
            return JSONResponse({"error": "Email verification is not available on this server; use the DNS method."}, status_code=503)
        started = verify.start_email_verification(domain, role, _ip_hash(ip))
        if not started:
            return JSONResponse({"error": "Choose a role address."}, status_code=400)
        raw, role_email = started
        # Count now: a token was issued and an email is about to be sent.
        store.rl_record("vstart_ip", ip)
        store.rl_record("vstart_dom", domain)
        store.rl_record("vemail_dom", domain)
        link = f"{config.OPERATOR_SITE_ORIGIN}/asm/confirm?t={raw}"
        await mailer.send_verification_link(domain, role_email, link)
        return {"method": "email", "sent_to": role_email}

    # DNS method: a token is always issued on this path, so count it.
    token = verify.start_dns_verification(domain, _ip_hash(ip))
    store.rl_record("vstart_ip", ip)
    store.rl_record("vstart_dom", domain)
    return {
        "method": "dns",
        "apex_record": {"name": domain, "type": "TXT", "value": f"{verify.TXT_PREFIX}{token}"},
        "under_record": {"name": f"_falconeye.{domain}", "type": "TXT", "value": token},
    }


class CheckReq(BaseModel):
    domain: str


@router.post("/verify/check-dns")
@limiter.limit("10/minute")
async def verify_check_dns(request: Request, payload: CheckReq, response: Response):
    domain = _norm(payload.domain)
    if not domain or blocklist.is_blocked(domain):
        return JSONResponse(_BLOCK_BODY if domain else {"error": "Enter a valid domain."},
                            status_code=200 if domain else 400)
    # A check is not a token issue or an email send, so it is NOT counted in the
    # persistent limit table (a user waiting on DNS propagation may poll several
    # times). The slowapi burst limit above bounds abuse of the DNS probe.

    row = await verify.check_dns(domain)
    if not row:
        return {"verified": False, "message": "The TXT record was not found yet. "
                                              "DNS can take a few minutes to propagate."}
    store.upsert_domain(domain, "verified", source="verify", verify_method="dns")
    cookie = verify.issue_grant(domain, "dns", "")
    _set_cookie(response, GRANT_COOKIE, cookie, config.ASM_GRANT_DAYS * _DAY)
    log.info("asm verified method=dns domain=%s", tag(domain))
    return {"verified": True, "domain": domain, "grant_days": config.ASM_GRANT_DAYS}


# ------------------------------------------------------------------- scan ----

class ScanReq(BaseModel):
    domain: str
    engagement: str = ""
    confirm_domain: str = ""


@router.post("/scan")
@limiter.limit("6/minute")
async def start_scan(request: Request, payload: ScanReq, response: Response):
    domain = _norm(payload.domain)
    if not domain:
        return JSONResponse({"error": "Enter a valid domain."}, status_code=400)

    op = _operator(request)
    ip = _ip(request)

    if op:
        engagement = (payload.engagement or "").strip()
        if not engagement:
            return JSONResponse({"error": "An engagement reference is required for an operator scan."}, status_code=400)
        reason = blocklist.classify(domain)
        if reason and not reason.operator_override:
            return JSONResponse({"error": "Public suffixes can never be scanned."}, status_code=400)
        if reason and reason.operator_override:
            if (payload.confirm_domain or "").strip().lower() != domain:
                return JSONResponse({"needs_confirmation": True,
                                     "message": "This domain is on the block list. Retype the exact "
                                                "domain to confirm scanning it."}, status_code=409)
        if not _rl_ok("scan_op", ip, config.ASM_OPERATOR_SCAN_PER_DAY, _DAY):
            return JSONResponse({"error": "Operator daily scan limit reached."}, status_code=429)
        store.upsert_domain(domain, "operator", source="operator", operator=1, engagement=engagement)
        store.record_operator_audit("scan", _ip_hash(ip), engagement, domain)
        return _launch(domain, "on_demand", response, operator=1, engagement=engagement)

    # Normal user.
    if blocklist.is_blocked(domain):
        return JSONResponse(_BLOCK_BODY, status_code=200)
    grant = _grant_for(request, domain)
    if not grant:
        return JSONResponse({"error": "Ownership of this domain is not verified.",
                             "needs_verification": True}, status_code=403)
    if not await verify.recheck_grant(grant):
        return JSONResponse({"error": "Ownership could not be re-confirmed. The DNS verification "
                                      "record is no longer present."}, status_code=403)
    if not _rl_ok("scan_user", ip, config.ASM_SCAN_PER_DAY, _DAY):
        return JSONResponse({"error": "Daily scan limit reached. Try again later."}, status_code=429)
    return _launch(domain, "on_demand", response, operator=0, grant_id=grant["grant_id"])


def _launch(domain: str, mode: str, response: Response, *, operator: int = 0,
            engagement: str = "", grant_id: str = ""):
    # Capacity is read from the shared scan table, so the cap and queue hold across
    # every gunicorn worker, not per worker.
    if not jobs.can_accept():
        return JSONResponse({"error": "The scanner is at capacity. Try again in a few minutes."},
                            status_code=503)
    scan_id = secrets.token_urlsafe(18)
    store.create_scan(scan_id, domain, mode, operator=operator, engagement=engagement,
                      grant_id=grant_id, state="queued")
    jobs.submit(scan_id)
    return {"scan_id": scan_id, "state": "queued", "capacity": jobs.capacity()}


def _authorize_scan(request: Request, scan: dict) -> bool:
    if scan.get("operator"):
        return _operator(request) is not None
    return _grant_for(request, scan["domain"]) is not None


@router.get("/scan/{scan_id}")
async def get_scan(request: Request, scan_id: str):
    scan = store.get_scan(scan_id)
    # 404 both for a missing scan and for one the caller may not see, so existence
    # is never revealed.
    if not scan or not _authorize_scan(request, scan):
        return JSONResponse({"error": "Not found."}, status_code=404)
    body = {"scan_id": scan_id, "state": scan["state"], "capacity": jobs.capacity()}
    if scan["state"] == "done":
        body = report.api_payload(scan, store.get_hosts(scan_id), store.get_findings(scan_id))
        body["capacity"] = jobs.capacity()
    elif scan["state"] == "error":
        body["error"] = scan.get("error")
    return body


@router.get("/scan/{scan_id}/export.{fmt}")
async def export_scan(request: Request, scan_id: str, fmt: str):
    scan = store.get_scan(scan_id)
    if not scan or not _authorize_scan(request, scan) or scan["state"] != "done":
        return JSONResponse({"error": "Not found."}, status_code=404)
    hosts, found = store.get_hosts(scan_id), store.get_findings(scan_id)
    base = f"falconeye-asm-{scan['domain'].replace('.', '-')}"
    if fmt == "csv":
        return PlainTextResponse(report.export_csv(scan, hosts, found), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="{base}.csv"'})
    if fmt == "json":
        return PlainTextResponse(report.export_json(scan, hosts, found), media_type="application/json",
                                 headers={"Content-Disposition": f'attachment; filename="{base}.json"'})
    return JSONResponse({"error": "Unknown format."}, status_code=400)


# ------------------------------------------------------------- session view ----

@router.get("/session")
async def session_view(request: Request, domain: str = ""):
    """What this browser may do with *domain*: whether it holds a grant, and the
    domain's monitoring state. Requires the grant cookie, so it reveals nothing to
    anyone else."""
    dom = _norm(domain)
    out = {"operator": _operator(request) is not None,
           "monitoring_enabled": config.ASM_MONITORING_ENABLED,
           "operator_configured": config.asm_operator_configured()}
    if not dom:
        return out
    grant = _grant_for(request, dom)
    if not grant:
        out["verified"] = False
        return out
    row = store.get_domain(dom) or {}
    out.update({
        "verified": True, "domain": dom, "method": grant.get("method"),
        "monitor": {"enabled": bool(row.get("monitor_enabled")),
                    "freq": row.get("monitor_freq") or "weekly",
                    "paused": bool(row.get("monitor_paused")),
                    "notify_email": row.get("notify_email") or grant.get("notify_email") or ""},
    })
    return out


# -------------------------------------------------------------- monitoring ----

class MonitorReq(BaseModel):
    domain: str
    enabled: bool = True
    freq: str = "weekly"
    notify_email: str = ""


@router.post("/monitor")
async def set_monitor(request: Request, payload: MonitorReq):
    domain = _norm(payload.domain)
    if not domain:
        return JSONResponse({"error": "Enter a valid domain."}, status_code=400)
    op = _operator(request)
    grant = _grant_for(request, domain)
    if not op and not grant:
        return JSONResponse({"error": "Not authorized."}, status_code=403)
    if not config.ASM_MONITORING_ENABLED:
        return JSONResponse({"error": "Monitoring is not enabled on this server."}, status_code=400)
    freq = payload.freq if payload.freq in ("daily", "weekly") else "weekly"
    row = store.get_domain(domain) or {}
    notify = (payload.notify_email or row.get("notify_email")
              or (grant.get("notify_email") if grant else "") or config.OPERATOR_CONTACT_EMAIL)
    if payload.enabled:
        if not row.get("monitor_enabled") and store.count_monitored() >= config.ASM_MAX_MONITORED:
            return JSONResponse({"error": "This instance has reached its monitored-domain limit."}, status_code=400)
        if store.count_monitored_for_notify(notify) >= config.ASM_MAX_PER_NOTIFY and not row.get("monitor_enabled"):
            return JSONResponse({"error": "This address has reached its monitored-domain limit."}, status_code=400)
    store.set_monitoring(domain, payload.enabled, freq, notify)
    return {"ok": True, "enabled": payload.enabled, "freq": freq}


# ------------------------------------------------------- in-tab management ----

class ManageReq(BaseModel):
    domain: str


@router.post("/manage/revoke")
async def manage_revoke(request: Request, payload: ManageReq, response: Response):
    domain = _norm(payload.domain)
    if not domain or not (_operator(request) or _grant_for(request, domain)):
        return JSONResponse({"error": "Not authorized."}, status_code=403)
    n = store.revoke_all_grants(domain)
    response.delete_cookie(GRANT_COOKIE, path="/")
    return {"ok": True, "revoked": n}


@router.post("/manage/delete")
async def manage_delete(request: Request, payload: ManageReq, response: Response):
    domain = _norm(payload.domain)
    if not domain or not (_operator(request) or _grant_for(request, domain)):
        return JSONResponse({"error": "Not authorized."}, status_code=403)
    store.delete_domain(domain)
    response.delete_cookie(GRANT_COOKIE, path="/")
    log.info("asm data deleted domain=%s", tag(domain))
    return {"ok": True}


@router.post("/manage/rotate")
async def manage_rotate(request: Request, payload: ManageReq):
    domain = _norm(payload.domain)
    grant = _grant_for(request, domain)
    if not domain or not (_operator(request) or grant):
        return JSONResponse({"error": "Not authorized."}, status_code=403)
    store.bump_mgmt_version(domain)
    row = store.get_domain(domain) or {}
    notify = row.get("notify_email") or (grant.get("notify_email") if grant else "")
    if notify:
        await mailer.send_management_link(notify, domain, verify.management_link(domain))
        return {"ok": True, "emailed_to": notify}
    return {"ok": True, "emailed_to": None,
            "note": "No confirmed address on file, so the old link is now invalid but no new one was mailed."}


# ----------------------------------------------------------- operator mode ----

class UnlockReq(BaseModel):
    key: str = ""
    code: str = ""


@router.post("/operator/unlock")
@limiter.limit("10/minute")
async def operator_unlock(request: Request, payload: UnlockReq, response: Response):
    # 404 shaped when operator mode is not configured: no trace that it exists.
    if not operator.configured():
        return JSONResponse({"error": "Not found."}, status_code=404)
    ip = _ip(request)
    if not operator.cidr_ok(ip):
        return JSONResponse({"error": "Not found."}, status_code=404)
    wait = operator.lockout_remaining(ip)
    if wait > 0:
        return JSONResponse({"error": "Too many attempts.", "retry_after": wait}, status_code=429)
    if not operator.verify_credentials(payload.key, payload.code):
        operator.record_fail(ip)
        store.record_operator_audit("unlock_fail", _ip_hash(ip))
        await mailer.send_operator_notice(
            "FalconEye: failed operator unlock",
            f"A failed operator unlock attempt was made. Client hash {_ip_hash(ip)}.")
        return JSONResponse({"error": "Unlock failed."}, status_code=401)
    operator.clear_fail(ip)
    cookie = operator.begin_session(_ip_hash(ip))
    store.record_operator_audit("unlock_ok", _ip_hash(ip))
    await mailer.send_operator_notice(
        "FalconEye: operator mode unlocked",
        f"An operator session was started. Client hash {_ip_hash(ip)}. "
        f"It lasts {config.ASM_OPERATOR_SESSION_HOURS} hours.")
    _set_cookie(response, OP_COOKIE, cookie, config.ASM_OPERATOR_SESSION_HOURS * _HOUR)
    return {"unlocked": True, "hours": config.ASM_OPERATOR_SESSION_HOURS}


@router.post("/operator/lock")
async def operator_lock(request: Request, response: Response):
    if not operator.configured():
        return JSONResponse({"error": "Not found."}, status_code=404)
    operator.lock(request.cookies.get(OP_COOKIE, ""))
    response.delete_cookie(OP_COOKIE, path="/")
    return {"ok": True}


# -------------------------------------------------------------------- MCP ----

class McpDiscoverReq(BaseModel):
    domain: str
    engagement_reference: str = ""


@router.post("/mcp/discover")
async def mcp_discover(request: Request, payload: McpDiscoverReq):
    """Operator-context discovery for the local stdio MCP server.

    Active only when ASM_MCP_OPERATOR is set in the process environment, which is
    only ever the MCP server's own environment, never the public web app's. So
    this returns 404 on the public instance, and a browser cannot reach it even by
    forging the call. It runs synchronously (the agent waits for one result) and,
    unlike the UI operator path, does not override the block list: a blocked
    domain is refused here because there is no interactive retype confirmation.
    """
    if not config.ASM_MCP_OPERATOR:
        return JSONResponse({"error": "Not found."}, status_code=404)
    domain = _norm(payload.domain)
    if not domain:
        return JSONResponse({"error": "Enter a valid domain."}, status_code=400)
    engagement = (payload.engagement_reference or "").strip()
    if not engagement:
        return JSONResponse({"error": "engagement_reference is required."}, status_code=400)
    if blocklist.is_blocked(domain):
        return JSONResponse(_BLOCK_BODY, status_code=200)
    store.upsert_domain(domain, "operator", source="mcp", operator=1, engagement=engagement)
    store.record_operator_audit("mcp_scan", "mcp", engagement, domain)
    scan_id = secrets.token_urlsafe(18)
    store.create_scan(scan_id, domain, "on_demand", operator=1, engagement=engagement, state="queued")
    await jobs.run_scan(scan_id)
    scan = store.get_scan(scan_id)
    return report.api_payload(scan, store.get_hosts(scan_id), store.get_findings(scan_id))


# -------------------------------------------------------------- HTML pages ----

_PAGE_CSS = (
    "body{background:#030712;color:#f3f4f6;font-family:system-ui,-apple-system,Segoe UI,sans-serif;"
    "margin:0;padding:40px 16px;line-height:1.5}.card{max-width:520px;margin:0 auto;background:#0f1623;"
    "border:1px solid #2b394f;border-radius:14px;padding:28px}h1{font-size:1.3rem;margin:0 0 6px}"
    ".amber{color:#fbbf24}code{background:#1a2434;padding:2px 7px;border-radius:5px;font-size:1.05rem}"
    "button{background:#fbbf24;color:#030712;border:none;border-radius:9px;padding:11px 20px;"
    "font-weight:700;font-size:.95rem;cursor:pointer}a{color:#fbbf24}ul{color:#94a3b8;font-size:.9rem}"
    ".muted{color:#94a3b8;font-size:.9rem}"
)


def _page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{_PAGE_CSS}</style></head>"
        f"<body><div class='card'>{body}</div></body></html>", status_code=status)


_CONFIRM_ERRORS = {
    "used": ("Link already used",
             "This authorisation link has already been used. Start the verification again "
             "in FalconEye to get a new one."),
    "expired": ("Link expired",
                "This authorisation link has expired. Start the verification again in "
                "FalconEye to get a new one."),
    "unknown": ("Link not recognised",
                "This authorisation link is not recognised. Start the verification again in "
                "FalconEye to get a new one."),
}


def _confirm_error_page(status: str) -> HTMLResponse:
    title, msg = _CONFIRM_ERRORS.get(status, _CONFIRM_ERRORS["unknown"])
    return _page(title, f"<h1>{html.escape(title)}</h1><p class='muted'>{msg}</p>", status=410)


@pages.get("/asm/confirm")
async def confirm_page(t: str = ""):
    status, row = verify.confirm_detail(t)
    if status != "ok":
        return _confirm_error_page(status)
    domain = html.escape(row["domain"])
    body = (
        f"<h1>Authorise an attack surface scan</h1>"
        f"<p>You are about to authorise FalconEye to run an <strong>attack surface scan of</strong> "
        f"<code>{domain}</code>.</p>"
        f"<ul><li>This authorises scanning of {domain} and its subdomains for up to "
        f"{config.ASM_GRANT_DAYS} days.</li>"
        f"<li>The authorisation is bound to <strong>this browser</strong>.</li>"
        f"<li>You can revoke it any time from the management link in your email.</li></ul>"
        f"<form method='post' action='/asm/confirm'>"
        f"<input type='hidden' name='t' value='{html.escape(t)}'>"
        f"<button type='submit'>Authorise scan of {domain}</button></form>"
    )
    return _page("Authorise scan", body)


@pages.post("/asm/confirm")
async def confirm_submit(request: Request):
    form = await request.form()
    t = str(form.get("t", ""))
    row = verify.confirm_consume(t)
    if not row:
        status, _ = verify.confirm_detail(t)
        return _confirm_error_page(status)
    domain = row["domain"]
    role_email = verify.role_address(domain, row.get("role") or "") or ""
    store.upsert_domain(domain, "verified", source="verify", verify_method="email",
                        notify_email=role_email)
    cookie = verify.issue_grant(domain, "email", role_email)
    if role_email and mailer.configured():
        await mailer.send_management_link(role_email, domain, verify.management_link(domain))
    log.info("asm verified method=email domain=%s", tag(domain))
    resp = RedirectResponse(url="/#attacksurface", status_code=303)
    _set_cookie(resp, GRANT_COOKIE, cookie, config.ASM_GRANT_DAYS * _DAY)
    return resp


_MANAGE_ERRORS = {
    "bad": ("Link could not be verified",
            "This management link could not be verified. Use the most recent link exactly as "
            "it was emailed to you."),
    "expired": ("Link expired", "This management link has expired."),
    "rotated": ("Link replaced",
                "This link has been replaced by a newer one. Use your most recent management link."),
    "deleted": ("Data already deleted",
                "The data for this domain has already been deleted, so there is nothing to manage."),
}


def _manage_error_page(status: str) -> HTMLResponse:
    title, msg = _MANAGE_ERRORS.get(status, _MANAGE_ERRORS["bad"])
    return _page(title, f"<h1>{html.escape(title)}</h1><p class='muted'>{msg}</p>", status=410)


@pages.get("/asm/manage")
async def manage_page(t: str = ""):
    status, domain = verify.management_detail(t)
    if status != "ok":
        return _manage_error_page(status)
    d = html.escape(domain)
    tok = html.escape(t)
    body = (
        f"<h1>Manage access for <span class='amber'>{d}</span></h1>"
        f"<p class='muted'>These actions take effect immediately.</p>"
        f"<form method='post' action='/asm/manage' style='display:flex;flex-direction:column;gap:12px'>"
        f"<input type='hidden' name='t' value='{tok}'>"
        f"<button name='action' value='rotate'>Rotate this management link</button>"
        f"<button name='action' value='revoke'>Revoke all access grants</button>"
        f"<button name='action' value='delete'>Delete all data for {d}</button></form>"
    )
    return _page("Manage access", body)


@pages.post("/asm/manage")
async def manage_submit(request: Request):
    form = await request.form()
    t = str(form.get("t", ""))
    action = str(form.get("action", ""))
    status, domain = verify.management_detail(t)
    if status != "ok":
        return _manage_error_page(status)
    if action == "revoke":
        n = store.revoke_all_grants(domain)
        return _page("Revoked", f"<h1>Access revoked</h1><p class='muted'>Revoked {n} grant(s) for "
                     f"{html.escape(domain)}.</p>")
    if action == "delete":
        store.delete_domain(domain)
        log.info("asm data deleted (mgmt link) domain=%s", tag(domain))
        return _page("Deleted", f"<h1>Data deleted</h1><p class='muted'>Every record for "
                     f"{html.escape(domain)} has been removed.</p>")
    if action == "rotate":
        store.bump_mgmt_version(domain)
        row = store.get_domain(domain) or {}
        notify = row.get("notify_email") or ""
        if notify and mailer.configured():
            await mailer.send_management_link(notify, domain, verify.management_link(domain))
        return _page("Rotated", "<h1>Link rotated</h1><p class='muted'>The old link no longer works. "
                     "A new management link has been emailed to the address on file.</p>")
    return _page("Unknown action", "<h1>Unknown action</h1>", status=400)
