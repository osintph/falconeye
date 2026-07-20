"""
Mailgun sender for composed abuse reports (optional feature — Option B).

Before contacting Mailgun this module:
  * validates the recipient against the strict email regex,
  * refuses any recipient the tool did not itself resolve via RDAP
    (store.recipient_seen_in_cache) — so valid admin auth still cannot be used
    to send mail to an arbitrary address,
  * enforces per-IP, per-recipient, and global rate limits.

On a successful send it records rate-limit events and an append-only audit row.
The Mailgun API key is read from the environment at call time and is never
logged, never included in an error string, and never returned to the caller.
"""
import logging
import re

import httpx

from app.abuse import store
from app.utils.env import getenv_clean

log = logging.getLogger("falconeye.abuse")

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

# NOTE: Send is NOT rate-limited (v3.8.3). It is admin-authenticated and
# single-user, so a rate limit added no protection and only created debugging
# friction. Auth, the RDAP-recipient allowlist, and the audit log all remain.
# The abuse_send_rate_limit table is left in place (no destructive migration in
# a hotfix); it is simply no longer written to or read.


def _norm_region(raw) -> str:
    """Normalize MAILGUN_REGION to 'us' or 'eu'.

    Defensive against an inline comment left in the env file (systemd's
    EnvironmentFile does not strip trailing '# ...' comments), e.g.
    'eu   # or us' -> 'eu'. Anything unrecognized falls back to 'us'.
    """
    s = (raw or "").strip()
    if not s:
        return "us"
    token = s.split()[0].split("#")[0].strip().lower()
    return token if token in ("us", "eu") else "us"


def _mailgun_base(region: str) -> str:
    return "https://api.eu.mailgun.net" if region == "eu" else "https://api.mailgun.net"


def _config() -> dict:
    # getenv_clean strips any inline comment / quotes systemd leaves in the value
    # (see docs/regressions.md, v3.8.1). _norm_region stays as a second guard.
    return {
        "api_key": getenv_clean("MAILGUN_API_KEY"),
        "domain": getenv_clean("MAILGUN_DOMAIN"),
        "from": getenv_clean("MAILGUN_FROM"),
        "region": _norm_region(getenv_clean("MAILGUN_REGION")),
    }


def mailgun_configured() -> bool:
    c = _config()
    return bool(c["api_key"] and c["domain"] and c["from"])


async def send_via_mailgun(composed: dict, recipient_email: str, client_ip: str) -> dict:
    """Send a composed report via Mailgun. Never raises."""
    result = {"sent": False, "mailgun_message_id": None, "error": None, "rate_limited": False}

    recipient = (recipient_email or "").strip()
    if not EMAIL_RE.match(recipient) or len(recipient) > 254:
        result["error"] = "Invalid recipient email address."
        return result

    # Recipient allowlist: only an address the tool itself resolved via RDAP, OR
    # the operator's own configured reporter address (so "send a test to your own
    # inbox" works without weakening the arbitrary-recipient protection).
    reporter_self = getenv_clean("FALCONEYE_REPORTER_EMAIL").lower()
    allowed = store.recipient_seen_in_cache(recipient) or (
        bool(reporter_self) and recipient.lower() == reporter_self
    )
    if not allowed:
        result["error"] = (
            "Recipient was not returned by a recent RDAP lookup; refusing to send. "
            "Run the abuse contact lookup first."
        )
        return result

    cfg = _config()
    if not (cfg["api_key"] and cfg["domain"] and cfg["from"]):
        result["error"] = "Mailgun is not configured on this server."
        return result

    composed = composed or {}
    subject = str(composed.get("subject", "") or "")
    body_text = str(composed.get("body_text", "") or "")
    reporter_email = str(composed.get("reporter_email", "") or "")
    category = str(composed.get("category", "other") or "other")
    target = str(composed.get("target", "") or "")
    target_type = str(composed.get("target_type", "") or "")

    # Defense in depth: compose already sanitized, but strip header-breaking
    # characters from the single-line fields once more before they hit the API.
    subject = subject.replace("\r", " ").replace("\n", " ").strip()[:255] or "Abuse Report"
    reporter_email = reporter_email.replace("\r", "").replace("\n", "").strip()

    form = {
        "from": cfg["from"],
        "to": recipient,
        "subject": subject,
        "text": body_text,
        "o:tag": ["abuse-report", f"category:{category}"[:64]],
        "h:X-Report-Abuse": target[:255],
    }
    if EMAIL_RE.match(reporter_email or ""):
        form["h:Reply-To"] = reporter_email

    endpoint = f"{_mailgun_base(cfg['region'])}/v3/{cfg['domain']}/messages"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(endpoint, auth=("api", cfg["api_key"]), data=form)
    except Exception as exc:
        # Never interpolate cfg/api_key into the message.
        result["error"] = f"Mailgun request failed ({type(exc).__name__})."
        store.record_audit(client_ip, recipient, target, target_type, category, subject, None, False)
        return result

    if resp.status_code == 200:
        msg_id = None
        try:
            msg_id = resp.json().get("id")
        except Exception:
            msg_id = None
        result["sent"] = True
        result["mailgun_message_id"] = msg_id
        store.record_audit(client_ip, recipient, target, target_type, category, subject, msg_id, True)
        return result

    # Non-200: surface a trimmed Mailgun error body (contains no secret) but not the key.
    detail = ""
    try:
        detail = (resp.text or "")[:200]
    except Exception:
        detail = ""
    result["error"] = f"Mailgun returned HTTP {resp.status_code}. {detail}".strip()
    store.record_audit(client_ip, recipient, target, target_type, category, subject, None, False)
    return result
