"""Outbound mail for ASM, over the same Mailgun path the abuse tab uses.

The abuse send has its own recipient allowlist (an address returned by a prior
RDAP lookup, or the operator's reporter inbox), which is exactly wrong for ASM,
so ASM has its own small sender here with its own rules:

  verification link   only to a fixed role address at the exact apex being
                      verified (admin@, security@, ...). Never a typed-in address.
  management link     to the address the grant already confirmed.
  operator notice     to OPERATOR_CONTACT_EMAIL.
  monitoring diff     to the domain's confirmed notify address.

It reads the same MAILGUN_* environment the abuse path reads, so an instance that
can send abuse reports can send these with no extra configuration. Never raises;
returns {sent, error}. Never logs the API key. No em dashes.
"""
from __future__ import annotations

import logging
import re

import httpx

from app import config
from app.utils.env import getenv_clean
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.asm.mailer")

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def _region() -> str:
    token = (getenv_clean("MAILGUN_REGION") or "").split()[0:1]
    token = token[0].split("#")[0].strip().lower() if token else ""
    return token if token in ("us", "eu") else "us"


def _base(region: str) -> str:
    return "https://api.eu.mailgun.net" if region == "eu" else "https://api.mailgun.net"


def _cfg() -> dict:
    return {
        "api_key": getenv_clean("MAILGUN_API_KEY"),
        "domain": getenv_clean("MAILGUN_DOMAIN"),
        "from": getenv_clean("MAILGUN_FROM"),
        "region": _region(),
    }


def configured() -> bool:
    c = _cfg()
    return bool(c["api_key"] and c["domain"] and c["from"])


async def _send(recipient: str, subject: str, body_text: str) -> dict:
    """POST one message to Mailgun. Never raises."""
    result = {"sent": False, "error": None}
    recipient = (recipient or "").strip()
    if not _EMAIL_RE.match(recipient) or len(recipient) > 254:
        result["error"] = "invalid recipient"
        return result
    c = _cfg()
    if not (c["api_key"] and c["domain"] and c["from"]):
        result["error"] = "mail is not configured on this server"
        return result
    subject = (subject or "").replace("\r", " ").replace("\n", " ").strip()[:255] or "FalconEye ASM"
    form = {"from": c["from"], "to": recipient, "subject": subject, "text": body_text or "",
            "o:tag": ["asm"]}
    endpoint = f"{_base(c['region'])}/v3/{c['domain']}/messages"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(endpoint, auth=("api", c["api_key"]), data=form)
    except Exception as exc:  # noqa: BLE001 - never surface the key
        log.warning("asm mail send failed to %s: %s", tag(recipient), type(exc).__name__)
        result["error"] = f"mail request failed ({type(exc).__name__})"
        return result
    if resp.status_code == 200:
        result["sent"] = True
        return result
    result["error"] = f"mail returned HTTP {resp.status_code}"
    log.warning("asm mail to %s returned %s", tag(recipient), resp.status_code)
    return result


async def send_verification_link(domain: str, role_email: str, link: str) -> dict:
    subject = f"Authorise an attack surface scan of {domain}"
    body = (
        f"Someone asked FalconEye to assess the attack surface of {domain}.\n\n"
        f"If that was you, open this one-time link in the browser you want to run the "
        f"scan from and press the button on the page to authorise it:\n\n{link}\n\n"
        f"The link expires in {config.ASM_VERIFY_TOKEN_TTL_HOURS} hours and works once. "
        f"If it was not you, ignore this message and nothing happens.\n\n"
        f"This message was sent to a role address at {domain} because that is the only "
        f"place FalconEye will send it. FalconEye, {config.OPERATOR_SITE_ORIGIN}"
    )
    return await _send(role_email, subject, body)


async def send_management_link(notify_email: str, domain: str, link: str) -> dict:
    subject = f"Manage FalconEye attack surface access for {domain}"
    body = (
        f"Use this link to manage FalconEye access for {domain}. You can rotate this "
        f"link, revoke all access grants, or delete every record FalconEye holds for "
        f"the domain:\n\n{link}\n\nKeep it private: anyone with the link can revoke or "
        f"delete. Rotate it if it may have been seen.\n\nFalconEye, {config.OPERATOR_SITE_ORIGIN}"
    )
    return await _send(notify_email, subject, body)


async def send_operator_notice(subject: str, body: str) -> dict:
    return await _send(config.OPERATOR_CONTACT_EMAIL, subject, body)


async def send_monitor_diff(notify_email: str, domain: str, diff_text: str) -> dict:
    subject = f"FalconEye: attack surface change on {domain}"
    body = (
        f"FalconEye detected a change in the attack surface of {domain}:\n\n{diff_text}\n\n"
        f"Open FalconEye to see the full scan. To stop these emails, turn off monitoring "
        f"or use your management link.\n\nFalconEye, {config.OPERATOR_SITE_ORIGIN}"
    )
    return await _send(notify_email, subject, body)
