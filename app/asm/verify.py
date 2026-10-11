"""The ownership gate: DNS TXT and role-address email, grants, management links.

Two methods prove control of an apex. Both issue a signed, expiring grant bound
to the requester's browser; neither returns any ASM output until that grant
exists.

  DNS TXT   the requester publishes falconeye-verify=<token> on the apex, or the
            bare <token> at _falconeye.<apex>. We check live. The token hash is
            kept on the domain so monitoring and on-demand runs can re-check the
            record is still present before EVERY scan.
  email     a one-time link to a fixed role address at the domain. The grant is
            issued to whichever browser opens the link and presses the button; a
            GET never consumes the token or issues a grant, so a mail scanner that
            pre-fetches the link cannot authorise anything.

Tokens and links are random (secrets.token_urlsafe), single use, expire after
ASM_VERIFY_TOKEN_TTL_HOURS, and are stored only as a SHA-256 hash. The DNS token
is compared by hashing the value observed in DNS, so even it is never stored in
the clear. No em dashes in this module.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
from typing import Optional

import dns.resolver

from app import config
from app.asm import signing, store
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.asm.verify")

# The only addresses the email method will ever mail. Never a typed-in address,
# never a WHOIS contact.
ROLE_PREFIXES = ("admin", "administrator", "hostmaster", "postmaster", "webmaster", "security")
TXT_PREFIX = "falconeye-verify="

GRANT_COOKIE = "asm_grant"
_DNS_TIMEOUT = 5.0


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(raw: str) -> str:
    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ DNS TXT ----

def _txt_values_sync(name: str) -> list:
    out = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = _DNS_TIMEOUT
        resolver.timeout = _DNS_TIMEOUT
        for r in resolver.resolve(name, "TXT"):
            out.append(b"".join(r.strings).decode("utf-8", errors="replace").strip())
    except Exception:
        return []
    return out


async def _dns_candidate_tokens(domain: str) -> list:
    """Every value in DNS that could be our proof token, from both record shapes."""
    loop = asyncio.get_event_loop()
    apex, under = await asyncio.gather(
        loop.run_in_executor(None, _txt_values_sync, domain),
        loop.run_in_executor(None, _txt_values_sync, f"_falconeye.{domain}"),
    )
    candidates = []
    for v in apex:
        if v.startswith(TXT_PREFIX):
            candidates.append(v[len(TXT_PREFIX):].strip())
    for v in under:
        candidates.append(v.strip())
    return [c for c in candidates if c]


async def dns_token_present(domain: str, token_hash: str) -> bool:
    """True when a TXT value whose hash equals *token_hash* is live in DNS now.

    Used both at verification time and as the per-scan re-check for DNS grants.
    """
    if not token_hash:
        return False
    for candidate in await _dns_candidate_tokens(domain):
        if hash_token(candidate) == token_hash:
            return True
    return False


def start_dns_verification(domain: str, client_ip_hash: str) -> str:
    """Create a pending DNS verification and return the raw token to display."""
    raw = new_token()
    store.upsert_domain(domain, "pending", source="verify", verify_method="dns")
    store.create_verification(domain, "dns", "", hash_token(raw),
                              config.ASM_VERIFY_TOKEN_TTL_HOURS, client_ip_hash)
    return raw


async def check_dns(domain: str) -> Optional[dict]:
    """Confirm a live DNS verification for *domain* against the record in DNS.

    On success, consumes the verification, pins the token hash on the domain for
    future per-scan re-checks, and returns the consumed verification row. Returns
    None when no matching record is live.
    """
    for candidate in await _dns_candidate_tokens(domain):
        th = hash_token(candidate)
        row = store.get_live_verification(th)
        if row and row.get("method") == "dns" and row.get("domain") == domain:
            if store.consume_verification(row["id"]):
                store.set_dns_token_hash(domain, th)
                return row
    return None


# -------------------------------------------------------------------- email ----

def role_address(domain: str, role: str) -> Optional[str]:
    role = (role or "").strip().lower()
    if role not in ROLE_PREFIXES:
        return None
    return f"{role}@{domain}"


def start_email_verification(domain: str, role: str, client_ip_hash: str) -> Optional[tuple]:
    """Create a pending email verification. Returns (raw_token, role_email) or None
    when the role is not in the allowlist."""
    addr = role_address(domain, role)
    if not addr:
        return None
    raw = new_token()
    store.upsert_domain(domain, "pending", source="verify", verify_method="email")
    store.create_verification(domain, "email", role, hash_token(raw),
                              config.ASM_VERIFY_TOKEN_TTL_HOURS, client_ip_hash)
    return raw, addr


def confirm_lookup(raw_token: str) -> Optional[dict]:
    """The pending email verification a link proves, WITHOUT consuming it (GET)."""
    row = store.get_live_verification(hash_token(raw_token))
    if row and row.get("method") == "email":
        return row
    return None


def confirm_consume(raw_token: str) -> Optional[dict]:
    """Consume the email verification a link proves, atomically (POST).

    Returns the row only if it was still unconsumed, so pressing the button twice
    cannot issue two grants.
    """
    row = store.get_live_verification(hash_token(raw_token))
    if not row or row.get("method") != "email":
        return None
    if store.consume_verification(row["id"]):
        return row
    return None


# -------------------------------------------------------------------- grants ----

def issue_grant(domain: str, method: str, notify_email: str) -> str:
    """Issue a grant for *domain* and return the signed cookie value to set."""
    grant_id = secrets.token_urlsafe(18)
    store.issue_grant(grant_id, domain, config.ASM_GRANT_DAYS, notify_email, method)
    log.info("asm grant issued domain=%s method=%s", tag(domain), method)
    return signing.sign({"grant_id": grant_id, "domain": domain}, signing.GRANT_SALT)


def grant_from_cookie(cookie_value: str) -> Optional[dict]:
    """The live grant a cookie proves, or None (bad signature, expired, revoked)."""
    payload = signing.unsign(cookie_value, signing.GRANT_SALT, config.ASM_GRANT_DAYS * 86400)
    if not payload or "grant_id" not in payload:
        return None
    return store.get_live_grant(payload["grant_id"])


async def recheck_grant(grant: dict) -> bool:
    """Re-verify ownership before a scan. DNS grants re-check the TXT record is
    still present; email grants are valid as long as the grant itself is live
    (already guaranteed by get_live_grant)."""
    if grant.get("method") == "dns":
        dom = store.get_domain(grant["domain"])
        th = (dom or {}).get("dns_token_hash")
        return await dns_token_present(grant["domain"], th or "")
    return True


# --------------------------------------------------------------- management ----

def management_link(domain: str) -> str:
    dom = store.get_domain(domain) or {}
    version = dom.get("mgmt_version", 1)
    token = signing.sign({"domain": domain, "v": version, "kind": "mgmt"}, signing.MGMT_SALT)
    return f"{config.OPERATOR_SITE_ORIGIN}/asm/manage?t={token}"


def management_domain(token: str) -> Optional[str]:
    """The domain a management token is still valid for, or None.

    A token is valid only while its embedded version matches the domain's current
    mgmt_version, so rotating the link invalidates every older one.
    """
    payload = signing.unsign(token, signing.MGMT_SALT, 3650 * 86400)
    if not payload or payload.get("kind") != "mgmt":
        return None
    dom = store.get_domain(payload.get("domain", ""))
    if not dom:
        return None
    if payload.get("v") != dom.get("mgmt_version"):
        return None
    return dom["domain"]
