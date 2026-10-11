"""Operator mode: the master-key bypass for authorized engagements.

Disabled unless BOTH ASM_OPERATOR_KEY_HASH and ASM_OPERATOR_TOTP_SECRET are set.
When off, the router answers the unlock routes with 404 and the UI shows no trace
of the feature. The setup script (scripts/asm_operator_setup.py) generates the key
and the TOTP secret, prints both once, and stores only the bcrypt hash and the
secret.

Unlock needs the key AND a current TOTP code, from a source inside
ASM_OPERATOR_ALLOWED_CIDRS when that is set. Repeated failures from one IP lock
out with exponential backoff. The unlock issues a short-lived session (default 8h)
recorded in asm_operator_sessions; the session cookie is the signed session id.

The key hash uses bcrypt, matching the abuse-send admin auth, as the brief
directed. No em dashes in this module.
"""
from __future__ import annotations

import ipaddress
import logging
import secrets
from dataclasses import dataclass
from typing import Optional

import bcrypt
import pyotp

from app import config
from app.asm import signing, store
from app.utils.env import getenv_clean

log = logging.getLogger("falconeye.asm.operator")

# Lockout, same shape as the abuse-send backoff: the first few failures are free,
# then each further failure imposes a doubling cooldown up to a cap.
_FAIL_SCOPE = "op_fail"
FAIL_FREE = 3
BACKOFF_BASE = 5
BACKOFF_MAX = 900  # 15 minutes
FAIL_WINDOW = 3600


def configured() -> bool:
    return config.asm_operator_configured()


def hash_key(key: str) -> str:
    """Create the bcrypt hash for the setup script to store. Not used at runtime."""
    return bcrypt.hashpw(key.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _cidrs() -> list:
    nets = []
    for part in (getenv_clean("ASM_OPERATOR_ALLOWED_CIDRS") or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            log.warning("asm.operator: ignoring unparseable CIDR in ASM_OPERATOR_ALLOWED_CIDRS")
    return nets


def cidr_ok(ip: str) -> bool:
    """True when *ip* may attempt an unlock. Empty allowlist means any source."""
    nets = _cidrs()
    if not nets:
        return True
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def lockout_remaining(client_ip: str) -> int:
    """Seconds the caller must wait before another unlock attempt, or 0."""
    fails = store.rl_count(_FAIL_SCOPE, client_ip, FAIL_WINDOW)
    if fails <= FAIL_FREE:
        return 0
    cooldown = min(BACKOFF_MAX, BACKOFF_BASE * (2 ** (fails - FAIL_FREE - 1)))
    last = store.rl_last_ts(_FAIL_SCOPE, client_ip)
    if last is None:
        return 0
    waited = store.now() - last
    return max(0, cooldown - waited)


def verify_credentials(key: str, code: str) -> bool:
    """True only when the key verifies against the stored hash AND the TOTP code
    is current. Both are evaluated regardless, to avoid a short-circuit timing
    difference between a wrong key and a wrong code."""
    key_hash = getenv_clean("ASM_OPERATOR_KEY_HASH")
    secret = getenv_clean("ASM_OPERATOR_TOTP_SECRET")
    if not key_hash or not secret:
        return False
    try:
        key_ok = bcrypt.checkpw((key or "").encode("utf-8"), key_hash.encode("utf-8"))
    except Exception:  # noqa: BLE001 - malformed stored hash is a failure, not a 500
        key_ok = False
    try:
        totp_ok = pyotp.TOTP(secret).verify((code or "").strip(), valid_window=1)
    except Exception:  # noqa: BLE001
        totp_ok = False
    return bool(key_ok and totp_ok)


def record_fail(client_ip: str) -> None:
    store.rl_record(_FAIL_SCOPE, client_ip)


def clear_fail(client_ip: str) -> None:
    store.rl_clear(_FAIL_SCOPE, client_ip)


def begin_session(client_ip_hash: str) -> str:
    """Create an operator session and return the signed cookie value."""
    sid = secrets.token_urlsafe(24)
    store.create_operator_session(sid, config.ASM_OPERATOR_SESSION_HOURS, client_ip_hash)
    return signing.sign({"sid": sid}, signing.OPERATOR_SALT)


@dataclass(frozen=True)
class OperatorSession:
    sid: str


def session_from_cookie(cookie_value: str) -> Optional[OperatorSession]:
    """Return the live operator session a cookie proves, or None.

    Fails closed on a bad signature, an expired or revoked session, or when
    operator mode is not configured on this instance at all.
    """
    if not configured():
        return None
    payload = signing.unsign(cookie_value, signing.OPERATOR_SALT,
                             config.ASM_OPERATOR_SESSION_HOURS * 3600)
    if not payload or "sid" not in payload:
        return None
    row = store.get_live_operator_session(payload["sid"])
    if not row:
        return None
    return OperatorSession(sid=payload["sid"])


def lock(cookie_value: str) -> None:
    """End the operator session a cookie names, if any."""
    payload = signing.unsign(cookie_value, signing.OPERATOR_SALT,
                             config.ASM_OPERATOR_SESSION_HOURS * 3600)
    if payload and "sid" in payload:
        store.revoke_operator_session(payload["sid"])
