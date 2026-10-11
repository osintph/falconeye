"""Signed, expiring tokens for ASM grants, management links and operator sessions.

Three things in ASM are proven by possession of a signed value rather than by a
database row alone:

  grant             a successful verification issues this, bound to the browser
                    that holds the cookie. Default 30 days.
  management link   emailed to the confirmed address so the owner can rotate it,
                    revoke all grants, or delete every record for the domain.
  operator session  issued by the unlock route, short-lived (default 8h).

itsdangerous gives tamper-evidence and a built-in expiry without a database read
on every request, which is what a cookie check wants. Single-use verification
tokens are NOT signed here: those are random, stored hashed, and consumed in the
database (see verify.py), because single-use is a property the signature cannot
carry on its own.

The key comes from ASM_SIGNING_KEY. The setup script writes a high-entropy value
so grants survive a restart. Left unset, a per-process random key is used: every
restart then invalidates outstanding grants and links, which is safe but means an
operator who wants persistent grants must set the key. Never log the key.

No em dashes in this module.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.utils.env import getenv_clean

log = logging.getLogger("falconeye.asm.signing")

GRANT_SALT = "asm-grant-v1"
MGMT_SALT = "asm-mgmt-v1"
OPERATOR_SALT = "asm-operator-session-v1"


def _key() -> str:
    """The configured signing key, read live. There is NO per-process fallback:
    without ASM_SIGNING_KEY, ASM is disabled at the router (configured() is False)
    and sign() is never reached. A per-process fallback would silently invalidate
    every grant on each worker restart and differ between workers, so it is gone."""
    return getenv_clean("ASM_SIGNING_KEY")


def configured() -> bool:
    """True only when ASM_SIGNING_KEY is set. When False, the ASM router answers
    503 and the tab shows the feature as unavailable."""
    return bool(_key())


def _serializer(salt: str) -> URLSafeTimedSerializer:
    key = _key()
    if not key:
        # Guarded by the router (configured()), so this only trips a direct caller
        # that skipped the gate. Fail loudly rather than sign with an empty key.
        raise RuntimeError("ASM_SIGNING_KEY is not set")
    return URLSafeTimedSerializer(secret_key=key, salt=salt)


def sign(payload: dict, salt: str) -> str:
    """Sign *payload* (a small JSON-able dict) under *salt*."""
    return _serializer(salt).dumps(payload)


def unsign(token: str, salt: str, max_age_seconds: int) -> Optional[dict]:
    """Return the payload if the token is valid and within max_age, else None.

    Fails closed: a tampered, expired, malformed or wrong-salt token is None, so
    a caller that forgets to check the result still denies access rather than
    trusting junk.
    """
    if not token:
        return None
    try:
        value: Any = _serializer(salt).loads(token, max_age=max_age_seconds)
    except SignatureExpired:
        return None
    except BadSignature:
        return None
    except Exception:  # noqa: BLE001 - any decode failure is a denial, never a 500
        return None
    return value if isinstance(value, dict) else None
