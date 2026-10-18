"""Keyed hashes for values FalconEye keeps after a run's result is purged.

v3.39.0. Before this, the Attack Surface and Phishing Hunt run records kept the
domain, keyword and legitimate domain in plain text, and the audit row held an
unsalted, truncated SHA-256 of the domain or keyword: for a brand keyword that is
a dictionary lookup away from the plain text. Both now hold
HMAC-SHA256(FE_HASH_KEY, value).

Every value carries the ``h1:`` prefix, so a converted row is recognisable and
the release action and the sweep can convert exactly the rows still in plain
text, idempotently.

Without FE_HASH_KEY (the scripts generate one, so this means a hand-run
instance) the key is a per-process random value: nothing is stored in plain
text, but the hashes cannot be matched across restarts or workers. A warning is
logged once. Never log the key.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets

from app import config

log = logging.getLogger("falconeye.fehash")

PREFIX = "h1:"
_fallback_key: bytes | None = None


def _key() -> bytes:
    global _fallback_key
    if config.FE_HASH_KEY:
        return config.FE_HASH_KEY.encode("utf-8")
    if _fallback_key is None:
        _fallback_key = secrets.token_bytes(32)
        log.warning("FE_HASH_KEY is not set; using a per-process key, so stored run "
                    "hashes cannot be matched after a restart. Run scripts/upgrade.sh "
                    "to generate one.")
    return _fallback_key


def is_hashed(value: str | None) -> bool:
    return bool(value) and str(value).startswith(PREFIX)


def hmac_value(value: str | None) -> str:
    """``h1:`` + hex HMAC-SHA256 of the normalised value. Empty stays empty, and a
    value that is already hashed is returned unchanged."""
    if not value:
        return ""
    value = str(value)
    if is_hashed(value):
        return value
    norm = value.strip().lower().encode("utf-8")
    return PREFIX + hmac.new(_key(), norm, hashlib.sha256).hexdigest()
