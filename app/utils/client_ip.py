"""
Real client IP extraction for Cloudflare-fronted deployments.

Every per-IP rate limit in this app keys on :func:`get_client_ip`, so this is the
function an attacker attacks to get unbounded paid LLM calls: set ``CF-Connecting-IP``,
rotate the value, get a fresh counter each time.

Two independent defences stop that:

1. nginx (see nginx/falconeye.conf) refuses connections from outside Cloudflare's
   ranges, so an arbitrary caller cannot reach the origin at all.
2. This module only trusts ``CF-Connecting-IP`` when the direct TCP peer is itself a
   Cloudflare edge address (or an explicitly configured ``TRUSTED_PROXY_CIDRS``
   network). If the origin is ever exposed directly — a second listener, a changed
   allowlist, a misconfigured firewall — the header is ignored and the limit keys on
   the real peer address instead.

Defence 2 is what makes the limits hold without depending on config that lives outside
the code. Do not reintroduce an unconditional read of the header.
"""
import ipaddress
import logging

from fastapi import Request

from app.utils.cloudflare_ips import is_trusted_proxy

log = logging.getLogger(__name__)

UNKNOWN_IP = "unknown"

# One warning per process, not per request: the condition below is reachable by
# any caller, so logging it every time hands an attacker a log-flooding primitive.
# Once is enough — it is a standing configuration signal, not a per-request event.
_warned_untrusted_header = False


def _valid_ip(value: str) -> str:
    """Return *value* if it is a well-formed IP address, else ""."""
    value = value.strip()
    if not value:
        return ""
    # A spoofed header can carry anything; a malformed value must never become a
    # rate-limit key, or "unknown" style junk becomes its own unlimited bucket.
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return ""
    return value


def get_client_ip(request: Request) -> str:
    """Return the real client IP, or ``"unknown"`` when it cannot be determined.

    ``CF-Connecting-IP`` is honoured only when the direct TCP peer is a trusted proxy
    (a Cloudflare edge address, or a ``TRUSTED_PROXY_CIDRS`` network) *and* the header
    value parses as an IP address. In every other case the peer address is used, so a
    caller that reaches the origin directly is rate-limited on the address it is
    actually connecting from.
    """
    global _warned_untrusted_header

    peer = ""
    client = getattr(request, "client", None)
    if client is not None:
        peer = _valid_ip(getattr(client, "host", "") or "")

    header = (request.headers.get("CF-Connecting-IP", "") or "").strip()

    if peer and is_trusted_proxy(peer):
        cf_ip = _valid_ip(header)
        if cf_ip:
            return cf_ip
        # Cloudflare always sets this header. Its absence (or a malformed value)
        # means something else is fronting us; fall through to the peer address.
    elif header and not _warned_untrusted_header:
        _warned_untrusted_header = True
        # Either someone is probing the origin directly, or proxy headers are
        # misconfigured and every request is now sharing one rate-limit bucket.
        # Both are worth knowing about, and neither is visible otherwise.
        log.warning(
            "CF-Connecting-IP arrived from untrusted peer %s and was ignored; "
            "rate limits are keying on the peer address. If this is a legitimate "
            "proxy, add its network to TRUSTED_PROXY_CIDRS.",
            peer or "an unknown address",
        )

    return peer or UNKNOWN_IP


def get_client_ip_key(request: Request) -> str:
    """slowapi key_func that returns the real client IP."""
    return get_client_ip(request)
