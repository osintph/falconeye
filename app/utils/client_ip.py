"""
Real client IP extraction for Cloudflare-fronted deployments.

Nginx restricts inbound connections to Cloudflare IP ranges (see nginx/falconeye.conf).
Any CF-Connecting-IP header that reaches the app has been set by Cloudflare and can be
trusted as the true end-user IP. Do NOT remove the nginx allowlist without updating this
module — without that allowlist, CF-Connecting-IP could be spoofed by an arbitrary caller.
"""
from fastapi import Request


def get_client_ip(request: Request) -> str:
    """Return the real client IP.

    Reads CF-Connecting-IP (set by Cloudflare, trustworthy because nginx only
    accepts connections from Cloudflare IP ranges). Falls back to request.client.host
    when the header is absent (e.g. local dev without Cloudflare).
    """
    cf_ip = request.headers.get("CF-Connecting-IP", "").strip()
    if cf_ip:
        return cf_ip
    return request.client.host if request.client else "unknown"


def get_client_ip_key(request: Request) -> str:
    """slowapi key_func that returns the real client IP."""
    return get_client_ip(request)
