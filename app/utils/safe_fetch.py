"""
SSRF-safe HTTP fetcher for user-supplied URLs.

Defends against two bypass classes identified in H-1:
  1. Redirect-chain bypass: validates every hop independently (follow_redirects=False
     on the underlying client; we parse Location and re-validate before each request).
  2. DNS rebinding (TOCTOU): re-resolves and re-validates the hostname at the start of
     every hop, so a short-TTL rebind between check-time and use-time is caught on the
     next resolution. httpx still performs its own resolution at connect time (the true
     TOCTOU window), but this matches the threatintel-platform posture and narrows the
     gap substantially.

Only call this for requests where the URL is attacker-controlled.  Fixed-host API
calls (Shodan, RDAP, Telegram, etc.) should continue using httpx directly.
"""

import ipaddress
import socket
from typing import Optional
from urllib.parse import urlparse, urljoin

import httpx

ALLOWED_SCHEMES = {"http", "https"}

# Explicit blocks for ranges that ipaddress stdlib does not classify via the
# is_private / is_loopback / is_link_local / is_reserved / is_unspecified
# flags on Python 3.9 (L-1 blocklist completeness):
#   0.0.0.0/8  — "This" network (RFC 1122 §3.2.1.3): also caught by is_private
#   100.64.0.0/10 — CGNAT (RFC 6598): NOT in is_private on Python 3.9
#   64:ff9b::/96  — NAT64 well-known prefix (RFC 6052): NOT reliably in stdlib flags
# Remaining ranges (169.254.0.0/16, fe80::/10, ::/128, ::1, ::ffff:a.b.c.d)
# are caught by is_link_local, is_unspecified, is_loopback, or the ipv4_mapped
# unwrap below.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")


class SafeFetchError(Exception):
    """Raised when safe_fetch refuses or cannot complete a request."""


def is_private_ip(addr: str) -> bool:
    """Return True if *addr* should be blocked (private, loopback, link-local, etc.)."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # fail closed on unparseable addresses

    # Unwrap ::ffff:a.b.c.d to get the real IPv4 address.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True

    if isinstance(ip, ipaddress.IPv4Address):
        if ip in _CGNAT or ip in _THIS_NETWORK:
            return True
    elif isinstance(ip, ipaddress.IPv6Address):
        if ip in _NAT64:
            return True

    return False


def resolve_and_check(host: str) -> list[str]:
    """Resolve *host* and raise SafeFetchError if any returned address is private.

    Returns the list of validated public IP strings on success.
    """
    try:
        results = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SafeFetchError(f"Could not resolve hostname: {host}") from exc

    addrs: list[str] = []
    for result in results:
        addr = result[4][0]
        if is_private_ip(addr):
            raise SafeFetchError(f"Hostname {host!r} resolves to a blocked address: {addr}")
        addrs.append(addr)

    if not addrs:
        raise SafeFetchError(f"No addresses returned for hostname: {host}")

    return addrs


async def safe_fetch(
    url: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    timeout: float = 15.0,
    max_redirects: int = 3,
    allow_redirects: bool = True,
) -> dict:
    """Fetch *url* safely, re-validating every redirect hop against the SSRF blocklist.

    Returns a dict with keys: status, headers, body, url_final.
    Raises SafeFetchError on any policy violation or if max_redirects is exceeded.
    """
    current_url = url

    for hop in range(max_redirects + 1):
        parsed = urlparse(current_url)

        if parsed.scheme not in ALLOWED_SCHEMES:
            raise SafeFetchError(f"Scheme {parsed.scheme!r} is not allowed")

        host = parsed.hostname
        if not host:
            raise SafeFetchError("URL has no hostname")

        resolve_and_check(host)

        async with httpx.AsyncClient(
            follow_redirects=False,
            verify=True,
            timeout=timeout,
        ) as client:
            response = await client.request(
                method,
                current_url,
                headers=headers or {},
            )

        if allow_redirects and response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("location", "").strip()
            if not location:
                raise SafeFetchError("Redirect response missing Location header")

            # Resolve relative redirects against the current URL.
            next_url = urljoin(current_url, location)

            if hop == max_redirects:
                raise SafeFetchError(f"Exceeded maximum redirects ({max_redirects})")

            # 303 mandates GET for the subsequent request.
            if response.status_code == 303:
                method = "GET"

            current_url = next_url
            continue

        return {
            "status": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
            "url_final": str(response.url),
        }

    raise SafeFetchError(f"Exceeded maximum redirects ({max_redirects})")
