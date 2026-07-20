"""
SSRF-safe HTTP fetcher for user-supplied URLs.

Threat model and the three bypass classes this closes:
  1. Encoding / IPv6 / metadata bypass: `is_private_ip` classifies the RESOLVED
     address (unwrapping IPv4-mapped IPv6, blocking CGNAT / NAT64 / 0.0.0.0/8 /
     loopback / link-local / reserved). `resolve_and_check` rejects the host if
     ANY resolved address is private.
  2. Redirect-chain bypass: `follow_redirects=False`; each hop's Location is parsed
     and the new URL is fully re-resolved-validated-pinned before it is fetched.
  3. DNS rebinding (TOCTOU) — the v3.11.0 fix: we resolve the hostname ONCE, then
     open the HTTP connection to the VALIDATED IP address, never to the hostname.
     httpx is given an IP-literal URL (so it performs no second resolution), while
     the original hostname is preserved for the TLS SNI / certificate check
     (`extensions={"sni_hostname": host}`) and the HTTP Host header (vhost routing).
     A short-TTL domain can no longer rebind public->internal between check-time
     and connect-time, because there is no connect-time resolution to rebind.

Only call this for requests where the URL is attacker-controlled. Fixed-host API
calls (Shodan, RDAP, Telegram, etc.) may continue using httpx directly.

Reusable primitives for callers that run their own hop loop (e.g. url_expander):
`resolve_pinned(url)` -> PinnedConnection, and `pinned_request(client, method, url)`
which performs a single IP-pinned request. Do NOT introduce a second SSRF guard —
these are the single source of truth.
"""

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, urljoin

import httpx

ALLOWED_SCHEMES = {"http", "https"}

# Explicit blocks for ranges that ipaddress stdlib does not classify via the
# is_private / is_loopback / is_link_local / is_reserved / is_unspecified flags:
#   0.0.0.0/8      — "This" network (RFC 1122 §3.2.1.3)
#   100.64.0.0/10  — CGNAT (RFC 6598): NOT in is_private on older Pythons
#   64:ff9b::/96   — NAT64 well-known prefix (RFC 6052): NOT reliably in stdlib flags
# Remaining ranges (169.254.0.0/16, fe80::/10, ::/128, ::1, ::ffff:a.b.c.d)
# are caught by is_link_local, is_unspecified, is_loopback, or the ipv4_mapped
# unwrap below.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")


class SafeFetchError(Exception):
    """Raised when safe_fetch refuses or cannot complete a request."""


@dataclass
class PinnedConnection:
    """A validated target: the original hostname (for SNI + Host) plus the set of
    resolved public IPs the connection may be pinned to."""
    scheme: str
    host: str          # original hostname — used for TLS SNI, cert check, Host header
    port: int
    ips: list[str]     # validated public IP strings (all passed is_private_ip == False)


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

    Returns the list of validated public IP strings on success. This is the ONE
    resolution: the returned IPs are what callers must pin the connection to.
    """
    try:
        results = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SafeFetchError(f"Could not resolve hostname: {host}") from exc

    addrs: list[str] = []
    seen: set[str] = set()
    for result in results:
        addr = result[4][0]
        # Strip any IPv6 scope id (e.g. fe80::1%en0) before classification/pinning.
        addr = addr.split("%", 1)[0]
        if is_private_ip(addr):
            raise SafeFetchError("hostname resolves to a private or reserved address")
        if addr not in seen:
            seen.add(addr)
            addrs.append(addr)

    if not addrs:
        raise SafeFetchError(f"No addresses returned for hostname: {host}")

    return addrs


def resolve_pinned(url: str) -> PinnedConnection:
    """Validate scheme/host and resolve *url* to a set of validated public IPs.

    Raises SafeFetchError (fail closed) on a disallowed scheme, embedded userinfo,
    a missing hostname, an unresolvable host, or any resolved private/reserved IP.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SafeFetchError(f"Scheme {parsed.scheme!r} is not allowed")

    # Embedded credentials (http://user:pass@host/) are an SSRF-obfuscation vector.
    if parsed.username or parsed.password:
        raise SafeFetchError("URL userinfo (user:pass@) is not allowed")

    host = parsed.hostname
    if not host:
        raise SafeFetchError("URL has no hostname")

    ips = resolve_and_check(host)  # single resolution; raises on any private IP
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return PinnedConnection(scheme=parsed.scheme, host=host, port=port, ips=ips)


def _host_header(conn: PinnedConnection) -> str:
    default_port = 443 if conn.scheme == "https" else 80
    return conn.host if conn.port == default_port else f"{conn.host}:{conn.port}"


def _ip_url(url: str, conn: PinnedConnection, ip: str) -> str:
    """Rebuild *url* with its authority replaced by the pinned IP:port, preserving
    path/params/query/fragment and dropping any userinfo."""
    parsed = urlparse(url)
    hostpart = f"[{ip}]" if ":" in ip else ip
    return parsed._replace(netloc=f"{hostpart}:{conn.port}").geturl()


async def pinned_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    headers: Optional[dict] = None,
    conn: Optional[PinnedConnection] = None,
) -> httpx.Response:
    """Perform ONE request pinned to a validated IP (no redirect handling).

    Connects to a resolved+validated IP (never re-resolving the hostname), while
    preserving the original hostname for TLS SNI/cert verification and the Host
    header. Tries each validated IP in turn on a connection-level failure. The
    caller is responsible for redirect handling (and must re-call per hop so every
    hop is validated). Pass *conn* to reuse a resolution already done by the caller
    (so the same IP backs both a TLS probe and this fetch).
    """
    if conn is None:
        conn = resolve_pinned(url)

    req_headers = {k: v for k, v in (headers or {}).items() if k.lower() != "host"}
    req_headers["Host"] = _host_header(conn)

    last_exc: Optional[Exception] = None
    for ip in conn.ips:
        ip_url = _ip_url(url, conn, ip)
        try:
            return await client.request(
                method,
                ip_url,
                headers=req_headers,
                extensions={"sni_hostname": conn.host},
            )
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            last_exc = exc
            continue
    raise SafeFetchError(
        f"Could not connect to any validated address for {conn.host}: {last_exc}"
    )


async def safe_fetch(
    url: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    timeout: float = 15.0,
    max_redirects: int = 3,
    allow_redirects: bool = True,
) -> dict:
    """Fetch *url* safely, resolving+validating+IP-pinning every hop.

    Returns a dict with keys: status, headers, body, url_final. `url_final` is the
    hostname-based URL of the final hop (NOT the internal IP-pinned URL), so callers
    that display or parse it (e.g. RDAP RIR attribution) see the real host.
    Raises SafeFetchError on any policy violation or if max_redirects is exceeded.
    """
    current_url = url

    async with httpx.AsyncClient(
        follow_redirects=False,
        verify=True,
        timeout=timeout,
    ) as client:
        for hop in range(max_redirects + 1):
            # resolve_pinned raises SafeFetchError (fail closed) on any violation.
            conn = resolve_pinned(current_url)
            response = await pinned_request(
                client, method, current_url, headers=headers, conn=conn
            )

            if allow_redirects and response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location", "").strip()
                if not location:
                    raise SafeFetchError("Redirect response missing Location header")

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
                "url_final": current_url,
            }

    raise SafeFetchError(f"Exceeded maximum redirects ({max_redirects})")
