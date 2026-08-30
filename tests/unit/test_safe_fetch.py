"""
Unit tests for app/utils/safe_fetch.py — H-1 SSRF guard.

Covers:
  - Scheme validation
  - Private/loopback/link-local/CGNAT/NAT64 IPv4 and IPv6 blocking
  - IPv4-mapped IPv6 unwrapping (::ffff: bypass)
  - Public IP pass-through
  - Redirect-to-private-IP rejection (per-hop revalidation)
  - Redirect cap enforcement

Uses asyncio.run() — no pytest-asyncio dependency required.
"""

import asyncio
import ipaddress
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.utils.safe_fetch import (
    DEFAULT_MAX_BYTES,
    SafeFetchError,
    is_private_ip,
    resolve_and_check,
    safe_fetch,
)


# ---------------------------------------------------------------------------
# is_private_ip
# ---------------------------------------------------------------------------

def test_blocks_private_ipv4():
    assert is_private_ip("10.0.0.1")
    assert is_private_ip("172.16.0.1")
    assert is_private_ip("192.168.1.1")


def test_blocks_loopback():
    assert is_private_ip("127.0.0.1")
    assert is_private_ip("127.255.255.255")


def test_blocks_link_local_metadata():
    # AWS/GCP metadata endpoint
    assert is_private_ip("169.254.169.254")
    assert is_private_ip("169.254.0.1")


def test_blocks_cgnat():
    assert is_private_ip("100.64.0.1")
    assert is_private_ip("100.127.255.255")


def test_blocks_ipv4_mapped_ipv6_loopback():
    # ::ffff:127.0.0.1 must be treated as loopback after unwrapping
    assert is_private_ip("::ffff:127.0.0.1")


def test_blocks_ipv4_mapped_ipv6_metadata():
    # ::ffff:169.254.169.254 must be treated as link-local after unwrapping
    assert is_private_ip("::ffff:169.254.169.254")


def test_blocks_ipv6_loopback():
    assert is_private_ip("::1")


def test_blocks_nat64():
    # 64:ff9b::/96 — NAT64 well-known prefix
    assert is_private_ip("64:ff9b::1")
    assert is_private_ip("64:ff9b::7f00:1")  # maps to 127.0.0.1


def test_allows_public_ip():
    assert not is_private_ip("1.1.1.1")
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("2606:4700:4700::1111")  # Cloudflare public DNS


# ---------------------------------------------------------------------------
# resolve_and_check — uses socket mock
# ---------------------------------------------------------------------------

def _getaddrinfo_returning(addr: str):
    """Return a socket.getaddrinfo-style list for a single address."""
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    return [(family, socket.SOCK_STREAM, 0, "", (addr, 0))]


def test_resolve_raises_on_private_resolution():
    with patch("app.utils.safe_fetch.socket.getaddrinfo", return_value=_getaddrinfo_returning("127.0.0.1")):
        with pytest.raises(SafeFetchError, match="private or reserved"):
            resolve_and_check("evil.example.com")


def test_resolve_returns_public_ips():
    with patch("app.utils.safe_fetch.socket.getaddrinfo", return_value=_getaddrinfo_returning("1.2.3.4")):
        addrs = resolve_and_check("ok.example.com")
    assert addrs == ["1.2.3.4"]


def test_resolve_raises_on_dns_failure():
    with patch("app.utils.safe_fetch.socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
        with pytest.raises(SafeFetchError, match="resolve"):
            resolve_and_check("nonexistent.example.com")


# ---------------------------------------------------------------------------
# safe_fetch — scheme check (no network)
# ---------------------------------------------------------------------------

def test_blocks_non_https_and_non_http():
    with pytest.raises(SafeFetchError, match="not allowed"):
        asyncio.run(safe_fetch("ftp://example.com/file"))


def test_blocks_file_scheme():
    with pytest.raises(SafeFetchError, match="not allowed"):
        asyncio.run(safe_fetch("file:///etc/passwd"))


# ---------------------------------------------------------------------------
# safe_fetch — private IP blocks (resolve_and_check raises before any HTTP)
# ---------------------------------------------------------------------------

def test_blocks_private_ipv4_url():
    with patch("app.utils.safe_fetch.socket.getaddrinfo", return_value=_getaddrinfo_returning("192.168.0.1")):
        with pytest.raises(SafeFetchError):
            asyncio.run(safe_fetch("http://192.168.0.1/"))


def test_blocks_loopback_url():
    with patch("app.utils.safe_fetch.socket.getaddrinfo", return_value=_getaddrinfo_returning("127.0.0.1")):
        with pytest.raises(SafeFetchError):
            asyncio.run(safe_fetch("http://127.0.0.1/"))


# ---------------------------------------------------------------------------
# safe_fetch — redirect to private IP is rejected (per-hop revalidation)
# ---------------------------------------------------------------------------

def test_redirect_to_private_ip_raises():
    public_addr = _getaddrinfo_returning("1.2.3.4")
    private_addr = _getaddrinfo_returning("127.0.0.1")

    call_count = 0

    def side_effect(host, port):
        nonlocal call_count
        call_count += 1
        # First resolution (public.example.com) → public; second (127.0.0.1) → private
        if call_count == 1:
            return public_addr
        return private_addr

    redirect_response = httpx.Response(
        status_code=302,
        headers={"location": "http://127.0.0.1/secret"},
        request=httpx.Request("GET", "http://public.example.com/"),
    )

    async def run():
        with patch("app.utils.safe_fetch.socket.getaddrinfo", side_effect=side_effect):
            with patch("httpx.AsyncClient", side_effect=lambda **kw: _make_async_client(redirect_response)):
                await safe_fetch("http://public.example.com/", max_redirects=3)

    with pytest.raises(SafeFetchError, match="private or reserved"):
        asyncio.run(run())


# ---------------------------------------------------------------------------
# safe_fetch — max_redirects cap
# ---------------------------------------------------------------------------

def test_redirect_cap_exceeded():
    redirect_response = httpx.Response(
        status_code=302,
        headers={"location": "http://loop.example.com/"},
        request=httpx.Request("GET", "http://loop.example.com/"),
    )

    always_public = _getaddrinfo_returning("1.2.3.4")

    async def run():
        with patch("app.utils.safe_fetch.socket.getaddrinfo", return_value=always_public):
            with patch("httpx.AsyncClient", side_effect=lambda **kw: _make_async_client(redirect_response)):
                await safe_fetch("http://loop.example.com/", max_redirects=2)

    with pytest.raises(SafeFetchError, match="Exceeded maximum redirects"):
        asyncio.run(run())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Bound before any test patches httpx.AsyncClient — the helper below builds a real
# client while that patch is active, so it must not go through the patched name.
_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _client_from_handler(handler):
    """A real httpx.AsyncClient wired to a MockTransport running *handler*.

    Real clients rather than hand-rolled stubs on purpose: these tests assert on
    what safe_fetch puts on the wire (pinned IP, SNI, Host), not on which httpx
    method it happens to call to get there. A stub implementing only `.request`
    breaks the moment the transport changes — which is how the body-cap change
    (build_request + send(stream=True)) broke five of them.
    """
    return _REAL_ASYNC_CLIENT(
        transport=httpx.MockTransport(handler), follow_redirects=False
    )


def _make_async_client(response):
    """Client that answers every request with a copy of *response*."""

    def handler(request):
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            content=response.content,
        )

    return _client_from_handler(handler)


def _recording_client(response, sink):
    """Client that records each request (url/headers/extensions) before answering."""

    def handler(request):
        sink.append({
            "method": request.method,
            "url": str(request.url),
            "headers": dict(request.headers),
            "extensions": dict(request.extensions),
        })
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            content=response.content,
        )

    return _client_from_handler(handler)


# ---------------------------------------------------------------------------
# H-1 (v3.11.0): connection is pinned to the validated IP (DNS-rebinding fix)
# ---------------------------------------------------------------------------

def test_connection_pinned_to_validated_ip():
    """The HTTP connection targets the validated IP, while the hostname is
    preserved for TLS SNI (cert check) and the Host header (vhost routing)."""
    sink = []
    ok = httpx.Response(200, request=httpx.Request("GET", "https://example.com/"))

    async def run():
        with patch("app.utils.safe_fetch.socket.getaddrinfo",
                   return_value=_getaddrinfo_returning("93.184.216.34")):
            with patch("httpx.AsyncClient", side_effect=lambda **kw: _recording_client(ok, sink)):
                return await safe_fetch("https://example.com/path?q=1")

    res = asyncio.run(run())
    assert res["status"] == 200
    # url_final is the hostname URL, never the internal IP-pinned URL.
    assert res["url_final"] == "https://example.com/path?q=1"
    assert len(sink) == 1
    rec = sink[0]
    assert "93.184.216.34" in rec["url"]          # connected to the IP
    assert "example.com" not in rec["url"]         # not to the hostname
    assert rec["url"].endswith("/path?q=1")        # path/query preserved
    assert rec["extensions"].get("sni_hostname") == "example.com"  # TLS validates vs host
    assert rec["headers"].get("host") == "example.com"             # vhost routing


def test_dns_rebind_blocked_no_second_resolution():
    """The specific H-1 vulnerability: a host that resolves public first and
    internal second. We resolve ONCE and connect to the validated IP, so the
    rebind target is never reached and getaddrinfo is called exactly once."""
    sink = []
    ok = httpx.Response(200, request=httpx.Request("GET", "https://x/"))
    calls = {"n": 0}

    def side_effect(host, port):
        calls["n"] += 1
        # 1st lookup: public (passes the guard). Any later lookup: metadata IP.
        return _getaddrinfo_returning("93.184.216.34" if calls["n"] == 1 else "169.254.169.254")

    async def run():
        with patch("app.utils.safe_fetch.socket.getaddrinfo", side_effect=side_effect):
            with patch("httpx.AsyncClient", side_effect=lambda **kw: _recording_client(ok, sink)):
                return await safe_fetch("https://rebind.example.com/")

    res = asyncio.run(run())
    assert res["status"] == 200
    assert calls["n"] == 1                          # no connect-time re-resolution
    assert "93.184.216.34" in sink[0]["url"]        # pinned to the validated IP
    assert "169.254.169.254" not in sink[0]["url"]  # never the rebind target


def test_pins_to_first_reachable_validated_ip():
    """When a host has multiple validated IPs, a connect failure on the first
    falls through to the next — and every candidate is a validated public IP."""
    sink = []
    ok = httpx.Response(200, request=httpx.Request("GET", "http://x/"))

    def two_public_ips(host, port):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("5.6.7.8", 0)),
        ]

    def handler(request):
        sink.append(str(request.url))
        if "1.2.3.4" in str(request.url):
            raise httpx.ConnectError("connection refused")
        return httpx.Response(ok.status_code)

    async def run():
        with patch("app.utils.safe_fetch.socket.getaddrinfo", side_effect=two_public_ips):
            with patch("httpx.AsyncClient", side_effect=lambda **kw: _client_from_handler(handler)):
                return await safe_fetch("http://multi.example.com/")

    res = asyncio.run(run())
    assert res["status"] == 200
    assert any("1.2.3.4" in u for u in sink)   # first IP attempted
    assert any("5.6.7.8" in u for u in sink)   # failover to second


def test_userinfo_url_rejected():
    with pytest.raises(SafeFetchError, match="userinfo"):
        asyncio.run(safe_fetch("http://user:pass@example.com/"))


# ---------------------------------------------------------------------------
# Response body cap — the target does not get to choose how much memory it costs
# ---------------------------------------------------------------------------

def _fetch_with_body(body: bytes, headers=None, **kwargs):
    """Run safe_fetch against a mock target that returns *body*."""
    def handler(request):
        return httpx.Response(200, headers=headers or {}, content=body)

    async def run():
        with patch("app.utils.safe_fetch.socket.getaddrinfo",
                   return_value=_getaddrinfo_returning("1.2.3.4")):
            with patch("httpx.AsyncClient",
                       side_effect=lambda **kw: _client_from_handler(handler)):
                return await safe_fetch("http://big.example.com/", **kwargs)

    return asyncio.run(run())


def test_body_under_the_cap_is_returned_whole():
    res = _fetch_with_body(b"x" * 1000, max_bytes=5000)
    assert res["status"] == 200
    assert res["body"] == "x" * 1000


def test_body_over_the_cap_is_refused():
    with pytest.raises(SafeFetchError, match="byte cap"):
        _fetch_with_body(b"x" * 6000, max_bytes=5000)


def test_oversize_body_is_refused_not_truncated():
    """Truncating would hand the caller a partial body it cannot detect."""
    with pytest.raises(SafeFetchError):
        _fetch_with_body(b"x" * (DEFAULT_MAX_BYTES + 1))


def test_body_exactly_at_the_cap_is_allowed():
    res = _fetch_with_body(b"x" * 5000, max_bytes=5000)
    assert len(res["body"]) == 5000


def test_gzipped_body_is_decoded_once():
    """The rebuilt response must not carry content-encoding, or httpx re-inflates
    an already-inflated body and every compressed target raises DecodingError."""
    import gzip
    payload = gzip.compress(b"<html>compressed target</html>")
    res = _fetch_with_body(payload, headers={"content-encoding": "gzip",
                                             "content-type": "text/html"})
    assert res["body"] == "<html>compressed target</html>"


def test_response_headers_survive_the_cap():
    res = _fetch_with_body(b"ok", headers={"server": "nginx",
                                           "content-type": "text/plain"})
    assert res["headers"]["server"] == "nginx"
    assert res["headers"]["content-type"] == "text/plain"
