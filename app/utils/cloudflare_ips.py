"""
Cloudflare edge IP ranges, used to decide whether ``CF-Connecting-IP`` can be trusted.

Why this exists: every per-IP rate limit keys on :func:`app.utils.client_ip.get_client_ip`.
If that function trusted ``CF-Connecting-IP`` unconditionally, an attacker who can reach
the origin directly (i.e. around Cloudflare) would get a fresh rate-limit counter per
header value simply by rotating it, defeating every limit on the paid LLM endpoints.
The nginx allowlist in ``nginx/falconeye.conf`` is the first line of defence; this list
is the second, inside the application, so the limits hold even if that allowlist is
removed or the origin is exposed on another port.

The TCP peer the app sees IS a Cloudflare edge address in production: nginx proxies to
127.0.0.1:8000 and uvicorn's ProxyHeadersMiddleware (enabled by default, trusting the
loopback proxy) rewrites ``scope["client"]`` to the right-most untrusted X-Forwarded-For
entry, which nginx sets from ``$remote_addr``. Gunicorn's access log confirms it:
requests arrive as ``172.70.x.x:0``, not ``127.0.0.1``.

Ranges are the published lists from https://www.cloudflare.com/ips/ (v4 and v6) and are
kept byte-identical to the ``allow`` directives in nginx/falconeye.conf. Cloudflare
changes these rarely; when it does, update BOTH files together.

``TRUSTED_PROXY_CIDRS`` (comma-separated, unset by default) adds extra networks whose
``CF-Connecting-IP`` header is trusted. It exists for deployments where the app sees the
reverse proxy's own address instead of the edge address (e.g. proxy headers disabled).
Leave it unset unless that is actually the case — every CIDR added to it is a network
that can set the rate-limit key to anything it likes.
"""
import ipaddress
import logging

from app.utils.env import getenv_clean

log = logging.getLogger(__name__)

# https://www.cloudflare.com/ips-v4
CLOUDFLARE_IPV4 = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)

# https://www.cloudflare.com/ips-v6
CLOUDFLARE_IPV6 = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)


def _parse_networks(cidrs) -> list:
    nets = []
    for cidr in cidrs:
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            log.warning("Ignoring unparseable trusted-proxy CIDR: %r", cidr)
    return nets


_CLOUDFLARE_NETWORKS = _parse_networks(CLOUDFLARE_IPV4 + CLOUDFLARE_IPV6)

# Operator-supplied extras. Read once at import: this is systemd EnvironmentFile
# config, which cannot change without a restart.
_EXTRA_TRUSTED_NETWORKS = _parse_networks(
    getenv_clean("TRUSTED_PROXY_CIDRS").split(",")
)

TRUSTED_PROXY_NETWORKS = tuple(_CLOUDFLARE_NETWORKS + _EXTRA_TRUSTED_NETWORKS)


def _in_networks(addr: str, networks) -> bool:
    try:
        ip = ipaddress.ip_address(addr.strip())
    except (ValueError, AttributeError):
        return False
    # An IPv4-mapped IPv6 peer (::ffff:104.16.1.1) is the same host as its IPv4 form.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip in net for net in networks if ip.version == net.version)


def is_cloudflare_ip(addr: str) -> bool:
    """Return True if *addr* is inside a published Cloudflare edge range."""
    return _in_networks(addr, _CLOUDFLARE_NETWORKS)


def is_trusted_proxy(addr: str) -> bool:
    """Return True if *addr* may set ``CF-Connecting-IP`` on our behalf.

    That means a Cloudflare edge address, or one of the operator-configured
    ``TRUSTED_PROXY_CIDRS`` networks.
    """
    return _in_networks(addr, TRUSTED_PROXY_NETWORKS)
