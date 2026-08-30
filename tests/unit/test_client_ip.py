"""Unit tests for app.utils.client_ip.

The property under test is not "CF-Connecting-IP is read" but "the rate-limit key
cannot be chosen by the caller". Every per-IP limit in this app keys on
get_client_ip, so a caller who can pick its own value gets an unlimited number of
fresh counters — and the LLM endpoints behind those counters cost real money.

Written against the bug CLASS: a header is only honoured when the peer that
delivered it is a trusted proxy, so a future header added on the same pattern
fails these too.
"""
from typing import Optional
from unittest.mock import MagicMock

import pytest

from app.utils.client_ip import get_client_ip
from app.utils.cloudflare_ips import is_cloudflare_ip, is_trusted_proxy

# A real Cloudflare edge address (172.64.0.0/13) — gunicorn's access log shows
# exactly this shape arriving in production.
CF_EDGE = "172.70.186.138"


def _make_request(headers: dict, client_host: Optional[str] = "10.0.0.1") -> MagicMock:
    req = MagicMock()
    req.headers = headers
    if client_host is not None:
        req.client = MagicMock()
        req.client.host = client_host
    else:
        req.client = None
    return req


# ---------------------------------------------------------------------------
# Cloudflare-fronted traffic still resolves to the real end user
# ---------------------------------------------------------------------------

def test_returns_cf_connecting_ip_when_peer_is_cloudflare():
    req = _make_request({"CF-Connecting-IP": "203.0.113.42"}, client_host=CF_EDGE)
    assert get_client_ip(req) == "203.0.113.42"


def test_returns_cf_connecting_ip_for_every_published_range():
    """One representative address per published Cloudflare network."""
    for peer in ("173.245.48.1", "103.21.244.1", "141.101.64.1", "108.162.192.1",
                 "190.93.240.1", "188.114.96.1", "198.41.128.1", "162.158.0.1",
                 "104.16.0.1", "172.64.0.1", "131.0.72.1"):
        req = _make_request({"CF-Connecting-IP": "203.0.113.42"}, client_host=peer)
        assert get_client_ip(req) == "203.0.113.42", peer


def test_ipv6_cloudflare_peer_is_trusted():
    req = _make_request({"CF-Connecting-IP": "2001:db8::1"}, client_host="2606:4700::1")
    assert get_client_ip(req) == "2001:db8::1"


# ---------------------------------------------------------------------------
# The spoof: a caller reaching the origin directly cannot pick its own key
# ---------------------------------------------------------------------------

def test_ignores_cf_header_from_untrusted_peer():
    """The finding: origin reachable directly, attacker sets the header."""
    req = _make_request({"CF-Connecting-IP": "203.0.113.42"}, client_host="198.51.100.7")
    assert get_client_ip(req) == "198.51.100.7"


def test_rotating_the_header_from_one_peer_yields_one_key():
    """The bypass is rotation, so assert the whole rotation collapses to one key."""
    keys = {
        get_client_ip(_make_request({"CF-Connecting-IP": f"203.0.113.{n}"},
                                    client_host="198.51.100.7"))
        for n in range(1, 50)
    }
    assert keys == {"198.51.100.7"}


def test_private_and_loopback_peers_are_not_trusted_by_default():
    """A misconfigured hop must not become a free pass for the header."""
    for peer in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1"):
        req = _make_request({"CF-Connecting-IP": "203.0.113.42"}, client_host=peer)
        assert get_client_ip(req) == peer, peer


# ---------------------------------------------------------------------------
# Malformed values never become a rate-limit key
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bogus", [
    "not-an-ip",
    "203.0.113.42, 198.51.100.1",   # a list, not an address
    "203.0.113.999",
    "'; DROP TABLE llm_rate_limit; --",
    " ",
    "0x7f000001",
])
def test_malformed_header_falls_back_to_peer(bogus):
    req = _make_request({"CF-Connecting-IP": bogus}, client_host=CF_EDGE)
    assert get_client_ip(req) == CF_EDGE


def test_malformed_peer_host_becomes_unknown():
    req = _make_request({}, client_host="not-an-ip")
    assert get_client_ip(req) == "unknown"


# ---------------------------------------------------------------------------
# Fallbacks
# ---------------------------------------------------------------------------

def test_falls_back_to_request_client_host_when_header_missing():
    req = _make_request({}, client_host="198.51.100.7")
    assert get_client_ip(req) == "198.51.100.7"


def test_cloudflare_peer_without_the_header_uses_the_peer():
    req = _make_request({}, client_host=CF_EDGE)
    assert get_client_ip(req) == CF_EDGE


def test_no_client_at_all_is_unknown():
    req = _make_request({"CF-Connecting-IP": "203.0.113.42"}, client_host=None)
    assert get_client_ip(req) == "unknown"


def test_ignores_x_forwarded_for():
    # XFF must NOT be used — only CF-Connecting-IP from a trusted peer, or client.host
    req = _make_request(
        {"X-Forwarded-For": "1.2.3.4, 5.6.7.8"},
        client_host="198.51.100.7",
    )
    assert get_client_ip(req) == "198.51.100.7"


def test_xff_is_ignored_even_from_a_cloudflare_peer():
    req = _make_request({"X-Forwarded-For": "1.2.3.4"}, client_host=CF_EDGE)
    assert get_client_ip(req) == CF_EDGE


# ---------------------------------------------------------------------------
# The range list itself
# ---------------------------------------------------------------------------

def test_cloudflare_range_membership():
    assert is_cloudflare_ip("104.16.0.1")
    assert is_cloudflare_ip("2606:4700::1111")
    assert not is_cloudflare_ip("8.8.8.8")
    assert not is_cloudflare_ip("127.0.0.1")
    assert not is_cloudflare_ip("garbage")


def test_ipv4_mapped_cloudflare_peer_is_recognised():
    """A dual-stack listener can report ::ffff:104.16.0.1 for an IPv4 peer."""
    assert is_trusted_proxy("::ffff:104.16.0.1")
    assert not is_trusted_proxy("::ffff:8.8.8.8")


def test_app_list_matches_the_nginx_allowlist():
    """Both files gate on the same ranges; drift makes one of them a lie."""
    import pathlib
    import re

    from app.utils.cloudflare_ips import CLOUDFLARE_IPV4

    conf = pathlib.Path(__file__).resolve().parents[2] / "nginx" / "falconeye.conf"
    nginx_allowed = set(re.findall(r"allow\s+([0-9./]+);", conf.read_text()))
    assert nginx_allowed == set(CLOUDFLARE_IPV4)


def test_untrusted_header_is_logged_once_not_per_request(caplog):
    """The warning is a config signal, so it must not be an attacker's log flood."""
    import app.utils.client_ip as client_ip

    client_ip._warned_untrusted_header = False
    with caplog.at_level("WARNING", logger="app.utils.client_ip"):
        for _ in range(20):
            get_client_ip(_make_request({"CF-Connecting-IP": "203.0.113.42"},
                                        client_host="198.51.100.7"))
    assert len(caplog.records) == 1
    assert "TRUSTED_PROXY_CIDRS" in caplog.records[0].getMessage()


def test_no_warning_for_normal_cloudflare_traffic(caplog):
    import app.utils.client_ip as client_ip

    client_ip._warned_untrusted_header = False
    with caplog.at_level("WARNING", logger="app.utils.client_ip"):
        get_client_ip(_make_request({"CF-Connecting-IP": "203.0.113.42"},
                                    client_host=CF_EDGE))
    assert caplog.records == []


def test_service_unit_pins_forwarded_allow_ips():
    """The trust chain starts outside Python, in the gunicorn invocation.

    uvicorn only rewrites the client peer from X-Forwarded-For for peers in
    --forwarded-allow-ips, and setting it to "*" makes it take the LEFT-most
    (caller-supplied) entry instead of the right-most. That would hand an
    attacker the peer address, which is what every check above keys on. gunicorn
    also reads FORWARDED_ALLOW_IPS from the environment and the unit loads .env
    into that environment, so the flag must stay explicit to win over it.
    """
    import pathlib
    import re

    unit = (pathlib.Path(__file__).resolve().parents[2] / "falconeye.service").read_text()
    exec_start = unit.split("ExecStart=", 1)[1]
    match = re.search(r"--forwarded-allow-ips\s+(\S+)", exec_start)
    assert match, "falconeye.service must pin --forwarded-allow-ips explicitly"
    assert match.group(1) != "*", "--forwarded-allow-ips '*' makes the peer attacker-chosen"
    assert match.group(1) == "127.0.0.1", "the only trusted hop is the local nginx"
