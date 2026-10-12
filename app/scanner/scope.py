"""
Case scope: which hosts a kit investigation is allowed to touch.

This is NOT the SSRF guard. app.utils.safe_fetch stops the scanner reaching
internal and reserved address space, and it stays exactly as it is. This module
stops the scanner reaching third parties who are not the subject of the case,
which is a different failure and needs a different answer.

Why it exists
-------------
A cloaking kit answers a scanner with a redirect to the brand it impersonates.
If the case host is taken from the fetched response rather than from the URL the
operator submitted, every later stage runs against the impersonated brand: the
socket probe hits their production infrastructure looking for an operator
console, the registry and CT lookups profile their domain, and the copyable
indicator block fills up with their registrar and nameservers. That is
out-of-scope probing of an uninvolved third party and it is a conduct problem
before it is a correctness problem.

So the case registrable domain is fixed once, from the submitted URL, and every
outbound request on the case path is checked against it.

Attacker-controlled values (a Location header, a canonical link, an og:url, a
base href, an asset host) may become indicators. They are never lookup targets.
"""

import logging
from typing import Optional

import tldextract
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.scope")

# suffix_list_urls=() pins this to the Public Suffix List snapshot bundled with
# the installed tldextract. Without it the first call would try to fetch the
# live list over the network, which would mean an unannounced outbound request
# in the middle of a scan and a hard dependency on that fetch succeeding.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
# A second extractor that honours the PSL PRIVATE section, so a host under a
# platform suffix (pages.dev, workers.dev, blogspot.com, vercel.app, github.io,
# ...) is its own registrable name rather than collapsing to the platform apex.
# Used by the Phishing Hunt so brand-in-subdomain phishing on these platforms is
# a candidate; the default public-only extractor is unchanged for every other
# caller (ASM, kit analysis), which must keep treating the platform apex as the
# case domain.
_EXTRACT_PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


class OutOfScope(Exception):
    """Raised when a case-path request would leave the submitted domain."""


def registrable(host: str, private: bool = False) -> str:
    """The registrable domain for *host*, PSL-backed.

    Do not replace this with a split on the last two labels. `.qpon` is a real
    gTLD and `station.qpon` is already registrable, while `foo.bar.com.ph` is
    registrable at `bar.com.ph`. A naive split gets one of those wrong whichever
    way it is written.

    With private=True the PSL private section is honoured, so a host under a
    platform suffix resolves to the full platform subdomain (foo.pages.dev), not
    the apex. The default (public only) is unchanged for every existing caller.

    Fails closed. An IP literal, a bare public suffix such as `gov.ph`, and an
    unparseable value all return the input unchanged rather than an empty
    string, because an empty case domain would make `in_scope` compare against
    nothing.
    """
    if not host:
        return ""
    host = host.strip().strip(".").lower()
    if not host:
        return ""
    try:
        parts = (_EXTRACT_PRIVATE if private else _EXTRACT)(host)
    except Exception:
        log.warning("PSL extract failed for %s, falling back to the host", tag(host))
        return host
    if parts.ipv4 or parts.ipv6:
        return host
    top = parts.top_domain_under_public_suffix
    return top or host


def is_platform_suffix(host: str) -> bool:
    """True when *host* is exactly a PSL PRIVATE (platform) suffix such as pages.dev
    or blogspot.com, i.e. the platform apex itself with no subdomain. Such a host
    is the platform, never a brand lookalike. A public suffix (gov.ph) is not a
    platform."""
    if not host:
        return False
    host = host.strip().strip(".").lower()
    try:
        priv = _EXTRACT_PRIVATE(host)
        pub = _EXTRACT(host)
    except Exception:
        return False
    # The whole host is a private suffix, but NOT a public suffix: that is a
    # platform apex (pages.dev is private; gov.ph is public).
    return bool(priv.suffix == host and pub.suffix != host)


def in_scope(host: str, case_registrable: str) -> bool:
    """True when *host* is the case domain itself or a subdomain of it.

    Fails closed: an empty host or an empty case domain is out of scope, so a
    caller that forgets to thread the case domain through blocks its own
    requests rather than silently allowing every host.
    """
    if not host or not case_registrable:
        return False
    host = host.strip().strip(".").lower()
    case_registrable = case_registrable.strip().strip(".").lower()
    if not host or not case_registrable:
        return False
    return host == case_registrable or host.endswith("." + case_registrable)


def require_in_scope(host: str, case_registrable: str,
                     what: str = "request", case_id: Optional[str] = None) -> None:
    """Raise OutOfScope unless *host* belongs to the case domain.

    Every refusal is logged at WARNING with the case id, the refused host and
    the case domain, so an out-of-scope attempt is visible in the log even when
    a caller swallows the exception.
    """
    if in_scope(host, case_registrable):
        return
    log.warning(
        "out-of-scope %s refused: case=%s host=%s case_domain=%s",
        what, case_id or "-", tag(host), tag(case_registrable),
    )
    raise OutOfScope(
        f"{what} to {host or 'an empty host'} refused: outside the case domain "
        f"{case_registrable or 'unset'}"
    )
