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

log = logging.getLogger("falconeye.scope")

# suffix_list_urls=() pins this to the Public Suffix List snapshot bundled with
# the installed tldextract. Without it the first call would try to fetch the
# live list over the network, which would mean an unannounced outbound request
# in the middle of a scan and a hard dependency on that fetch succeeding.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


class OutOfScope(Exception):
    """Raised when a case-path request would leave the submitted domain."""


def registrable(host: str) -> str:
    """The registrable domain for *host*, PSL-backed.

    Do not replace this with a split on the last two labels. `.qpon` is a real
    gTLD and `station.qpon` is already registrable, while `foo.bar.com.ph` is
    registrable at `bar.com.ph`. A naive split gets one of those wrong whichever
    way it is written.

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
        parts = _EXTRACT(host)
    except Exception:
        log.warning("PSL extract failed for %r, falling back to the host", host)
        return host
    if parts.ipv4 or parts.ipv6:
        return host
    top = parts.top_domain_under_public_suffix
    return top or host


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
        what, case_id or "-", host or "-", case_registrable or "-",
    )
    raise OutOfScope(
        f"{what} to {host or 'an empty host'} refused: outside the case domain "
        f"{case_registrable or 'unset'}"
    )
