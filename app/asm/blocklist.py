"""Who cannot be assessed here, checked before any verification path.

Three layers, evaluated for a normal user before a domain can even enter the
verification gate. They all produce ONE identical response so the page never
reveals which rule matched, nor whether a domain is verified, monitored or
blocked:

    A  free and consumer mailbox providers (gmail.com, yahoo.com.ph, proton.me,
       ...), from the vendored willwhite/freemail list plus a local override
       file plus ASM_BLOCKED_DOMAINS. Matched by exact apex, never by MX, so a
       company domain on Google Workspace or Microsoft 365 is fine.
    B  shared-platform apexes from the Public Suffix List PRIVATE section
       (github.io, vercel.app, herokuapp.com, ...). The apex and its siblings
       are never scannable. A user may still verify their own label UNDER one
       (acme.github.io) where the platform allows a TXT record; that label is
       not blocked here.
    C  public suffixes themselves, from the PSL ICANN section (com, com.ph,
       gov.ph). Never scannable, operator mode included.

Operator mode can override layers A and B after a second confirmation, but never
layer C. The returned reason carries that distinction.

The PSL is vendored (data/public_suffix_list.dat, MPL-2.0) and parsed here rather
than read from tldextract's bundled snapshot, so the private section is current
and refreshed deliberately at release.

No em dashes in this module.
"""
from __future__ import annotations

import logging
import pathlib
from dataclasses import dataclass
from typing import Optional

from app import config
from app.utils.env import getenv_clean

log = logging.getLogger("falconeye.asm.blocklist")

_DATA = pathlib.Path(__file__).resolve().parent / "data"
_PSL = _DATA / "public_suffix_list.dat"
_FREEMAIL = _DATA / "free_email_domains.txt"
_FREEMAIL_OVERRIDE = _DATA / "free_email_overrides.txt"

# The single response shown for every block reason. Keep it identical everywhere.
BLOCK_MESSAGE = "This domain cannot be assessed here."


@dataclass(frozen=True)
class BlockReason:
    # "freemail" | "platform" | "public_suffix". Internal only; never sent to a
    # normal user (they always see BLOCK_MESSAGE).
    layer: str
    # Whether operator mode may override this block (A and B yes, C never).
    operator_override: bool


def _parse_psl():
    """(icann_rules, private_rules) as two sets of rule strings.

    A rule keeps its PSL prefix: "!" for an exception and "*." for a wildcard, so
    the matcher can tell them apart. Private rules are only those between the
    BEGIN/END PRIVATE DOMAINS markers.
    """
    icann: set = set()
    private: set = set()
    section = "icann"
    try:
        lines = _PSL.read_text(encoding="utf-8").splitlines()
    except Exception as exc:  # noqa: BLE001
        log.warning("asm.blocklist: could not read PSL: %s", exc)
        return icann, private
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if s.startswith("//"):
            if "BEGIN PRIVATE DOMAINS" in s:
                section = "private"
            elif "END PRIVATE DOMAINS" in s:
                section = "icann"
            continue
        # Rules are stored in their unicode form here; our inputs are ASCII
        # hostnames, which is what normalize_domain already guarantees.
        rule = s.lower()
        (private if section == "private" else icann).add(rule)
    return icann, private


_ICANN_RULES, _PRIVATE_RULES = _parse_psl()


def _public_suffix(domain: str, rules: set) -> str:
    """The public suffix of *domain* under *rules*, per the PSL algorithm.

    Longest matching rule wins; an exception rule removes its own leftmost label;
    a wildcard matches one label; when nothing matches the suffix is the rightmost
    label (the implicit "*" rule).
    """
    labels = domain.split(".")
    n = len(labels)
    for i in range(n):
        candidate = labels[i:]
        cstr = ".".join(candidate)
        if ("!" + cstr) in rules:
            # Exception: this level is NOT a suffix; the suffix is one label in.
            return ".".join(candidate[1:])
        if cstr in rules:
            return cstr
        if len(candidate) > 1 and ("*." + ".".join(candidate[1:])) in rules:
            return cstr
    return labels[-1]


def _is_icann_public_suffix(domain: str) -> bool:
    return _public_suffix(domain, _ICANN_RULES) == domain


def _is_private_apex(domain: str) -> bool:
    """True when *domain* is itself a PSL private suffix (a shared-platform apex).

    A label under one (acme.github.io) returns False: its private suffix is
    github.io, not itself, so it is allowed to verify.
    """
    merged = _ICANN_RULES | _PRIVATE_RULES
    ps_with_private = _public_suffix(domain, merged)
    if ps_with_private != domain:
        return False
    # It is a suffix; a private apex only if the private section is what made it
    # one (otherwise it is an ICANN public suffix, which is layer C).
    return _public_suffix(domain, _ICANN_RULES) != domain


def _load_freemail() -> set:
    domains: set = set()
    for path in (_FREEMAIL, _FREEMAIL_OVERRIDE):
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                s = line.strip().lower()
                if s and not s.startswith("#"):
                    domains.add(s)
        except Exception as exc:  # noqa: BLE001
            log.warning("asm.blocklist: could not read %s: %s", path.name, exc)
    return domains


_VENDORED_FREEMAIL = _load_freemail()


def _freemail_set() -> set:
    """The free-mail set: vendored plus override file plus env, read live for the
    env and operator file so a running instance can be extended without a redeploy.
    """
    domains = set(_VENDORED_FREEMAIL)
    op_path = getenv_clean("ASM_FREEMAIL_OVERRIDE_PATH")
    if op_path:
        try:
            for line in pathlib.Path(op_path).read_text(encoding="utf-8").splitlines():
                s = line.strip().lower()
                if s and not s.startswith("#"):
                    domains.add(s)
        except FileNotFoundError:
            pass
        except Exception as exc:  # noqa: BLE001
            log.warning("asm.blocklist: operator freemail file unreadable: %s", exc)
    for extra in (config.ASM_BLOCKED_DOMAINS or "").split(","):
        extra = extra.strip().lower()
        if extra:
            domains.add(extra)
    return domains


def classify(domain: str) -> Optional[BlockReason]:
    """Why *domain* is blocked for a normal user, or None when it is assessable.

    *domain* must already be normalized (lowercase apex, no scheme/port/path).
    Order matters: a public suffix is checked first (com is not free mail), then
    free mail (gmail.com is free mail, not a platform apex), then platform apex.
    """
    if not domain:
        return BlockReason(layer="public_suffix", operator_override=False)
    domain = domain.strip().strip(".").lower()
    if not domain or "." not in domain:
        return BlockReason(layer="public_suffix", operator_override=False)

    if _is_icann_public_suffix(domain):
        return BlockReason(layer="public_suffix", operator_override=False)
    if domain in _freemail_set():
        return BlockReason(layer="freemail", operator_override=True)
    if _is_private_apex(domain):
        return BlockReason(layer="platform", operator_override=True)
    return None


def is_blocked(domain: str) -> bool:
    return classify(domain) is not None
