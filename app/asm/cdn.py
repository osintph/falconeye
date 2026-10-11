"""Published CDN and edge ranges, excluded from the ASM port scan.

A host that resolves into a CDN's shared edge is not the target's own service:
the open ports there belong to the provider and are the same for every tenant,
so scanning them probes someone else's infrastructure and tells us nothing about
the target. The brief's rule is explicit, and it applies in operator mode too:
do not port scan an IP inside a published CDN range; mark the host "behind CDN,
ports not scanned" instead.

Two signals, either is enough:
  - the resolved IP falls inside a vendored provider range, or
  - the host's CNAME ends in a provider suffix (this is how Akamai is covered,
    since Akamai publishes no single consolidated IP list).

Ranges are vendored in data/cdn_ranges.json and refreshed at release, kept out of
app/ip_sources/infrastructure.py on purpose: that module is a deliberately small,
auditable allowlist that caps a reputation verdict, and its docstring argues the
volatile CloudFront/Akamai ranges do not belong there. This file is the opposite
case, a refresh-at-release exclusion list, so it carries its own copy.

No em dashes in this module.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import pathlib
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("falconeye.asm.cdn")

_DATA = pathlib.Path(__file__).resolve().parent / "data" / "cdn_ranges.json"


@dataclass(frozen=True)
class CdnMatch:
    provider: str
    reason: str  # "ip" or "cname"


def _load():
    networks: list = []            # (ip_network, provider)
    cname_suffixes: list = []      # (suffix, provider)
    try:
        raw = json.loads(_DATA.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - a missing list must not break a scan
        log.warning("asm.cdn: could not load %s: %s", _DATA.name, exc)
        return networks, cname_suffixes
    for provider, spec in (raw.get("providers") or {}).items():
        for cidr in list(spec.get("v4", [])) + list(spec.get("v6", [])):
            try:
                networks.append((ipaddress.ip_network(cidr, strict=False), provider))
            except ValueError:
                continue
        for suffix in spec.get("cname_suffixes", []):
            cname_suffixes.append((suffix.lower().lstrip("."), provider))
    return networks, cname_suffixes


_NETWORKS, _CNAME_SUFFIXES = _load()


def cdn_for_ip(ip: str) -> Optional[str]:
    """The provider whose published range contains *ip*, or None."""
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    for network, provider in _NETWORKS:
        if addr.version == network.version and addr in network:
            return provider
    return None


def cdn_for_cname(cname: str) -> Optional[str]:
    """The provider a *cname* points at by suffix, or None."""
    if not cname:
        return None
    host = cname.strip().rstrip(".").lower()
    for suffix, provider in _CNAME_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return provider
    return None


def classify_host(resolved_ips, cname: str = "") -> Optional[CdnMatch]:
    """Return a CdnMatch when the host is CDN-fronted and must not be port scanned.

    IP match is checked first (it is the brief's literal rule), then the CNAME
    suffix, which also catches Akamai and any host pointed at a provider by name
    even when the IP list is incomplete.
    """
    for ip in resolved_ips or []:
        provider = cdn_for_ip(ip)
        if provider:
            return CdnMatch(provider=provider, reason="ip")
    provider = cdn_for_cname(cname)
    if provider:
        return CdnMatch(provider=provider, reason="cname")
    return None
