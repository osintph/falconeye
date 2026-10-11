"""Passive discovery: the in-scope hostnames of an apex, from free sources.

Sources (all free, keyless where possible, verified 2026-10-11):
  CT logs       crt.sh then Cert Spotter, reusing domain_intel.fetch_ct.
  passive DNS   Mnemonic (api.mnemonic.no, keyless, 10/min and 1000/day, TLP:WHITE).
  Wayback       the CDX server, historic hostnames seen under the domain.
  RIPEstat      ASN and announced prefixes of the apex's resolved IPs, as context
                (not a host source), reusing asn_intel.fetch. Shown with the
                required "Source: RIPEstat" attribution.

These are fixed-host data providers, not the target, so they use httpx directly,
the same rule domain_intel and asn_intel already follow. Discovery only returns
hostnames inside the apex; the CNAME target a host points at is never treated as a
host to discover or probe. No em dashes in this module.
"""
from __future__ import annotations

import asyncio
import logging
import re

import httpx

from app import config
from app.ip_sources import asn_intel
from app.routers import domain_intel
from app.scanner.scope import in_scope, registrable
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.asm.discovery")

_UA = f"FalconEye-ASM/3.37.0 (+{config.OPERATOR_SITE_ORIGIN})"
_MNEMONIC = "https://api.mnemonic.no/pdns/v3"
_WAYBACK = "https://web.archive.org/cdx/search/cdx"
_PDNS_TIMEOUT = 15.0
_WAYBACK_TIMEOUT = 20.0
# A single discovery run should not try to enumerate an unbounded archive.
_WAYBACK_LIMIT = 10000

# A real hostname to probe. Drops CT wildcard SANs (*.example.com) and any other
# value that is not a resolvable name.
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def _hostnames_from_urls(values) -> set:
    hosts = set()
    for v in values or []:
        s = str(v or "").strip().lower()
        if not s:
            continue
        if "://" in s:
            s = s.split("://", 1)[1]
        s = s.split("/", 1)[0].split(":", 1)[0]
        if s:
            hosts.add(s)
    return hosts


async def _mnemonic(client: httpx.AsyncClient, domain: str) -> set:
    try:
        r = await client.get(f"{_MNEMONIC}/{domain}",
                             params={"limit": 1000}, timeout=_PDNS_TIMEOUT,
                             headers={"User-Agent": _UA})
        if r.status_code != 200:
            return set()
        data = r.json()
    except Exception as exc:  # noqa: BLE001
        log.info("asm discovery mnemonic failed for %s: %s", tag(domain), type(exc).__name__)
        return set()
    rows = data.get("data") if isinstance(data, dict) else data
    hosts = set()
    for row in rows or []:
        for key in ("query", "answer"):
            val = str((row or {}).get(key, "")).strip().lower().rstrip(".")
            if val:
                hosts.add(val)
    return hosts


async def _wayback(client: httpx.AsyncClient, domain: str) -> set:
    try:
        r = await client.get(_WAYBACK, params={
            "url": domain, "matchType": "domain", "output": "json",
            "fl": "original", "collapse": "urlkey", "limit": _WAYBACK_LIMIT,
        }, timeout=_WAYBACK_TIMEOUT, headers={"User-Agent": _UA})
        if r.status_code != 200:
            return set()
        rows = r.json()
    except Exception as exc:  # noqa: BLE001
        log.info("asm discovery wayback failed for %s: %s", tag(domain), type(exc).__name__)
        return set()
    # First row is the header ["original"].
    urls = [row[0] for row in rows[1:] if row] if isinstance(rows, list) else []
    return _hostnames_from_urls(urls)


async def discover(domain: str) -> dict:
    """Return discovered in-scope hostnames plus source status and ASN context."""
    reg = registrable(domain) or domain
    sources = {}
    hosts: set = {domain, f"www.{domain}"}

    async with httpx.AsyncClient(follow_redirects=True) as client:
        ct_task = domain_intel.fetch_ct(client, domain)
        mnem_task = _mnemonic(client, domain)
        wb_task = _wayback(client, domain)
        ct, mnem, wb = await asyncio.gather(ct_task, mnem_task, wb_task,
                                            return_exceptions=True)

        if isinstance(ct, dict):
            for sub in ct.get("subdomains") or []:
                hosts.add(str(sub).strip().lower().rstrip("."))
            sources["ct"] = {"ok": not ct.get("error"), "source": ct.get("source"),
                             "count": len(ct.get("subdomains") or [])}
        else:
            sources["ct"] = {"ok": False, "source": None, "count": 0}

        mnem_set = mnem if isinstance(mnem, set) else set()
        wb_set = wb if isinstance(wb, set) else set()
        hosts |= mnem_set | wb_set
        sources["passive_dns"] = {"ok": bool(mnem_set) or isinstance(mnem, set), "count": len(mnem_set)}
        sources["wayback"] = {"ok": isinstance(wb, set), "count": len(wb_set)}

        # Keep only real, in-scope hostnames (subdomains of the apex). A CT
        # wildcard SAN (*.example.com) and any malformed value are dropped; the
        # CNAME target a host points at is excluded by construction here.
        in_scope_hosts = sorted(
            h for h in hosts if h and _HOST_RE.match(h) and in_scope(h, reg))

        # RIPEstat context for the apex's first resolved IP.
        asn = {"available": False, "reason": "no resolved IP for the apex"}
        try:
            first_ip = await _first_resolved_ip(domain)
            if first_ip:
                asn = await asn_intel.fetch(client, None, first_ip)
                if not (asn or {}).get("available"):
                    asn = {"available": False, "reason": "RIPEstat did not return routing context"}
        except Exception as exc:  # noqa: BLE001
            log.info("asm discovery asn failed for %s: %s", tag(domain), type(exc).__name__)
            asn = {"available": False, "reason": "RIPEstat lookup error"}

    return {"hosts": in_scope_hosts, "sources": sources, "asn": asn, "registrable": reg}


async def _first_resolved_ip(domain: str):
    import socket
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.run_in_executor(None, socket.getaddrinfo, domain, None)
    except Exception:
        return None
    for info in infos:
        addr = info[4][0].split("%", 1)[0]
        return addr
    return None
