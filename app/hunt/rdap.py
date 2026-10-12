"""Hunt RDAP client.

Instead of routing every Hunt lookup through one aggregator (rdap.org), which
throttles a burst and leaves campaign members with an "unknown" registrar, this
resolves each TLD's own authoritative RDAP server from the IANA bootstrap and
queries it directly. Concurrency is capped per server, 429 is retried with
backoff (honouring Retry-After), and parsed answers are cached for 24 hours.
When a TLD is absent from the bootstrap the rdap.org aggregator is the fallback;
when RDAP yields nothing, system whois provides the registrar. The result is the
same shape as domain_intel.parse_rdap so callers are unchanged.

No em dashes in this module.
"""
from __future__ import annotations

import asyncio
import re
import time

import httpx

from app import config
from app.asm import store
from app.routers import domain_intel
from app.scanner.scope import registrable

_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_BOOTSTRAP_KEY = "__bootstrap__"
_UA = {"User-Agent": "FalconEye-Hunt/3.38.21 (OSINT research)",
       "Accept": "application/rdap+json, application/json"}

# Per-RDAP-host concurrency limiters, rebuilt if the running event loop changes
# (so tests that each spin their own loop do not share a stale semaphore).
_sema: dict = {}
_sema_loop = None
_bootstrap_mem = {"map": None, "at": 0.0}


def _tld(domain: str) -> str:
    reg = registrable(domain) or domain
    return reg.rsplit(".", 1)[-1] if "." in reg else reg


def _host(url: str) -> str:
    m = re.match(r"https?://([^/]+)", url or "")
    return m.group(1).lower() if m else url


def _sem(host: str) -> asyncio.Semaphore:
    global _sema_loop, _sema
    loop = asyncio.get_event_loop()
    if loop is not _sema_loop:
        _sema, _sema_loop = {}, loop
    if host not in _sema:
        _sema[host] = asyncio.Semaphore(config.HUNT_RDAP_PER_SERVER)
    return _sema[host]


async def _load_bootstrap(client: httpx.AsyncClient) -> dict:
    """TLD -> list of RDAP base URLs, from the IANA bootstrap, cached 24h."""
    if _bootstrap_mem["map"] is not None and \
            (time.time() - _bootstrap_mem["at"]) < config.HUNT_RDAP_BOOTSTRAP_TTL:
        return _bootstrap_mem["map"]
    cached = store.rdap_cache_get(_BOOTSTRAP_KEY, config.HUNT_RDAP_BOOTSTRAP_TTL)
    if isinstance(cached, dict) and cached:
        _bootstrap_mem.update(map=cached, at=time.time())
        return cached
    mapping: dict = {}
    try:
        r = await client.get(_BOOTSTRAP_URL, headers=_UA, timeout=config.HUNT_RDAP_TIMEOUT)
        if r.status_code == 200:
            for service in (r.json().get("services") or []):
                tlds, bases = (service + [[], []])[:2]
                for t in tlds:
                    mapping[t.lower()] = [b.rstrip("/") + "/" for b in bases]
    except Exception:  # noqa: BLE001
        mapping = {}
    if mapping:
        store.rdap_cache_put(_BOOTSTRAP_KEY, mapping)
        _bootstrap_mem.update(map=mapping, at=time.time())
    return mapping


async def _servers_for(client: httpx.AsyncClient, domain: str) -> list:
    """Authoritative RDAP base URLs for the domain's TLD, else the aggregator."""
    mapping = await _load_bootstrap(client)
    bases = list(mapping.get(_tld(domain)) or [])
    bases.append("https://rdap.org/")  # last-resort aggregator
    return bases


async def _get(client: httpx.AsyncClient, base: str, domain: str) -> dict | None:
    """One RDAP GET against *base*, retrying 429 with backoff. Returns the raw
    JSON, a not_found marker, or None for a transient failure worth retrying
    elsewhere."""
    url = base + "domain/" + domain
    host = _host(base)
    for attempt in range(config.HUNT_RDAP_MAX_RETRIES + 1):
        try:
            async with _sem(host):
                r = await client.get(url, headers=_UA, follow_redirects=True,
                                     timeout=config.HUNT_RDAP_TIMEOUT)
            if r.status_code == 200:
                return r.json()
            if r.status_code == 404:
                return {"error": "not_found", "status_code": 404}
            if r.status_code == 429 and attempt < config.HUNT_RDAP_MAX_RETRIES:
                ra = r.headers.get("Retry-After")
                delay = float(ra) if (ra or "").isdigit() else (2 ** attempt)
                await asyncio.sleep(min(delay, 10))
                continue
            return None
        except Exception:  # noqa: BLE001
            if attempt < config.HUNT_RDAP_MAX_RETRIES:
                await asyncio.sleep(2 ** attempt)
                continue
            return None
    return None


_WHOIS_REG = re.compile(r"(?im)^\s*(?:registrar|sponsoring registrar)\s*:\s*(.+?)\s*$")
_WHOIS_CREATED = re.compile(
    r"(?im)^\s*(?:creation date|created|registered on|registration time)\s*:\s*(.+?)\s*$")


async def _whois_fallback(domain: str) -> dict | None:
    """Registrar (and creation date if present) from system whois."""
    text = await domain_intel.fetch_whois(domain)
    if not text:
        return None
    reg = _WHOIS_REG.search(text)
    created = _WHOIS_CREATED.search(text)
    if not reg and not created:
        return None
    out = {"registrar": {"name": reg.group(1)} if reg else None,
           "events": {}, "abuse_contact": None, "nameservers": [], "source": "whois"}
    if created:
        out["events"]["registration"] = created.group(1).strip()[:10]
    return out


async def lookup(client: httpx.AsyncClient, domain: str) -> dict | None:
    """Parsed RDAP for *domain* (parse_rdap shape), from its authoritative server,
    with cache, per-server throttling, 429 retry, and a whois registrar fallback.
    A cached answer is returned without a network call; transient failures are not
    cached, so a later run retries them."""
    cached = store.rdap_cache_get(domain, config.HUNT_RDAP_CACHE_TTL)
    if cached is not None:
        return cached or None
    parsed = None
    for base in await _servers_for(client, domain):
        raw = await _get(client, base, domain)
        if raw is None:
            continue  # transient: try the next server
        if raw.get("error"):
            parsed = raw  # definitive not_found; stop
            break
        parsed = domain_intel.parse_rdap(raw)
        if parsed and (parsed.get("registrar") or parsed.get("events")):
            break
    if parsed is None or (parsed.get("error") == "not_found") or \
            not (parsed.get("registrar") or (parsed.get("events") or {}).get("registration")):
        who = await _whois_fallback(domain)
        if who:
            parsed = who
    if parsed is not None and not parsed.get("error"):
        store.rdap_cache_put(domain, parsed)  # cache only definitive answers
    return parsed if (parsed and not parsed.get("error")) else None
