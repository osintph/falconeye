import asyncio
import ipaddress
import json
import logging
import socket
import sqlite3
from datetime import datetime, timezone, timedelta

import dns.resolver
import dns.reversename
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from slowapi import Limiter

from app.config import ABUSECH_AUTH_KEY, DB_PATH, GREYNOISE_API_KEY, OPERATOR_CONTACT_UA
from app.database import get_db
from app.ip_sources import reputation, asn_intel
from app.utils import abusech, cache
from app.utils.client_ip import get_client_ip_key
from app.utils.logsafe import tag

router = APIRouter(prefix="/api/ip", tags=["ip"])
limiter = Limiter(key_func=get_client_ip_key)
log = logging.getLogger("falconeye.ip")

CACHE_TTL_HOURS = 6
FETCH_TIMEOUT = 10.0
USER_AGENT = f"FalconEye/3.0 ({OPERATOR_CONTACT_UA}; OSINT research)"


def validate_ip(raw: str) -> str | None:
    """Validate an IP address string. Returns the canonical form or None."""
    try:
        ip = ipaddress.ip_address(raw.strip())
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return None
        return str(ip)
    except ValueError:
        return None


# ---- Cache table ----
# Self-initialize the cache table at import, mirroring every other router
# (dork_generator, email_header, url_expander, abuse). Without this the tab
# 500s on any database that was created fresh rather than migrated in place.

def _init_cache():
    """Self-init entry point (delegates to the shared cache store)."""
    cache.init_table("ip_intel_cache", key_col="ip")


_init_cache()


# ---- Cache helpers (delegate to the shared cache store, reusing the request conn) ----

CACHE_TABLE = "ip_intel_cache"


def get_cached(db: sqlite3.Connection, ip: str) -> dict | None:
    return cache.get(CACHE_TABLE, ip, CACHE_TTL_HOURS, key_col="ip", conn=db)


def store_cache(db: sqlite3.Connection, ip: str, response: dict) -> None:
    cache.set(CACHE_TABLE, ip, response, key_col="ip", conn=db)


# ---- Which parts of one lookup can fail, for the negative cache ----
#
# The keyless fetchers signal failure by returning None, and each is
# distinguishable from a real empty answer: Shodan returns {"empty": True} for a
# 404, URLhaus returns a body with query_status for a miss, RIPEstat returns a
# dict. GreyNoise returns None when it has no key too, which is fine: retrying it
# costs no HTTP call and means a key added mid-window starts working within the
# minute.
#
# Deliberately NOT tracked:
#   reverse_dns - an address with no PTR record is the normal case, and an empty
#     list cannot be told apart from a resolver failure, so retrying it would
#     re-query DNS on every single lookup of every PTR-less address.
#   asn_intel  - {"available": False} means both "this IP has no ASN" and "RIPE
#     was unhappy", and it keeps its own per-ASN cache of the upstream answers,
#     so a failure there is already not pinned to this row.
_CORE_FETCHERS = ("shodan", "greynoise", "ripestat", "urlhaus")


def _core_failed(response: dict) -> list:
    """Which keyless fetchers did not answer in this response."""
    return [name for name in _CORE_FETCHERS if response.get(name) is None]


def _failed_parts(response: dict) -> list:
    """Every part of this lookup that failed: sources and keyless fetchers."""
    sources = ((response.get("reputation") or {}).get("sources")) or {}
    return reputation.failed_sources(sources) + _core_failed(response)


def _rebuild_reputation(response: dict) -> None:
    """Recompute the verdict, geo consensus and merged ports in place.

    Called after a partial retry has replaced some of the parts the block is
    derived from. Everything here is pure computation over what is already in
    the response.
    """
    sources = ((response.get("reputation") or {}).get("sources")) or {}
    shodan = response.get("shodan") if isinstance(response.get("shodan"), dict) else None
    ripestat = response.get("ripestat") if isinstance(response.get("ripestat"), dict) else None
    greynoise = response.get("greynoise") if isinstance(response.get("greynoise"), dict) else None
    if shodan is not None:
        shodan_ports = [] if shodan.get("empty") else (shodan.get("ports") or [])
    else:
        shodan_ports = None
    block = reputation.assemble(
        sources,
        greynoise_malicious=((greynoise or {}).get("classification") == "malicious"),
        shodan_ports=shodan_ports,
        existing_country=(ripestat or {}).get("country"),
        network_name=(ripestat or {}).get("asn_holder"),
        ip=response.get("ip"),
    )
    response["reputation"] = {**block, "_target": response.get("ip")}


async def _retry_failed(db: sqlite3.Connection, ip: str, cached: dict,
                        failures: dict, stale: list) -> dict:
    """Re-attempt the parts of a cached lookup that failed, and nothing else.

    The row itself stays cached: what expires early is the failure, not the
    answer. Sources that answered are never re-queried here, because AbuseIPDB
    is 1,000 checks a day and VirusTotal 500 and those quotas are what the cache
    exists to protect.
    """
    rep_names = [n for n in stale if n in reputation.ALL_NAMES]
    core_names = [n for n in stale if n in _CORE_FETCHERS]

    async with httpx.AsyncClient(follow_redirects=True) as client:
        jobs = {}
        if rep_names:
            jobs["_reputation"] = reputation.fetch_sources(ip, client, only=rep_names)
        if "shodan" in core_names:
            jobs["shodan"] = fetch_shodan_internetdb(client, ip)
        if "greynoise" in core_names:
            jobs["greynoise"] = fetch_greynoise(client, ip)
        if "ripestat" in core_names:
            jobs["ripestat"] = fetch_ripestat(client, ip)
        if "urlhaus" in core_names:
            jobs["urlhaus"] = fetch_urlhaus_host(client, ip)

        names = list(jobs)
        results = await asyncio.gather(*(jobs[n] for n in names), return_exceptions=True)
        got = {}
        for name, value in zip(names, results):
            got[name] = None if isinstance(value, Exception) else value

        new_sources = got.pop("_reputation", None) or {}
        if not isinstance(new_sources, dict):
            new_sources = {}
        for name, value in got.items():
            cached[name] = value

        merged = dict(((cached.get("reputation") or {}).get("sources")) or {})
        merged.update(new_sources)
        cached.setdefault("reputation", {})["sources"] = merged

        if cached.get("shodan") and (cached["shodan"] or {}).get("vulns"):
            cached["cve_details"] = await fetch_cve_details(client, cached["shodan"]["vulns"])

    _rebuild_reputation(cached)

    # Stamp what is still failing. A failure that was not retried (it is inside
    # its own window) keeps its original stamp, so the window is per source and
    # a retry that fails again restarts only its own.
    still = _failed_parts(cached)
    kept = {n: t for n, t in failures.items() if n in still and n not in stale}
    if kept:
        cached[cache.FAILURES_KEY] = kept
    cache.note_failures(cached, [n for n in still if n not in kept])

    cache.update_blob(CACHE_TABLE, ip, cached, key_col="ip", conn=db)
    cache.take_failures(cached)
    cached["cache_hit"] = True
    return cached


# ---- Data source fetchers ----

async def fetch_shodan_internetdb(client: httpx.AsyncClient, ip: str) -> dict | None:
    try:
        r = await client.get(
            f"https://internetdb.shodan.io/{ip}",
            timeout=FETCH_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            return {"empty": True}
        log.warning(f"Shodan InternetDB returned {r.status_code} for {tag(ip)}")
        return None
    except Exception as e:
        log.warning(f"Shodan InternetDB exception for {tag(ip)}: {e}")
        return None


async def fetch_greynoise(client: httpx.AsyncClient, ip: str) -> dict | None:
    if not GREYNOISE_API_KEY:
        return None
    try:
        r = await client.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            timeout=FETCH_TIMEOUT,
            headers={"key": GREYNOISE_API_KEY, "User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        if r.status_code in (200, 404):
            return r.json()
        log.warning(f"GreyNoise returned {r.status_code} for {tag(ip)}")
        return None
    except Exception as e:
        log.warning(f"GreyNoise exception for {tag(ip)}: {e}")
        return None


async def fetch_ripestat(client: httpx.AsyncClient, ip: str) -> dict | None:
    try:
        r = await client.get(
            "https://stat.ripe.net/data/network-info/data.json",
            params={"resource": ip},
            timeout=FETCH_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        if r.status_code != 200:
            return None
        net_data = r.json().get("data", {})
        asns = net_data.get("asns", [])
        prefix = net_data.get("prefix")

        result = {"prefix": prefix, "asn": asns[0] if asns else None, "asn_holder": None, "country": None}

        if asns:
            asn_r = await client.get(
                "https://stat.ripe.net/data/as-overview/data.json",
                params={"resource": f"AS{asns[0]}"},
                timeout=FETCH_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
            )
            if asn_r.status_code == 200:
                asn_data = asn_r.json().get("data", {})
                result["asn_holder"] = asn_data.get("holder")

        geo_r = await client.get(
            "https://stat.ripe.net/data/maxmind-geo-lite/data.json",
            params={"resource": ip},
            timeout=FETCH_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        if geo_r.status_code == 200:
            geo_data = geo_r.json().get("data", {}).get("located_resources", [])
            if geo_data:
                locations = geo_data[0].get("locations", [])
                if locations:
                    loc = locations[0]
                    result["country"] = loc.get("country")
                    result["city"] = loc.get("city")
                    result["latitude"] = loc.get("latitude")
                    result["longitude"] = loc.get("longitude")

        return result
    except Exception as e:
        log.warning(f"RIPEstat exception for {tag(ip)}: {e}")
        return None


async def fetch_urlhaus_host(client: httpx.AsyncClient, ip: str) -> dict | None:
    return await abusech.urlhaus_host(client, ip)


def fetch_reverse_dns_sync(ip: str) -> list[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4.0
        resolver.timeout = 4.0
        rev = dns.reversename.from_address(ip)
        ptr = resolver.resolve(rev, "PTR")
        return [str(r).rstrip(".") for r in ptr]
    except Exception:
        return []


async def fetch_reverse_dns(ip: str) -> list[str]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, fetch_reverse_dns_sync, ip)


async def fetch_cve_details(client: httpx.AsyncClient, cve_ids: list[str]) -> dict[str, dict]:
    if not cve_ids:
        return {}
    details = {}

    async def fetch_one(cve_id: str):
        try:
            r = await client.get(
                f"https://cvedb.shodan.io/cve/{cve_id}",
                timeout=8.0,
                headers={"User-Agent": USER_AGENT},
            )
            if r.status_code == 200:
                d = r.json()
                details[cve_id] = {
                    "cvss": d.get("cvss"),
                    "epss": d.get("epss"),
                    "kev": d.get("kev"),
                    "summary": (d.get("summary") or "")[:300],
                }
        except Exception:
            pass

    await asyncio.gather(*[fetch_one(c) for c in cve_ids[:10]])
    return details


# ---- Main endpoint ----

@router.get("/lookup/{ip}")
@limiter.limit("20/minute")
async def lookup_ip(request: Request, ip: str, refresh: bool = False,
                    db: sqlite3.Connection = Depends(get_db)):
    validated = validate_ip(ip)
    if not validated:
        raise HTTPException(status_code=400, detail="Invalid or non-routable IP address.")

    # refresh=1 bypasses the 6 hour cache and re-queries every source, then
    # replaces the cached row. It is the same endpoint and therefore carries the
    # same per-IP limiter as any other lookup: a refresh costs a lookup, which
    # is what stops it being a free way to spend the upstream quotas.
    cached = None if refresh else get_cached(db, validated)
    if cached:
        # A cached failure is not a cached answer. Any source that failed carries
        # a stamp; once that stamp is older than cache.NEGATIVE_TTL_SECONDS the
        # source is re-attempted here instead of being served for the rest of the
        # six hours. Refresh skips this path entirely and re-queries everything.
        failures = cache.take_failures(cached)
        stale = cache.stale_failures(failures)
        if stale:
            log.info("event=ip_cache_retry target=%s sources=%s",
                     tag(validated), ",".join(sorted(stale)))
            return await _retry_failed(db, validated, cached, failures, stale)
        # Otherwise the failure is inside its window: it stands, the upstream is
        # left alone, and the stored stamps are untouched by this read.
        #
        # Replay the per-source lines so a cached answer is not a silent one.
        # Without this the log shows nothing for the majority of lookups, which
        # is what forced the v3.33.2 diagnosis through the database by hand.
        reputation.log_cached_sources(
            validated, ((cached.get("reputation") or {}).get("sources") or {}))
        return cached

    async with httpx.AsyncClient(follow_redirects=True) as client:
        shodan_task = fetch_shodan_internetdb(client, validated)
        greynoise_task = fetch_greynoise(client, validated)
        ripestat_task = fetch_ripestat(client, validated)
        urlhaus_task = fetch_urlhaus_host(client, validated)
        ptr_task = fetch_reverse_dns(validated)
        # v3.9.0: five reputation sources fetched concurrently with the core ones,
        # so total latency is bounded by the slowest source, not the sum.
        reputation_task = reputation.fetch_sources(validated, client)
        # v3.20.0: ASN identity + announced prefixes, folded into this same
        # request per the brief (no second round-trip on render). Peers/
        # upstreams are expand-to-load, see the /asn/{asn}/routing endpoint.
        asn_task = asn_intel.fetch(client, db, validated)

        shodan, greynoise, ripestat, urlhaus, ptr, rep_sources, asn_block = await asyncio.gather(
            shodan_task, greynoise_task, ripestat_task, urlhaus_task, ptr_task, reputation_task, asn_task,
            return_exceptions=True,
        )

        if isinstance(shodan, Exception): shodan = None
        if isinstance(greynoise, Exception): greynoise = None
        if isinstance(ripestat, Exception): ripestat = None
        if isinstance(urlhaus, Exception): urlhaus = None
        if isinstance(ptr, Exception): ptr = []
        if isinstance(rep_sources, Exception) or not isinstance(rep_sources, dict): rep_sources = {}
        if isinstance(asn_block, Exception) or not isinstance(asn_block, dict): asn_block = {"available": False}

        cve_details = {}
        if shodan and shodan.get("vulns"):
            cve_details = await fetch_cve_details(client, shodan["vulns"])

    # Assemble the multi-source reputation: consensus verdict, geo consensus, merged ports.
    _shodan = shodan if isinstance(shodan, dict) else None
    _ripestat = ripestat if isinstance(ripestat, dict) else None
    _greynoise = greynoise if isinstance(greynoise, dict) else None
    if _shodan is not None:
        shodan_ports = [] if _shodan.get("empty") else (_shodan.get("ports") or [])
    else:
        shodan_ports = None
    reputation_block = reputation.assemble(
        rep_sources,
        greynoise_malicious=((_greynoise or {}).get("classification") == "malicious"),
        shodan_ports=shodan_ports,
        existing_country=(_ripestat or {}).get("country"),
        network_name=(_ripestat or {}).get("asn_holder"),
        # Lets the verdict recognise a public resolver or a CDN edge, where an
        # abuse report is about one client rather than about the address.
        ip=validated,
    )

    response = {
        "ip": validated,
        "shodan": shodan,
        "greynoise": greynoise,
        "ripestat": ripestat,
        "urlhaus": urlhaus,
        "reverse_dns": ptr,
        "cve_details": cve_details,
        "reputation": {**reputation_block, "_target": validated},
        "asn_intel": asn_block,
        "cache_hit": False,
    }

    # Stamp whatever failed before the row is written, so the next lookup
    # re-attempts it instead of being served this failure for six hours.
    cache.note_failures(response, _failed_parts(response))
    store_cache(db, validated, response)
    cache.take_failures(response)
    return response


# ---- ASN routing relationships (v3.20.0) ----
# Expand-to-load only: peers/upstreams cost several extra RIPEstat calls
# (asn-neighbours plus name resolution for the shown subset), so unlike the
# core ASN block above this is a deliberate second round-trip, fired only
# when the user opens the routing section in the UI - never on page load.

@router.get("/asn/{asn}/routing")
@limiter.limit("20/minute")
async def asn_routing(request: Request, asn: int, db: sqlite3.Connection = Depends(get_db)):
    if asn <= 0 or asn > 4294967295:
        raise HTTPException(status_code=400, detail="Invalid ASN.")
    async with httpx.AsyncClient(follow_redirects=True) as client:
        return await asn_intel.fetch_routing(client, db, asn)
