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

from app.config import DB_PATH, GREYNOISE_API_KEY, ABUSECH_AUTH_KEY
from app.database import get_db
from app.ip_sources import reputation, asn_intel
from app.utils import abusech, cache
from app.utils.client_ip import get_client_ip_key

router = APIRouter(prefix="/api/ip", tags=["ip"])
limiter = Limiter(key_func=get_client_ip_key)
log = logging.getLogger("falconeye.ip")

CACHE_TTL_HOURS = 6
FETCH_TIMEOUT = 10.0
USER_AGENT = "FalconEye/3.0 (osintph.info; OSINT research)"


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

def get_cached(db: sqlite3.Connection, ip: str) -> dict | None:
    return cache.get("ip_intel_cache", ip, CACHE_TTL_HOURS, key_col="ip", conn=db)


def store_cache(db: sqlite3.Connection, ip: str, response: dict) -> None:
    cache.set("ip_intel_cache", ip, response, key_col="ip", conn=db)


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
        log.warning(f"Shodan InternetDB returned {r.status_code} for {ip}")
        return None
    except Exception as e:
        log.warning(f"Shodan InternetDB exception for {ip}: {e}")
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
        log.warning(f"GreyNoise returned {r.status_code} for {ip}")
        return None
    except Exception as e:
        log.warning(f"GreyNoise exception for {ip}: {e}")
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
        log.warning(f"RIPEstat exception for {ip}: {e}")
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
async def lookup_ip(request: Request, ip: str, db: sqlite3.Connection = Depends(get_db)):
    validated = validate_ip(ip)
    if not validated:
        raise HTTPException(status_code=400, detail="Invalid or non-routable IP address.")

    cached = get_cached(db, validated)
    if cached:
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
    )

    response = {
        "ip": validated,
        "shodan": shodan,
        "greynoise": greynoise,
        "ripestat": ripestat,
        "urlhaus": urlhaus,
        "reverse_dns": ptr,
        "cve_details": cve_details,
        "reputation": reputation_block,
        "asn_intel": asn_block,
        "cache_hit": False,
    }

    store_cache(db, validated, response)
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
