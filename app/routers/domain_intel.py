import asyncio
import json
import logging
import socket
import sqlite3
import subprocess
from datetime import datetime, timezone, timedelta

import dns.resolver
import dns.reversename
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import DB_PATH
from app.database import get_db
from app.utils.domain import normalize_domain, extract_tld

router = APIRouter(prefix="/api/domain", tags=["domain"])
limiter = Limiter(key_func=get_remote_address)
log = logging.getLogger("falconeye.domain")

CACHE_TTL_HOURS = 6
RDAP_TIMEOUT = 10.0
CT_TIMEOUT = 20.0
RIPESTAT_TIMEOUT = 8.0
DNS_TIMEOUT = 5.0
WHOIS_TIMEOUT = 10.0

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"]


# ---- Cache helpers ----

def get_cached(db: sqlite3.Connection, domain: str) -> dict | None:
    row = db.execute(
        "SELECT * FROM domain_intel_cache WHERE domain = ?", (domain,)
    ).fetchone()
    if not row:
        return None
    fetched = datetime.fromisoformat(row["fetched_at"])
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - fetched > timedelta(hours=CACHE_TTL_HOURS):
        return None
    return {
        "rdap": json.loads(row["rdap_json"]) if row["rdap_json"] else None,
        "whois_text": row["whois_text"],
        "dns": json.loads(row["dns_json"]) if row["dns_json"] else None,
        "ct": json.loads(row["ct_json"]) if row["ct_json"] else None,
        "network": json.loads(row["network_json"]) if row["network_json"] else None,
        "fetched_at": row["fetched_at"],
        "cache_hit": True,
    }


def store_cache(
    db: sqlite3.Connection,
    domain: str,
    rdap: dict | None,
    whois_text: str | None,
    dns_data: dict | None,
    ct: list | None,
    network: dict | None,
) -> None:
    db.execute(
        """
        INSERT OR REPLACE INTO domain_intel_cache
            (domain, rdap_json, whois_text, dns_json, ct_json, network_json, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (
            domain,
            json.dumps(rdap) if rdap else None,
            whois_text,
            json.dumps(dns_data) if dns_data else None,
            json.dumps(ct) if ct else None,
            json.dumps(network) if network else None,
        ),
    )
    db.commit()


# ---- RDAP ----

async def fetch_rdap(client: httpx.AsyncClient, domain: str) -> dict | None:
    """
    Query rdap.org universal proxy. It follows IANA bootstrap and redirects
    to the authoritative registry RDAP server.
    """
    try:
        r = await client.get(
            f"https://rdap.org/domain/{domain}",
            headers={
                "User-Agent": "FalconEye/3.0 (osintph.info; OSINT research)",
                "Accept": "application/rdap+json, application/json",
            },
            follow_redirects=True,
            timeout=RDAP_TIMEOUT,
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            log.info(f"RDAP: domain not found for {domain}")
            return {"error": "not_found", "status_code": 404}
        log.warning(f"RDAP returned {r.status_code} for {domain}")
        return {"error": "rdap_error", "status_code": r.status_code}
    except Exception as e:
        log.warning(f"RDAP exception for {domain}: {e}")
        return None


def parse_rdap(rdap_raw: dict | None) -> dict | None:
    """Extract the operationally useful fields from a raw RDAP response."""
    if not rdap_raw or rdap_raw.get("error"):
        return rdap_raw

    result = {
        "handle": rdap_raw.get("handle"),
        "ldh_name": rdap_raw.get("ldhName"),
        "status": rdap_raw.get("status", []),
        "nameservers": [],
        "events": {},
        "registrar": None,
        "registrant": None,
        "abuse_contact": None,
        "secure_dns": rdap_raw.get("secureDNS", {}),
    }

    # Nameservers
    for ns in rdap_raw.get("nameservers", []):
        result["nameservers"].append(ns.get("ldhName", "").lower())

    # Events (registration, expiration, last changed)
    for event in rdap_raw.get("events", []):
        action = event.get("eventAction")
        date = event.get("eventDate")
        if action and date:
            result["events"][action] = date

    # Entities (registrar, registrant, abuse contact)
    for entity in rdap_raw.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [None, []])
        vcard_props = vcard[1] if len(vcard) > 1 else []

        contact = {"handle": entity.get("handle"), "name": None, "email": None, "phone": None}
        for prop in vcard_props:
            if not isinstance(prop, list) or len(prop) < 4:
                continue
            field_name = prop[0]
            field_value = prop[3]
            if field_name == "fn":
                contact["name"] = field_value
            elif field_name == "email":
                contact["email"] = field_value
            elif field_name == "tel":
                contact["phone"] = field_value

        if "registrar" in roles:
            result["registrar"] = contact
        if "registrant" in roles:
            result["registrant"] = contact
        if "abuse" in roles:
            result["abuse_contact"] = contact

    return result


# ---- WHOIS fallback (only for TLDs without RDAP) ----

async def fetch_whois(domain: str) -> str | None:
    """
    Run system whois as fallback. Used only when RDAP returns nothing useful.
    Capped at 10 seconds via subprocess timeout.
    """
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                ["whois", domain],
                capture_output=True,
                text=True,
                timeout=WHOIS_TIMEOUT,
            ),
        )
        if result.returncode == 0:
            return result.stdout[:8000]
        return None
    except Exception as e:
        log.warning(f"WHOIS exception for {domain}: {e}")
        return None


# ---- DNS ----

def fetch_dns_sync(domain: str) -> dict:
    """Synchronous DNS resolution wrapped in executor by caller."""
    result = {rt: [] for rt in DNS_RECORD_TYPES}
    result["resolved_ips"] = []
    result["ptr_records"] = {}

    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT

    for record_type in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type)
            for rdata in answers:
                result[record_type].append(str(rdata).strip('"'))
        except Exception:
            continue

    # Collect resolved IPs from A and AAAA records
    result["resolved_ips"] = result.get("A", []) + result.get("AAAA", [])

    # Reverse DNS for resolved IPs
    for ip in result["resolved_ips"][:5]:  # cap at 5 to keep things fast
        try:
            rev = dns.reversename.from_address(ip)
            ptr = resolver.resolve(rev, "PTR")
            result["ptr_records"][ip] = [str(r).rstrip(".") for r in ptr]
        except Exception:
            result["ptr_records"][ip] = []

    return result


async def fetch_dns(domain: str) -> dict:
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, fetch_dns_sync, domain)
    except Exception as e:
        log.warning(f"DNS resolution failed for {domain}: {e}")
        return {rt: [] for rt in DNS_RECORD_TYPES}


# ---- Certificate Transparency ----

async def fetch_ct_crtsh(client: httpx.AsyncClient, domain: str) -> dict | None:
    """
    Primary CT source: crt.sh. Returns None on failure (caller falls back to Google CT).
    Includes one retry with backoff for transient 502s.
    """
    for attempt in range(2):
        try:
            r = await client.get(
                f"https://crt.sh/?q={domain}&output=json",
                timeout=CT_TIMEOUT,
                headers={"User-Agent": "FalconEye/3.0 (osintph.info)"},
            )
            if r.status_code == 200 and "json" in r.headers.get("content-type", "").lower():
                try:
                    return {"raw": r.json(), "source": "crt.sh"}
                except Exception as e:
                    log.warning(f"crt.sh JSON parse failed for {domain}: {e}")
                    return None
            elif r.status_code == 200:
                # 200 with HTML body — error page
                log.warning(f"crt.sh returned 200 with non-JSON content for {domain}")
                if attempt == 0:
                    await asyncio.sleep(3)
                    continue
                return None
            else:
                log.warning(f"crt.sh returned {r.status_code} for {domain} (attempt {attempt + 1})")
                if attempt == 0 and r.status_code in (500, 502, 503, 504):
                    await asyncio.sleep(3)
                    continue
                return None
        except Exception as e:
            log.warning(f"crt.sh exception for {domain} attempt {attempt + 1}: {e}")
            if attempt == 0:
                await asyncio.sleep(2)
                continue
            return None
    return None


async def fetch_ct_certspotter(client: httpx.AsyncClient, domain: str) -> dict | None:
    """
    Fallback CT source: Certspotter by SSLMate (api.certspotter.com).
    Free tier, no key required, returns up to 100 issuances per query.

    The expand parameter MUST include every field we want returned. Without
    it, the API returns only the default minimal fields (id, sha256 hashes,
    not_before, not_after, revoked).
    """
    try:
        r = await client.get(
            "https://api.certspotter.com/v1/issuances",
            params=[
                ("domain", domain),
                ("include_subdomains", "true"),
                ("expand", "dns_names"),
                ("expand", "issuer"),
            ],
            timeout=CT_TIMEOUT,
            headers={"User-Agent": "FalconEye/3.0 (osintph.info)"},
        )
        if r.status_code != 200:
            log.warning(f"Certspotter returned {r.status_code} for {domain}")
            return None

        data = r.json()
        if not isinstance(data, list):
            log.warning(f"Certspotter unexpected response shape for {domain}")
            return None

        normalized = []
        for entry in data[:300]:
            dns_names = entry.get("dns_names") or []
            issuer_obj = entry.get("issuer") or {}

            issuer_label = (
                issuer_obj.get("friendly_name")
                or issuer_obj.get("name")
                or ""
            )

            normalized.append({
                "serial": entry.get("id"),
                "issuer": issuer_label,
                "common_name": dns_names[0] if dns_names else "",
                "sans": dns_names[:20],
                "not_before": entry.get("not_before"),
                "not_after": entry.get("not_after"),
            })

        return {"raw_normalized": normalized, "source": "certspotter"}
    except Exception as e:
        log.warning(f"Certspotter exception for {domain}: {e}")
        return None


async def fetch_ct(client: httpx.AsyncClient, domain: str) -> dict:
    """
    Query CT sources with fallback. Returns a dict with certificates, subdomains,
    source attribution, and an error field if all sources failed.
    """
    primary = await fetch_ct_crtsh(client, domain)

    if primary:
        raw_certs = primary["raw"]
        source = primary["source"]
    else:
        log.info(f"Falling back to Certspotter for {domain}")
        fallback = await fetch_ct_certspotter(client, domain)
        if fallback:
            return _normalize_google_ct(fallback, domain)
        else:
            return {
                "certificates": [],
                "subdomains": [],
                "source": None,
                "error": "All CT sources unavailable. crt.sh and Certspotter both failed. Try again in a few minutes.",
            }

    # Normalize crt.sh response
    seen = {}
    all_sans = set()

    for cert in raw_certs[:300]:
        serial = cert.get("serial_number")
        if serial and serial in seen:
            continue
        not_before = cert.get("not_before")
        not_after = cert.get("not_after")
        issuer = cert.get("issuer_name", "")
        common_name = cert.get("common_name", "")
        name_value = cert.get("name_value", "")

        sans = [s.strip() for s in name_value.split("\n") if s.strip()]
        all_sans.update(sans)

        seen[serial or f"{not_before}_{common_name}"] = {
            "serial": serial,
            "issuer": issuer,
            "common_name": common_name,
            "sans": sans[:20],
            "not_before": not_before,
            "not_after": not_after,
        }

    certs = sorted(seen.values(), key=lambda c: c.get("not_before") or "", reverse=True)
    subdomains = sorted(set(
        s.lower() for s in all_sans
        if s.endswith(f".{domain}") or s == domain
    ))

    return {
        "certificates": certs[:100],
        "subdomains": subdomains,
        "source": source,
        "error": None,
    }


def _normalize_google_ct(fallback: dict, domain: str) -> dict:
    """Convert Google CT normalized entries into the standard FalconEye CT response."""
    certs_in = fallback["raw_normalized"]
    all_sans = set()
    for c in certs_in:
        for san in c.get("sans", []):
            if san:
                all_sans.add(san)

    subdomains = sorted(set(
        s.lower() for s in all_sans
        if s.endswith(f".{domain}") or s == domain
    ))

    certs = sorted(certs_in, key=lambda c: c.get("not_before") or "", reverse=True)

    return {
        "certificates": certs[:100],
        "subdomains": subdomains,
        "source": "certspotter",
        "error": None,
    }


# ---- Network attribution (ASN / hosting) ----

async def fetch_network(client: httpx.AsyncClient, ip: str) -> dict | None:
    """RIPEstat network info for an IP, then ASN holder details."""
    try:
        r = await client.get(
            f"https://stat.ripe.net/data/network-info/data.json",
            params={"resource": ip},
            timeout=RIPESTAT_TIMEOUT,
            headers={"User-Agent": "FalconEye/3.0 (osintph.info)"},
        )
        if r.status_code != 200:
            return None
        net_data = r.json().get("data", {})
        asns = net_data.get("asns", [])
        prefix = net_data.get("prefix")

        result = {
            "ip": ip,
            "prefix": prefix,
            "asn": asns[0] if asns else None,
            "asn_holder": None,
            "asn_country": None,
        }

        # Get ASN overview for the first ASN
        if asns:
            asn_r = await client.get(
                f"https://stat.ripe.net/data/as-overview/data.json",
                params={"resource": f"AS{asns[0]}"},
                timeout=RIPESTAT_TIMEOUT,
                headers={"User-Agent": "FalconEye/3.0 (osintph.info)"},
            )
            if asn_r.status_code == 200:
                asn_data = asn_r.json().get("data", {})
                result["asn_holder"] = asn_data.get("holder")
        return result
    except Exception as e:
        log.warning(f"RIPEstat exception for {ip}: {e}")
        return None


# ---- Main endpoint ----

@router.get("/lookup/{domain}")
@limiter.limit("20/minute")
async def lookup_domain(request: Request, domain: str, db: sqlite3.Connection = Depends(get_db)):
    normalized = normalize_domain(domain)
    if not normalized:
        raise HTTPException(
            status_code=400,
            detail="Invalid domain format. Provide a hostname like example.com (no protocol or path).",
        )

    # Cache check
    cached = get_cached(db, normalized)
    if cached:
        return {
            "domain": normalized,
            "rdap": parse_rdap(cached.get("rdap")) if cached.get("rdap") else None,
            "rdap_raw": cached.get("rdap"),
            "whois_text": cached.get("whois_text"),
            "dns": cached.get("dns"),
            "ct": cached.get("ct"),
            "network": cached.get("network"),
            "cache_hit": True,
            "fetched_at": cached["fetched_at"],
        }

    # Parallel fetches
    async with httpx.AsyncClient(follow_redirects=True) as client:
        rdap_task = fetch_rdap(client, normalized)
        ct_task = fetch_ct(client, normalized)
        dns_task = fetch_dns(normalized)

        rdap_raw, ct_data, dns_data = await asyncio.gather(
            rdap_task, ct_task, dns_task, return_exceptions=True
        )

        # Coerce exceptions to None
        if isinstance(rdap_raw, Exception):
            rdap_raw = None
        if isinstance(ct_data, Exception):
            ct_data = {"certificates": [], "subdomains": []}
        if isinstance(dns_data, Exception):
            dns_data = {rt: [] for rt in DNS_RECORD_TYPES}

        # WHOIS fallback if RDAP returned nothing useful
        whois_text = None
        rdap_useful = rdap_raw and not rdap_raw.get("error")
        if not rdap_useful:
            whois_text = await fetch_whois(normalized)

        # Network attribution for resolved IPs (max 2 to keep things snappy)
        network_data = {"ips": []}
        for ip in (dns_data.get("resolved_ips") or [])[:2]:
            net = await fetch_network(client, ip)
            if net:
                network_data["ips"].append(net)

    # Store cache
    store_cache(db, normalized, rdap_raw, whois_text, dns_data, ct_data, network_data)

    return {
        "domain": normalized,
        "rdap": parse_rdap(rdap_raw),
        "rdap_raw": rdap_raw,
        "whois_text": whois_text,
        "dns": dns_data,
        "ct": ct_data,
        "network": network_data,
        "cache_hit": False,
    }
