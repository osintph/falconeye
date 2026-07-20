"""
Aggregate the five IP-reputation sources into a consensus verdict, a geo-consensus
block, and a merged port list. Every source is fetched concurrently and every
failure is contained per-source, so a slow/broken source never blanks the result
or 500s the endpoint.
"""
import asyncio

import httpx

from app.ip_sources import abuseipdb, virustotal, otx, censys, threatfox
from app.ip_sources.base import SourceResult, ERROR

_NAMES = ["abuseipdb", "virustotal", "otx", "censys", "threatfox"]

# Verdict thresholds (named constants per the brief).
ABUSEIPDB_MALICIOUS = 75
ABUSEIPDB_SUSPICIOUS = 25
VT_MALICIOUS = 3
OTX_MALICIOUS_PULSES = 3

_HOSTING_KW = ("hosting", "cloud", "server", "datacenter", "data center", "vps", "dedicated", "colo")


def _is_hosting(name: str) -> bool:
    n = (name or "").lower()
    return any(k in n for k in _HOSTING_KW)


def compute_verdict(sources: dict, greynoise_malicious: bool = False) -> dict:
    def sig(name, field):
        s = sources.get(name, {})
        return (s.get("data") or {}).get(field) if s.get("ok") else None

    ab = sig("abuseipdb", "confidence")
    vt = sig("virustotal", "malicious")
    pulses = sig("otx", "pulse_count")
    tf_matched = bool(sig("threatfox", "matched"))

    reasons = []
    if (ab is not None and ab >= ABUSEIPDB_MALICIOUS):
        reasons.append(f"AbuseIPDB {ab}%")
    if (vt is not None and vt >= VT_MALICIOUS):
        reasons.append(f"VirusTotal {vt} vendors")
    if tf_matched:
        reasons.append("ThreatFox IOC match")
    if (pulses is not None and pulses >= OTX_MALICIOUS_PULSES):
        reasons.append(f"OTX {pulses} pulses")
    if reasons:
        return {"verdict": "MALICIOUS", "reasoning": "Malicious: " + ", ".join(reasons)}

    if (ab is not None and ABUSEIPDB_SUSPICIOUS <= ab < ABUSEIPDB_MALICIOUS):
        reasons.append(f"AbuseIPDB {ab}%")
    if (vt is not None and 1 <= vt < VT_MALICIOUS):
        reasons.append(f"VirusTotal {vt} vendor(s)")
    if (pulses is not None and 1 <= pulses < OTX_MALICIOUS_PULSES):
        reasons.append(f"OTX {pulses} pulse(s)")
    if greynoise_malicious:
        reasons.append("GreyNoise malicious")
    if reasons:
        return {"verdict": "SUSPICIOUS", "reasoning": "Suspicious: " + ", ".join(reasons)}

    return {"verdict": "CLEAN", "reasoning": "No source flagged this IP"}


def compute_geo(sources: dict, existing_country: str | None, network_name: str | None) -> dict:
    countries: dict = {}

    def add(code, label):
        if not code:
            return
        c = str(code).upper()
        countries.setdefault(c, [])
        if label not in countries[c]:
            countries[c].append(label)

    add(existing_country, "geolocation")
    for name in ("abuseipdb", "virustotal", "otx", "censys"):
        s = sources.get(name, {})
        if s.get("ok"):
            add(s.get("country"), name)
    cz = sources.get("censys", {})
    if cz.get("ok"):
        add((cz.get("data") or {}).get("asn_country"), "asn-registration")

    return {
        "countries": countries,
        "agreement": len(countries) <= 1,
        "is_hosting_asn": _is_hosting(network_name),
    }


def merge_ports(shodan_ports, censys_source: dict | None) -> dict:
    merged: dict = {}
    shodan_ran = shodan_ports is not None
    for p in (shodan_ports or []):
        try:
            port = int(p)
        except (TypeError, ValueError):
            continue
        merged.setdefault(port, {"port": port, "service": None, "sources": []})
        if "shodan" not in merged[port]["sources"]:
            merged[port]["sources"].append("shodan")

    censys_ran = bool(censys_source and censys_source.get("ok"))
    if censys_ran:
        for pd in ((censys_source.get("data") or {}).get("ports") or []):
            port = pd.get("port")
            if port is None:
                continue
            e = merged.setdefault(int(port), {"port": int(port), "service": None, "sources": []})
            if "censys" not in e["sources"]:
                e["sources"].append("censys")
            if pd.get("service") and not e["service"]:
                e["service"] = pd["service"]

    ports = sorted(merged.values(), key=lambda x: x["port"])
    consulted = [label for label, ran in (("Shodan InternetDB", shodan_ran), ("Censys", censys_ran)) if ran]
    return {"ports": ports, "consulted": consulted, "empty": len(ports) == 0}


async def fetch_sources(ip: str, client: httpx.AsyncClient) -> dict:
    """Fetch all five sources concurrently. Never raises; each failure is contained.
    Kept separate from assemble() so callers can run this concurrently with the
    existing IP fetchers (latency bounded by the slowest source, not the sum)."""
    results = await asyncio.gather(
        abuseipdb.fetch(ip, client),
        virustotal.fetch(ip, client),
        otx.fetch(ip, client),
        censys.fetch(ip, client),
        threatfox.fetch(ip, client),
        return_exceptions=True,
    )
    sources = {}
    for name, r in zip(_NAMES, results):
        if isinstance(r, BaseException):
            sources[name] = SourceResult(name, False, ERROR, {}, type(r).__name__).as_dict()
        else:
            sources[name] = r.as_dict()
    return sources


def assemble(sources: dict, *, greynoise_malicious: bool = False, shodan_ports=None,
             existing_country=None, network_name=None) -> dict:
    """Build the verdict / geo-consensus / merged-ports block from fetched sources."""
    return {
        "sources": sources,
        "verdict": compute_verdict(sources, greynoise_malicious),
        "geo": compute_geo(sources, existing_country, network_name),
        "ports": merge_ports(shodan_ports, sources.get("censys")),
    }


async def enrich(ip: str, client: httpx.AsyncClient, **ctx) -> dict:
    """Convenience: fetch then assemble (used where concurrency with core fetchers
    is not needed, e.g. tests)."""
    return assemble(await fetch_sources(ip, client), **ctx)
