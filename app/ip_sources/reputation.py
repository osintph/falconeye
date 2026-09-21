"""
Aggregate the five IP-reputation sources into a consensus verdict, a geo-consensus
block, and a merged port list. Every source is fetched concurrently and every
failure is contained per-source, so a slow/broken source never blanks the result
or 500s the endpoint.
"""
import asyncio
import logging
import time

import httpx

from app.ip_sources import abuseipdb, virustotal, otx, censys, threatfox
from app.ip_sources.base import SourceResult, ERROR
from app.utils.env import getenv_clean

log = logging.getLogger("falconeye.ip_sources")

_NAMES = ["abuseipdb", "virustotal", "otx", "censys", "threatfox"]
_MODULES = {
    "abuseipdb": abuseipdb, "virustotal": virustotal, "otx": otx,
    "censys": censys, "threatfox": threatfox,
}

MALICIOUS = "MALICIOUS"
SUSPICIOUS = "SUSPICIOUS"
CLEAN = "CLEAN"
# A verdict is only CLEAN when every source actually answered. A source that has
# no key, errored, timed out or hit quota is UNAVAILABLE, and its silence is not
# evidence of innocence. Before v3.33.2 such a source returned None from sig()
# below and was indistinguishable from one that answered and found nothing, so
# the card said "No source flagged this IP" when in truth nothing had been asked.
INCOMPLETE = "INCOMPLETE"


def configured_sources() -> dict:
    """Which reputation sources have credentials, without calling anything.

    Used to tell the operator up front that a lookup cannot be conclusive,
    rather than after a lookup that silently consulted nothing.
    """
    configured, missing = [], []
    for name in _NAMES:
        mod = _MODULES[name]
        entry = {"source": name, "label": getattr(mod, "LABEL", name),
                 "env": getattr(mod, "KEY_ENV", None)}
        (configured if getenv_clean(entry["env"] or "") else missing).append(entry)
    return {
        "configured": len(configured),
        "total": len(_NAMES),
        "missing": missing,
        "none_configured": not configured,
    }


# Verdict thresholds (named constants per the brief).
ABUSEIPDB_MALICIOUS = 75
ABUSEIPDB_SUSPICIOUS = 25
VT_MALICIOUS = 3
OTX_MALICIOUS_PULSES = 3

_HOSTING_KW = ("hosting", "cloud", "server", "datacenter", "data center", "vps", "dedicated", "colo")


def _is_hosting(name: str) -> bool:
    n = (name or "").lower()
    return any(k in n for k in _HOSTING_KW)


def _availability(sources: dict) -> tuple[int, list]:
    """(count that answered, [{source, label, state, error} for those that did not])."""
    responded, unavailable = 0, []
    for name in _NAMES:
        entry = sources.get(name) or {}
        if entry.get("ok"):
            responded += 1
        else:
            unavailable.append({
                "source": name,
                "label": getattr(_MODULES[name], "LABEL", name),
                "state": entry.get("state") or ERROR,
                "error": entry.get("error"),
            })
    return responded, unavailable


def compute_verdict(sources: dict, greynoise_malicious: bool = False) -> dict:
    def sig(name, field):
        s = sources.get(name, {})
        return (s.get("data") or {}).get(field) if s.get("ok") else None

    ab = sig("abuseipdb", "confidence")
    vt = sig("virustotal", "malicious")
    pulses = sig("otx", "pulse_count")
    tf_matched = bool(sig("threatfox", "matched"))

    responded, unavailable = _availability(sources)
    total = len(_NAMES)
    coverage = {
        "sources_responded": responded,
        "sources_total": total,
        "sources_unavailable": unavailable,
        "coverage_note": f"{responded} of {total} reputation sources responded",
    }

    def result(verdict, reasoning):
        return {"verdict": verdict, "reasoning": reasoning, **coverage}

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
        # A positive hit stands on its own: one source finding something bad is
        # evidence even if another never answered.
        return result(MALICIOUS, "Malicious: " + ", ".join(reasons))

    if (ab is not None and ABUSEIPDB_SUSPICIOUS <= ab < ABUSEIPDB_MALICIOUS):
        reasons.append(f"AbuseIPDB {ab}%")
    if (vt is not None and 1 <= vt < VT_MALICIOUS):
        reasons.append(f"VirusTotal {vt} vendor(s)")
    if (pulses is not None and 1 <= pulses < OTX_MALICIOUS_PULSES):
        reasons.append(f"OTX {pulses} pulse(s)")
    if greynoise_malicious:
        reasons.append("GreyNoise malicious")
    if reasons:
        return result(SUSPICIOUS, "Suspicious: " + ", ".join(reasons))

    # Nothing flagged it. That is only CLEAN if everything actually answered.
    if unavailable:
        named = ", ".join(f"{u['label']} ({u['state']})" for u in unavailable)
        return result(
            INCOMPLETE,
            f"Incomplete: {responded} of {total} reputation sources responded. "
            f"No result from {named}. Nothing that did respond flagged this IP.",
        )
    return result(CLEAN, f"No source flagged this IP. All {total} sources responded.")


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


def log_source_call(name: str, target: str, status: str, latency_ms: int, cached: bool) -> None:
    """One structured line per source call, at INFO.

    Added in v3.33.2. Before this the app logged nothing about source calls at
    all, so diagnosing a wrong verdict meant reading the SQLite cache by hand:
    there was no way to tell from the logs whether a source had been asked, what
    it said, or how long it took. Keys are never logged, only which source and
    what it returned.
    """
    log.info(
        "event=ip_source source=%s target=%s status=%s latency_ms=%d cached=%s",
        name, target, status, latency_ms, "true" if cached else "false",
    )


def log_cached_sources(ip: str, sources: dict) -> None:
    """Replay the same line shape for a cache hit, so the log is not silent."""
    for name in _NAMES:
        entry = sources.get(name) or {}
        status = entry.get("state") or ERROR
        log_source_call(name, ip, status, 0, True)


async def _timed_fetch(name: str, ip: str, client: httpx.AsyncClient):
    """Run one source, time it, log it, and never let it raise."""
    mod = _MODULES[name]
    start = time.perf_counter()
    try:
        result = await mod.fetch(ip, client)
    except BaseException as exc:  # noqa: BLE001 - contained per source, by design
        elapsed = int((time.perf_counter() - start) * 1000)
        log_source_call(name, ip, f"exception:{type(exc).__name__}", elapsed, False)
        return SourceResult(name, False, ERROR, {}, type(exc).__name__)
    elapsed = int((time.perf_counter() - start) * 1000)
    log_source_call(name, ip, result.state, elapsed, False)
    return result


async def fetch_sources(ip: str, client: httpx.AsyncClient) -> dict:
    """Fetch all five sources concurrently. Never raises; each failure is contained.
    Kept separate from assemble() so callers can run this concurrently with the
    existing IP fetchers (latency bounded by the slowest source, not the sum)."""
    results = await asyncio.gather(*(_timed_fetch(n, ip, client) for n in _NAMES))
    return {name: r.as_dict() for name, r in zip(_NAMES, results)}


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
