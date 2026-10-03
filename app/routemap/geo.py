"""
Per-hop geolocation, the RTT physics bound, and the hop annotations.

THE PROBLEM THIS SOLVES
-----------------------
Drawing a traceroute on a map by feeding each hop to an IP geolocation
database produces a path that crosses oceans it did not cross. The reason is
not that the databases are bad; it is that a backbone router's address is
registered wherever its operator filed the prefix. A Tata router in the middle
of a Manila-to-California path geolocates to whatever country Tata registered
that block in, and the map then shows the packet detouring through it.

Two defences, in this order:

1. Ask the router's hostname first (``app/routemap/hoiho.py``). The carrier's
   own naming scheme is better evidence than a registry entry.
2. Check every candidate location against the speed of light. A location that
   cannot be reached and returned from inside the measured RTT is wrong, no
   matter which source said it, so it is rejected and the next source is tried.

THE BOUND
---------
Light in fibre travels about 200 km per millisecond (c times a refractive index
of roughly 1.47, so about 204 km/ms; 200 is the round number everybody uses).
An RTT is a round trip, so the distance a hop can be away is at most

    max_km = min_rtt_ms * 200 / 2 = min_rtt_ms * 100

:data:`KM_PER_MS_ROUND_TRIP` is that 100.

Three properties of this bound matter, and getting any of them wrong turns a
sanity check into a source of false rejections:

* It is an **upper** limit only. Real paths are longer than the great circle,
  routers add processing delay, and queueing and asymmetric return paths inflate
  RTTs routinely. A hop whose RTT is far larger than the distance needs is
  normal and is never rejected for it. Only the impossible direction is checked.
* It is measured against the **minimum** RTT of the hop's probes, because the
  floor of several samples is the closest thing to propagation delay. Using the
  average would reject real locations on a congested path.
* It is applied with a tolerance (:data:`SLACK_KM`), because the origin itself
  is only known to city level and the first hop of a trace legitimately reports
  0.0 ms. Without it, a 0.2 ms LAN hop would "prove" that every location on
  earth is impossible.

ANNOTATIONS
-----------
The three things an investigator reading a trace has to know not to
misinterpret, each stated rather than left as a surprising number:

* An RTT that falls at the *next* hop means the inflated hop's reply took a
  different way back, not that the packet went somewhere and came back. Labelled
  as an asymmetric return path, and the hop is not moved on the map.
* Loss at a middle hop with no loss after it is the router rate-limiting its own
  ICMP replies, not packets being dropped. It is the single most common
  misreading of a traceroute.
* A tail of hops that never answer is the destination or its firewall declining
  ICMP, which is not a broken path.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import math

import dns.resolver
import dns.reversename
import httpx

from app.config import HTTPX_TIMEOUT, OPERATOR_CONTACT_UA
from app.routemap import hoiho, sitecodes
from app.routemap.parse import Hop, is_routable_hostname
from app.utils.logsafe import tag
from app.utils.safe_fetch import is_private_ip

log = logging.getLogger("falconeye.routemap.geo")

USER_AGENT = f"FalconEye/3.35 ({OPERATOR_CONTACT_UA}; traceroute geolocation)"

# Half of ~200 km/ms in fibre, because an RTT is a round trip. See the module
# docstring for the derivation and for why it is an upper bound only.
KM_PER_MS_ROUND_TRIP = 100.0
# Tolerance on the bound: the origin is a city, not a point, and a sub-millisecond
# first hop is a real measurement that must not be allowed to rule out the world.
SLACK_KM = 300.0

# Source labels. These are the contract with the frontend and the MCP tool.
SOURCE_HOIHO = "hoiho"
SOURCE_SITE_CODE = sitecodes.SOURCE   # "site-code"
SOURCE_IP_DB = "ip-db"
SOURCE_LOCAL = "local"
SOURCE_UNRESOLVED = "unresolved"

RIPESTAT_GEO = "https://stat.ripe.net/data/maxmind-geo-lite/data.json"
# Bounded fan-out: a 30-hop trace must not open 30 sockets to RIPEstat at once.
IP_DB_CONCURRENCY = 6

# Annotation thresholds. A hop has to be inflated by BOTH an absolute margin and
# a ratio before it is called out, so a 2 ms wobble on a 1 ms LAN hop and a
# 5 ms wobble on a 200 ms transpacific hop are both left alone.
INFLATION_ABS_MS = 25.0
INFLATION_FACTOR = 1.4

# Hard ceilings on each external source, independent of that source's own
# per-request timeout. A client timeout bounds one call; these bound the source.
# Hoiho batches a whole trace into one request, the IP database makes one
# request per address at concurrency 6, and PTR is 40 lookups at concurrency 8,
# so each gets the time its shape needs and no more.
#
# A source that runs out of time contributes nothing and the hops it would have
# placed are reported unresolved. It never fails the trace: the whole point of
# having three sources is that losing one is survivable.
HOIHO_BUDGET_SECONDS = 15.0
IP_DB_BUDGET_SECONDS = 20.0
REVERSE_DNS_BUDGET_SECONDS = 12.0

ANNOT_LOCAL = "local / ISP internal"
ANNOT_RTT_IMPOSSIBLE = "location impossible for RTT"
ANNOT_ASYMMETRIC = "likely asymmetric return path"
ANNOT_ICMP_LIMIT = "ICMP rate limiting, not real loss"
ANNOT_NO_ICMP = "destination or path does not answer ICMP"


# ------------------------------------------------------------------ geometry ---

def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres.

    The great circle is the *shortest* path between two points, so using it for
    an upper bound is the conservative direction: a real fibre route is longer,
    which can only make a location harder to reach, never easier. A bound built
    on the shortest possible path therefore never rejects a location the light
    could have reached.
    """
    radius_km = 6371.0088
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = phi2 - phi1
    d_lambda = math.radians(lon2 - lon1)
    a = (math.sin(d_phi / 2) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2)
    return 2 * radius_km * math.asin(min(1.0, math.sqrt(a)))


# Coordinates a geolocation database returns when it means "no idea".
#
# 0,0 is the big one: RIPEstat/MaxMind answered 0.0,0.0 for three of the
# Arelion hops in the v3.35.0 fixtures. That point is in the Gulf of Guinea,
# and treating it as a location would put routers in the ocean off Ghana, which
# is precisely the class of confident-but-wrong placement this tab exists to
# stop. The others are the centroids some databases return for a country or for
# the planet when they can only narrow it that far; they are real places, but
# as an answer about a specific router they mean "unknown".
_SENTINEL_COORDS = {
    (0.0, 0.0),        # null island: "no data" from almost every geolocation DB
    (38.0, -97.0),     # MaxMind's historical centre-of-the-US fallback
    (37.751, -97.822), # its later, more precise centre-of-the-US fallback
}
# How close counts as "that sentinel". Tight: a real router can legitimately be
# a few kilometres from any of these, and only the exact fallback value is the
# one that means nothing.
_SENTINEL_TOLERANCE = 0.01


def is_sentinel(lat: float, lon: float) -> bool:
    """Whether (lat, lon) is a database's way of saying it does not know."""
    return any(abs(lat - s_lat) <= _SENTINEL_TOLERANCE
               and abs(lon - s_lon) <= _SENTINEL_TOLERANCE
               for s_lat, s_lon in _SENTINEL_COORDS)


def max_distance_km(min_rtt_ms: float) -> float:
    """The furthest a hop answering in *min_rtt_ms* can be from the origin."""
    return max(0.0, float(min_rtt_ms)) * KM_PER_MS_ROUND_TRIP + SLACK_KM


def rtt_allows(origin: tuple[float, float] | None, lat: float, lon: float,
               min_rtt_ms: float | None) -> tuple[bool, float | None, float | None]:
    """Whether a location is reachable inside the measured RTT.

    Returns ``(allowed, distance_km, budget_km)``. Unknowable cases allow:
    with no origin or no RTT sample there is nothing to contradict, and
    inventing a rejection from missing data would be worse than drawing the
    hop. The caller renders ``distance_km`` either way, so an operator can see
    the margin on a hop that passed.
    """
    if origin is None or min_rtt_ms is None:
        return True, None, None
    distance = haversine_km(origin[0], origin[1], lat, lon)
    budget = max_distance_km(min_rtt_ms)
    return distance <= budget, round(distance, 1), round(budget, 1)


# --------------------------------------------------------------- classifying ---

def classify_address(addr: str) -> str:
    """"local" for an address that is not routable on the public internet.

    Delegates to ``safe_fetch.is_private_ip``, which is the codebase's one
    answer to this question and already covers the ranges the stdlib flags
    miss: CGNAT (100.64.0.0/10), 0.0.0.0/8 and the NAT64 prefix. CGNAT matters
    here specifically, because a carrier-NAT hop is the second or third hop of
    most consumer traces and geolocating it would place the operator's own ISP
    wherever the carrier registered that block.
    """
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        return SOURCE_UNRESOLVED
    return SOURCE_LOCAL if is_private_ip(addr) else "public"


# ------------------------------------------------------------- the IP source ---

async def _ip_geolocate_one(client: httpx.AsyncClient, semaphore: asyncio.Semaphore,
                            addr: str) -> dict | None:
    """One address through RIPEstat's MaxMind GeoLite view.

    The same upstream the IP Reputation tab already uses (see fetch_ripestat in
    app/routers/ip_intel.py), deliberately: the brief is to reuse the IP
    geolocation this instance already has rather than add a provider, and
    RIPEstat is free, keyless and already a declared third party in the privacy
    policy. Never raises.
    """
    async with semaphore:
        try:
            response = await client.get(
                RIPESTAT_GEO, params={"resource": addr}, timeout=HTTPX_TIMEOUT,
                headers={"User-Agent": USER_AGENT})
        except Exception as exc:
            log.warning("ip geolocation exception for %s: %s", tag(addr), exc)
            return None
    if response.status_code != 200:
        return None
    try:
        body = response.json()
    except Exception:
        return None
    located = ((body.get("data") or {}).get("located_resources") or [])
    if not located:
        return None
    locations = located[0].get("locations") or []
    if not locations:
        return None
    first = locations[0]
    try:
        lat = float(first["latitude"])
        lon = float(first["longitude"])
    except (KeyError, TypeError, ValueError):
        return None
    if math.isnan(lat) or math.isnan(lon):
        return None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None
    if is_sentinel(lat, lon):
        # Not an answer. Returning None here is what lets the hop fall through
        # to being reported as unplaced rather than drawn in the Gulf of Guinea.
        log.info("event=ip_geo_sentinel addr=%s lat=%s lon=%s", tag(addr), lat, lon)
        return None
    return {"lat": lat, "lon": lon,
            "city": first.get("city") or None,
            "cc": first.get("country") or None}


async def ip_geolocate(addresses: list[str]) -> dict:
    """Geolocate several public addresses at once. Never raises."""
    wanted = [a for a in dict.fromkeys(addresses) if a]
    if not wanted:
        return {}
    semaphore = asyncio.Semaphore(IP_DB_CONCURRENCY)
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            *[_ip_geolocate_one(client, semaphore, addr) for addr in wanted],
            return_exceptions=True)
    out = {}
    for addr, result in zip(wanted, results):
        if isinstance(result, dict):
            out[addr] = result
    return out


# ------------------------------------------------------------ reverse DNS ---
#
# WHY THIS EXISTS, AND WHY IT IS NOT OPTIONAL
#
# The whole tab is built on the router's hostname being better evidence than
# its address. A local traceroute hands us those hostnames because the
# traceroute binary resolves them itself. RIPE Atlas does not: a hop in an
# Atlas result carries an address and nothing else.
#
# Found by running the first live trace to heise.de. Every hostname column was
# empty, so Hoiho and the site-code table had nothing to work on, every hop
# fell back to the IP database, and the Marseille router came out as "FR" while
# the Singapore and Paris hops came out unplaced. The headline feature was
# silently inert on the primary path.
#
# So any hop that has a public address and no name gets one here. This also
# fixes the same gap for a pasted "traceroute -n" or "tracert -d", where the
# user asked their own tool not to resolve.
#
# Bounded and best effort: a resolver that is slow or unhappy costs the trace a
# few hundred milliseconds and some hostnames, never the result.
REVERSE_DNS_CONCURRENCY = 8
REVERSE_DNS_TIMEOUT = 2.0
# One trace is at most 30 hops. The cap is here so a pasted trace cannot turn
# into an unbounded fan-out of DNS queries.
REVERSE_DNS_MAX = 40


def _ptr_sync(addr: str) -> str | None:
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = REVERSE_DNS_TIMEOUT
        resolver.timeout = REVERSE_DNS_TIMEOUT
        answer = resolver.resolve(dns.reversename.from_address(addr), "PTR")
        for record in answer:
            name = str(record).rstrip(".")
            if name:
                return name
    except Exception:
        return None
    return None


async def reverse_dns(addresses: list[str]) -> dict:
    """PTR names for public addresses. Never raises, never blocks for long."""
    wanted = [a for a in dict.fromkeys(addresses) if a][:REVERSE_DNS_MAX]
    if not wanted:
        return {}
    semaphore = asyncio.Semaphore(REVERSE_DNS_CONCURRENCY)
    loop = asyncio.get_event_loop()

    async def one(addr: str):
        async with semaphore:
            return await loop.run_in_executor(None, _ptr_sync, addr)

    results = await asyncio.gather(*[one(a) for a in wanted],
                                   return_exceptions=True)
    return {addr: name for addr, name in zip(wanted, results)
            if isinstance(name, str) and name}


# --------------------------------------------------------------- place naming ---

def _hoiho_place(record: dict) -> str | None:
    parts = [p for p in (record.get("place"), record.get("st"), record.get("cc")) if p]
    return ", ".join(parts) if parts else None


def _ip_place(record: dict) -> str | None:
    parts = [p for p in (record.get("city"), record.get("cc")) if p]
    return ", ".join(parts) if parts else None


# ------------------------------------------------------------------ the pass ---

def _blank_location(hop: Hop) -> dict:
    return {
        "hop": hop.hop,
        "addresses": list(hop.addresses),
        "address": hop.addresses[0] if hop.addresses else None,
        "hostnames": list(hop.hostnames),
        "hostname": hop.hostnames[0] if hop.hostnames else None,
        "min_rtt_ms": hop.min_rtt_ms,
        "avg_rtt_ms": hop.avg_rtt_ms,
        "sent": hop.sent,
        "lost": hop.lost,
        "loss_pct": hop.loss_pct,
        "codes": list(hop.codes),
        "source": SOURCE_UNRESOLVED,
        "lat": None,
        "lon": None,
        "place": None,
        "cc": None,
        "distance_km": None,
        "rtt_budget_km": None,
        "annotations": [],
        "reason": None,
        # Every candidate that was considered and what happened to it, so a
        # rejection is auditable rather than a hop that silently vanished.
        "candidates": [],
    }


def _reject_reason(distance: float | None, budget: float | None) -> str:
    if distance is None or budget is None:
        return ANNOT_RTT_IMPOSSIBLE
    return (f"{ANNOT_RTT_IMPOSSIBLE}: {distance:,.0f} km away but the round trip "
            f"allows at most {budget:,.0f} km")


def locate_hops(hops: list[Hop], hoiho_records: dict, ip_records: dict,
                origin: tuple[float, float] | None) -> list[dict]:
    """Resolve every hop to a location, source and set of annotations.

    Pure: every upstream answer is passed in, so this is the function the tests
    drive directly and the one that holds the ordering rule (hostname, then IP
    database, then nothing) and the physics bound.
    """
    located: list[dict] = []

    for hop in hops:
        entry = _blank_location(hop)

        if not hop.addresses and not hop.hostnames:
            entry["reason"] = "the hop did not answer, so there is nothing to locate"
            located.append(entry)
            continue

        # A private, CGNAT or otherwise non-routable hop is placed at the origin
        # and nothing is queried about it: it is inside the operator's own house
        # or their ISP's, we already know where that is, and asking a third
        # party would be asking about the operator's own network.
        classes = {classify_address(a) for a in hop.addresses}
        if hop.addresses and classes == {SOURCE_LOCAL}:
            entry["source"] = SOURCE_LOCAL
            entry["annotations"] = [ANNOT_LOCAL]
            entry["place"] = ANNOT_LOCAL
            if origin is not None:
                entry["lat"], entry["lon"] = origin
            entry["reason"] = "private, CGNAT or reserved address, not geolocated"
            located.append(entry)
            continue

        public = [a for a in hop.addresses if classify_address(a) == "public"]

        # ---- source 1: the router hostname, via Hoiho
        for hostname in hop.hostnames:
            if not is_routable_hostname(hostname):
                continue
            record = hoiho_records.get(hostname)
            if not record or not record.get("located"):
                entry["candidates"].append({
                    "source": SOURCE_HOIHO, "hostname": hostname,
                    "accepted": False,
                    "why": "no Hoiho rule matched this hostname"
                           if record is not None else "Hoiho did not answer",
                })
                continue
            lat, lon = record["lat"], record["lng"]
            allowed, distance, budget = rtt_allows(origin, lat, lon, hop.min_rtt_ms)
            candidate = {"source": SOURCE_HOIHO, "hostname": hostname,
                         "place": _hoiho_place(record), "lat": lat, "lon": lon,
                         "distance_km": distance, "rtt_budget_km": budget,
                         "accepted": allowed,
                         "match_strs": record.get("match_strs") or [],
                         "match_meanings": record.get("match_meanings") or []}
            if not allowed:
                candidate["why"] = _reject_reason(distance, budget)
                entry["candidates"].append(candidate)
                continue
            entry["candidates"].append(candidate)
            entry.update({
                "source": SOURCE_HOIHO, "lat": lat, "lon": lon,
                "place": _hoiho_place(record), "cc": record.get("cc"),
                "distance_km": distance, "rtt_budget_km": budget,
                "match_strs": record.get("match_strs") or [],
                "match_meanings": record.get("match_meanings") or [],
            })
            break

        # ---- source 2: the carrier's own site code in the hostname
        #
        # Between Hoiho and the IP database, because it is the carrier naming
        # its own site, which beats a registry entry; and after Hoiho, because
        # Hoiho is the broader, externally validated ruleset and this table is
        # a handful of carriers.
        if entry["source"] == SOURCE_UNRESOLVED:
            for hostname in hop.hostnames:
                if not is_routable_hostname(hostname):
                    continue
                record = sitecodes.lookup(hostname)
                if not record:
                    continue
                lat, lon = record["lat"], record["lon"]
                allowed, distance, budget = rtt_allows(origin, lat, lon, hop.min_rtt_ms)
                candidate = {"source": SOURCE_SITE_CODE, "hostname": hostname,
                             "place": record["place"], "lat": lat, "lon": lon,
                             "distance_km": distance, "rtt_budget_km": budget,
                             "accepted": allowed, "carrier": record["carrier"],
                             "code": record["code"], "source_ref": record["source_ref"]}
                if not allowed:
                    candidate["why"] = _reject_reason(distance, budget)
                    entry["candidates"].append(candidate)
                    continue
                entry["candidates"].append(candidate)
                entry.update({
                    "source": SOURCE_SITE_CODE, "lat": lat, "lon": lon,
                    "place": record["place"], "cc": record["cc"],
                    "distance_km": distance, "rtt_budget_km": budget,
                    "carrier": record["carrier"], "site_code": record["code"],
                    "source_ref": record["source_ref"],
                })
                break

        # ---- source 3: the IP geolocation database
        if entry["source"] == SOURCE_UNRESOLVED:
            for addr in public:
                record = ip_records.get(addr)
                if not record:
                    entry["candidates"].append({
                        "source": SOURCE_IP_DB, "address": addr, "accepted": False,
                        "why": "the IP geolocation database has no location for this address",
                    })
                    continue
                lat, lon = record["lat"], record["lon"]
                allowed, distance, budget = rtt_allows(origin, lat, lon, hop.min_rtt_ms)
                candidate = {"source": SOURCE_IP_DB, "address": addr,
                             "place": _ip_place(record), "lat": lat, "lon": lon,
                             "distance_km": distance, "rtt_budget_km": budget,
                             "accepted": allowed}
                if not allowed:
                    candidate["why"] = _reject_reason(distance, budget)
                    entry["candidates"].append(candidate)
                    continue
                entry["candidates"].append(candidate)
                entry.update({
                    "source": SOURCE_IP_DB, "lat": lat, "lon": lon,
                    "place": _ip_place(record), "cc": record.get("cc"),
                    "distance_km": distance, "rtt_budget_km": budget,
                })
                break

        # ---- nothing survived
        if entry["source"] == SOURCE_UNRESOLVED:
            rejected = [c for c in entry["candidates"] if not c.get("accepted")]
            impossible = [c for c in rejected if ANNOT_RTT_IMPOSSIBLE in (c.get("why") or "")]
            if impossible:
                entry["annotations"] = [ANNOT_RTT_IMPOSSIBLE]
                entry["reason"] = impossible[0]["why"]
            elif rejected:
                entry["reason"] = rejected[0]["why"]
            else:
                entry["reason"] = "no hostname rule and no IP database entry"

        located.append(entry)

    return located


# ----------------------------------------------------------------- annotating ---

def annotate(located: list[dict]) -> list[dict]:
    """Add the three read-this-correctly annotations, in place.

    Reads only what :func:`locate_hops` produced, so it is independently
    testable and cannot accidentally depend on an upstream.
    """
    count = len(located)

    for index, entry in enumerate(located):
        rtt = entry.get("min_rtt_ms")

        # ---- RTT inflation, versus the following hop.
        #
        # A hop slower than the hop *behind* it has not moved: the packet got
        # further in less time afterwards, which can only mean this hop's own
        # reply came back a different way. The hop is annotated and left exactly
        # where it was placed, because the inflation is in the return path and
        # says nothing about where the router is.
        if rtt is not None:
            following = next((located[j].get("min_rtt_ms")
                              for j in range(index + 1, count)
                              if located[j].get("min_rtt_ms") is not None), None)
            if (following is not None
                    and rtt > following + INFLATION_ABS_MS
                    and rtt > following * INFLATION_FACTOR):
                _add(entry, ANNOT_ASYMMETRIC,
                     f"{rtt:.1f} ms here but {following:.1f} ms at a later hop")

            # ---- a sharp jump against the previous hop in the same place.
            previous = located[index - 1] if index else None
            if (previous is not None
                    and previous.get("min_rtt_ms") is not None
                    and previous.get("place")
                    and previous.get("place") == entry.get("place")
                    and rtt > previous["min_rtt_ms"] + INFLATION_ABS_MS
                    and rtt > previous["min_rtt_ms"] * INFLATION_FACTOR):
                _add(entry, ANNOT_ASYMMETRIC,
                     f"{rtt:.1f} ms against {previous['min_rtt_ms']:.1f} ms at the "
                     f"previous hop in the same location")

        # ---- loss here, less of it later: the router is rate-limiting its own
        # replies rather than dropping traffic.
        #
        # The test is against the BEST later hop, not against all of them. If
        # any hop further down the path answered with less loss, then packets
        # were getting through this one, so the loss measured here is the
        # router declining to answer and not the path dropping traffic. An
        # earlier version required every later hop to be clean, which missed
        # the common case of two rate-limiting routers on one path: each one
        # hid the other.
        #
        # A hop at 100% loss did not answer at all and is not evidence about
        # the path, so it is excluded from the comparison.
        loss = entry.get("loss_pct")
        if loss and loss < 100.0:
            later = [located[j].get("loss_pct") for j in range(index + 1, count)]
            answered_later = [l for l in later if l is not None and l < 100.0]
            if answered_later and min(answered_later) < loss:
                best = min(answered_later)
                _add(entry, ANNOT_ICMP_LIMIT,
                     f"{loss:.0f}% loss here but only {best:.0f}% at a later hop, "
                     f"so the packets were getting through")

    # ---- a tail that never answers.
    #
    # Scanned from the end so it marks the run of silent hops rather than every
    # unanswered hop in the middle of the trace, which is a different thing (a
    # router that does not send time-exceeded at all, with the path continuing
    # right through it).
    tail_start = count
    while tail_start > 0:
        candidate = located[tail_start - 1]
        if candidate.get("loss_pct") == 100.0 or not candidate.get("addresses"):
            tail_start -= 1
            continue
        break
    if tail_start < count:
        for entry in located[tail_start:]:
            _add(entry, ANNOT_NO_ICMP,
                 "the last hops of the trace never replied, so the destination "
                 "or something in front of it is not answering ICMP")

    return located


def _add(entry: dict, label: str, detail: str) -> None:
    if label not in entry["annotations"]:
        entry["annotations"].append(label)
    notes = entry.setdefault("annotation_details", [])
    note = f"{label}: {detail}"
    if note not in notes:
        notes.append(note)


# -------------------------------------------------------------- the whole run ---

async def _within(budget: float, coro, label: str, fallback):
    """Run *coro* under a hard ceiling. On timeout, return *fallback*.

    Wrapping rather than trusting each client's own timeout: a client timeout
    applies per request, and a source that makes several requests can still run
    long enough to outlive nginx and have its worker killed mid-response. That
    is what produced the 502 in v3.35.0.
    """
    try:
        return await asyncio.wait_for(coro, timeout=budget)
    except asyncio.TimeoutError:
        log.warning("event=routemap_source_timeout source=%s budget=%.0fs; "
                    "its hops are reported unresolved", label, budget)
        return fallback
    except Exception as exc:
        log.warning("event=routemap_source_failed source=%s error=%s", label, exc)
        return fallback


async def resolve(hops: list[Hop], origin: tuple[float, float] | None) -> dict:
    """Locate and annotate a parsed trace. The one entry point.

    Hoiho and the IP database are asked concurrently for everything that could
    need them, then :func:`locate_hops` decides per hop which answer to use.
    Asking both up front costs one extra IP lookup for a hop the hostname
    already placed, and buys the fallback being available the moment the
    physics bound rejects a hostname location, instead of a second round trip
    in the middle of the decision.
    """
    # Fill in the names the source did not give us, so the hostname-first
    # sources have something to work on. Atlas results carry no names at all,
    # and "traceroute -n" was asked not to produce them.
    unnamed = [addr for hop in hops if not hop.hostnames
               for addr in hop.addresses if classify_address(addr) == "public"]
    if unnamed:
        resolved = await _within(REVERSE_DNS_BUDGET_SECONDS,
                                 reverse_dns(unnamed), "reverse-dns", {})
        if resolved:
            for hop in hops:
                if hop.hostnames:
                    continue
                for addr in hop.addresses:
                    name = resolved.get(addr)
                    if name:
                        hop.add_hostname(name)
            log.info("event=routemap_reverse_dns asked=%d resolved=%d",
                     len(set(unnamed)), len(resolved))

    hostnames, addresses = [], []
    for hop in hops:
        for name in hop.hostnames:
            if is_routable_hostname(name):
                hostnames.append(name)
        for addr in hop.addresses:
            if classify_address(addr) == "public":
                addresses.append(addr)

    # Both sources at once, each under its own ceiling, neither able to hold
    # the trace open past it.
    hoiho_result, ip_records = await asyncio.gather(
        _within(HOIHO_BUDGET_SECONDS, hoiho.lookup(hostnames), "hoiho", ({}, None)),
        _within(IP_DB_BUDGET_SECONDS, ip_geolocate(addresses), "ip-db", {}),
    )
    hoiho_records, ruleset = hoiho_result if isinstance(hoiho_result, tuple) else ({}, None)
    if not isinstance(ip_records, dict):
        ip_records = {}

    located = annotate(locate_hops(hops, hoiho_records, ip_records, origin))
    return {"hops": located, "hoiho_ruleset_date": ruleset}


def first_located(located: list[dict]) -> tuple[float, float] | None:
    """The first hop with a public location, as an anchor of last resort.

    Used only when a caller supplies no origin at all, which in practice means
    the MCP tool or a scripted request: the browser tab will not draw a map
    without one. Deliberately NOT the server's own location, which would be a
    confident lie about where the trace started.
    """
    for entry in located:
        if entry.get("source") in (SOURCE_HOIHO, SOURCE_SITE_CODE, SOURCE_IP_DB) \
                and entry.get("lat") is not None:
            return (entry["lat"], entry["lon"])
    return None
