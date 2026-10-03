"""
RIPE Atlas: pick a probe near the user, run one traceroute, read the result.

WHAT THIS IS
------------
The primary way the Route Map tab gets a trace. FalconEye does not run
traceroutes itself; it asks a RIPE Atlas probe on the user's own network, or
failing that in their country, to run one. That is the only way to get a path
that starts where the user is rather than where this server is.

WHAT IS SENT TO RIPE, AND WHAT IS NOT
-------------------------------------
This matters enough to be the second thing in this file.

Sent:
  * the target the user typed, in the measurement definition
  * probe selection criteria: an AS number, or a two-letter country code

NOT sent:
  * the user's coordinates, ever.

The tab knows the user's position to about 10 km, and it would be the obvious
thing to hand RIPE a ``radius=<lat>,<lon>:50`` probe filter. It deliberately
does not. Probe selection goes by ASN first and country second, both derived
from the visitor's IP address server-side, and the "distance from you" figure
on the result is computed **here**, locally, from the probe's own published
coordinates and the user's coordinates, which never leave this process.

A measurement created here is PUBLIC. RIPE Atlas publishes one-off measurements
in its measurement database, including the target, the probe and the result.
The UI says so next to the button, and the privacy policy says so. Nothing in
this module can make that not true, which is exactly why the user is told
before they press it.

CREDITS
-------
Atlas measurements are paid for in credits: a traceroute costs 30 credits per
result, so one trace from one probe is 30. An account earns 15 credits a minute
per connected probe it hosts (about 21,600 a day) and new accounts can claim a
one-time 50,000. The balance is checked before every measurement, against both
the real account balance and this instance's own daily cap, because a budget
that is only enforced by the vendor is not a budget.
"""
from __future__ import annotations

import asyncio
import logging
import time

import httpx

from app.config import (ATLAS_API_KEY, ATLAS_BASE_URL, ATLAS_DAILY_CREDIT_CAP,
                        ATLAS_ENABLED, ATLAS_MEASUREMENT_TIMEOUT_SECONDS,
                        ATLAS_PROBE_CACHE_TTL_HOURS, OPERATOR_CONTACT_UA)
from app.utils import cache
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.routemap.atlas")

USER_AGENT = f"FalconEye/3.35 ({OPERATOR_CONTACT_UA}; Route Map)"

# What one traceroute costs, per RIPE's published credit table. Used for the
# pre-flight affordability check; RIPE's own accounting is authoritative.
TRACEROUTE_CREDITS_PER_RESULT = 30

# Spend recorded per UTC day, in the shared cache table, so the instance cap
# survives a restart and is shared across workers.
_SPEND_TABLE = "routemap_atlas_spend"

# Probe lists per ASN/country change slowly and a probe lookup is not the
# interesting part of the budget, so they are cached.
_PROBE_TABLE = "routemap_atlas_probes"


class AtlasUnavailable(Exception):
    """Atlas cannot serve this request. ``kind`` drives the UI's message."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind          # disabled | credits | noprobe | failed
        self.message = message


def init_tables() -> None:
    cache.init_table(_SPEND_TABLE, key_col="day")
    cache.init_table(_PROBE_TABLE, key_col="selector")


init_tables()


def configured() -> bool:
    return bool(ATLAS_ENABLED and ATLAS_API_KEY)


def _client() -> httpx.AsyncClient:
    """Authenticated: for reading the credit balance and scheduling a measurement."""
    return httpx.AsyncClient(
        base_url=ATLAS_BASE_URL,
        headers={"Authorization": f"Key {ATLAS_API_KEY}",
                 "User-Agent": USER_AGENT,
                 "Accept": "application/json"},
        timeout=20.0,
    )


def _public_client() -> httpx.AsyncClient:
    """Unauthenticated: for reading the results of a public measurement.

    A one-off Atlas measurement is public, so its results need no key, and the
    key this instance holds is deliberately scoped to credit info and
    scheduling only. Sending it on a request that does not need it would be
    both pointless and a wider exposure than the operation calls for.
    """
    return httpx.AsyncClient(
        base_url=ATLAS_BASE_URL,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        timeout=20.0,
    )


# ------------------------------------------------------------------ budget ---

def _today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def spent_today() -> int:
    row = cache.get(_SPEND_TABLE, _today(), 48, key_col="day")
    return int((row or {}).get("credits") or 0)


def record_spend(credits: int) -> None:
    day = _today()
    total = spent_today() + max(0, int(credits))
    cache.set(_SPEND_TABLE, day, {"credits": total}, key_col="day")


async def balance() -> int | None:
    """The account's current credit balance, or None if it cannot be read."""
    try:
        async with _client() as client:
            response = await client.get("/credits/")
    except Exception as exc:
        log.warning("atlas credit check failed: %s", exc)
        return None
    if response.status_code != 200:
        log.warning("atlas credit check returned %s", response.status_code)
        return None
    try:
        return int((response.json() or {}).get("current_balance"))
    except Exception:
        return None


async def check_budget() -> None:
    """Raise AtlasUnavailable unless one more traceroute is affordable.

    Two gates, and both have to pass. The instance cap is ours and is checked
    first because it costs no request; the account balance is RIPE's and is
    checked because the cap cannot know about spending from anywhere else.
    """
    if not configured():
        raise AtlasUnavailable(
            "disabled",
            "Atlas tracing is switched off on this instance.")

    used = spent_today()
    if used + TRACEROUTE_CREDITS_PER_RESULT > ATLAS_DAILY_CREDIT_CAP:
        raise AtlasUnavailable(
            "credits",
            f"This instance has reached its daily RIPE Atlas budget "
            f"({used}/{ATLAS_DAILY_CREDIT_CAP} credits).")

    current = await balance()
    if current is not None and current < TRACEROUTE_CREDITS_PER_RESULT:
        raise AtlasUnavailable(
            "credits", "The RIPE Atlas account has no credits left.")


# ------------------------------------------------------------------- probes --

async def _probes_for(selector: str, params: dict) -> list[dict]:
    cached = cache.get(_PROBE_TABLE, selector, ATLAS_PROBE_CACHE_TTL_HOURS,
                       key_col="selector")
    if cached is not None:
        return cached.get("probes") or []
    try:
        async with _client() as client:
            response = await client.get("/probes/", params=params)
    except Exception as exc:
        log.warning("atlas probe search failed for %s: %s", selector, exc)
        return []
    if response.status_code != 200:
        log.warning("atlas probe search returned %s for %s",
                    response.status_code, selector)
        return []
    try:
        results = (response.json() or {}).get("results") or []
    except Exception:
        return []

    probes = []
    for item in results:
        geometry = item.get("geometry") or {}
        coords = geometry.get("coordinates") or []
        lat = lon = None
        if len(coords) == 2:
            try:
                lon, lat = float(coords[0]), float(coords[1])
            except (TypeError, ValueError):
                lat = lon = None
        # A probe with no published coordinates is kept. It cannot be ranked by
        # distance, so it sorts last, but it is still a usable probe on the
        # right network: a software probe whose host left the location blank
        # (and whose country then reads "Unknown") must not be invisible.
        probes.append({
            "id": item.get("id"),
            "asn": item.get("asn_v4") or item.get("asn_v6"),
            "country": item.get("country_code"),
            "lat": lat, "lon": lon,
            "status": (item.get("status") or {}).get("name"),
        })
    cache.set(_PROBE_TABLE, selector, {"probes": probes}, key_col="selector")
    return probes


async def select_probe(asn: int | None, country: str | None,
                       origin: tuple[float, float] | None) -> dict:
    """The probe to trace from: the user's own network first, their country next.

    ``origin`` is used only to rank the candidates by distance, here, in this
    process. It is never sent to RIPE.
    """
    from app.routemap.geo import haversine_km

    # ASN first and coordinates second, never country alone: a probe can
    # legitimately report its country as "Unknown" (a software probe whose host
    # did not publish a location), and a country-led search would then miss the
    # one probe that is actually on the visitor's own network.
    candidates: list[dict] = []
    if asn:
        candidates = await _probes_for(
            f"asn:{asn}", {"asn_v4": asn, "status": 1, "page_size": 100})
    if not candidates and country:
        candidates = await _probes_for(
            f"cc:{country.upper()}",
            {"country_code": country.upper(), "status": 1, "page_size": 100})

    candidates = [p for p in candidates if p.get("id")]
    if not candidates:
        raise AtlasUnavailable(
            "noprobe",
            "No connected RIPE Atlas probe was found on your network or in "
            "your country, so a trace from Atlas would not describe your path.")

    if origin is not None:
        for probe in candidates:
            if probe.get("lat") is None or probe.get("lon") is None:
                probe["distance_km"] = None
                continue
            probe["distance_km"] = round(
                haversine_km(origin[0], origin[1], probe["lat"], probe["lon"]), 1)
        # Nearest first; unlocatable probes last rather than excluded.
        candidates.sort(key=lambda p: (p["distance_km"] is None,
                                       p["distance_km"] or 0.0))
    return candidates[0]


# -------------------------------------------------------------- measurement --

async def _create(client: httpx.AsyncClient, target: str, probe_id: int,
                  af: int) -> int:
    body = {
        "definitions": [{
            "type": "traceroute",
            "af": af,
            "target": target,
            "description": "FalconEye Route Map",
            "protocol": "ICMP",
            "resolve_on_probe": True,
            "paris": 0,
            "first_hop": 1,
            "max_hops": 30,
            # Three probes per hop, so the physics bound has a real minimum to
            # work from rather than a single sample.
            "packets": 3,
        }],
        "probes": [{"type": "probes", "value": str(probe_id), "requested": 1}],
        "is_oneoff": True,
    }
    response = await client.post("/measurements/", json=body)
    if response.status_code not in (200, 201):
        detail = ""
        try:
            detail = str((response.json() or {}).get("error") or "")[:200]
        except Exception:
            pass
        if response.status_code in (401, 403):
            # Both shapes arrive as 403, so the body decides. Nothing about the
            # key itself is logged or surfaced, only that it was refused.
            looks_like_credits = "credit" in detail.lower() or "balance" in detail.lower()
            if not looks_like_credits:
                log.error(
                    "RIPE Atlas refused the request as unauthorised (HTTP %s). The "
                    "API key is missing, wrong, lacks the schedule-measurement "
                    "permission, or has expired. Set a current ATLAS_API_KEY in "
                    ".env, or set ATLAS_ENABLED=false to stop offering Atlas traces.",
                    response.status_code)
                raise AtlasUnavailable(
                    "auth",
                    "This instance cannot schedule RIPE Atlas measurements right now.")
        if response.status_code in (402, 403):
            raise AtlasUnavailable(
                "credits",
                "RIPE Atlas refused the measurement, which usually means the "
                "account is out of credits.")
        raise AtlasUnavailable(
            "failed",
            f"RIPE Atlas refused the measurement (HTTP {response.status_code}). {detail}".strip())
    try:
        ids = (response.json() or {}).get("measurements") or []
        return int(ids[0])
    except Exception as exc:
        raise AtlasUnavailable("failed", "RIPE Atlas did not return a measurement id") from exc


async def _await_result(client: httpx.AsyncClient, measurement_id: int) -> list:
    """Poll until the one-off measurement has a result, or time out."""
    deadline = time.monotonic() + ATLAS_MEASUREMENT_TIMEOUT_SECONDS
    delay = 3.0
    while time.monotonic() < deadline:
        await asyncio.sleep(delay)
        delay = min(delay * 1.4, 10.0)
        try:
            response = await client.get(f"/measurements/{measurement_id}/results/")
        except Exception as exc:
            log.warning("atlas result poll failed for %s: %s", measurement_id, exc)
            continue
        if response.status_code != 200:
            continue
        try:
            results = response.json() or []
        except Exception:
            continue
        if results:
            return results
    raise AtlasUnavailable(
        "failed",
        "The Atlas measurement did not return a result in time.")


def to_trace_text(result: dict) -> str:
    """Render one Atlas traceroute result as Unix traceroute output.

    Deliberately rendered into text and fed through the same parser as a pasted
    trace, rather than converted straight into Hop objects. One parser, one set
    of fixtures, one place where a format bug can live. The cost is a render
    and a re-parse of a few kilobytes, which is nothing next to a second code
    path that drifts.
    """
    target = result.get("dst_name") or result.get("dst_addr") or "target"
    dst = result.get("dst_addr") or ""
    lines = [f"traceroute to {target} ({dst}), 30 hops max, 60 byte packets"]

    for hop in result.get("result") or []:
        number = hop.get("hop")
        if number is None:
            continue
        parts = []
        for probe in hop.get("result") or []:
            if "x" in probe or probe.get("x") == "*":
                parts.append("*")
                continue
            rtt = probe.get("rtt")
            addr = probe.get("from")
            if rtt is None or not addr:
                parts.append("*")
                continue
            name = probe.get("name")
            label = f"{name} ({addr})" if name and name != addr else addr
            parts.append(f"{label}  {float(rtt):.3f} ms")
        lines.append(f"{number:>2}  " + "  ".join(parts) if parts
                     else f"{number:>2}  * * *")
    return "\n".join(lines) + "\n"


async def start(target: str, asn: int | None, country: str | None,
                origin: tuple[float, float] | None, af: int = 4) -> dict:
    """Pick a probe and schedule the measurement. Fast, and safe in a request.

    Split out from waiting for the result in v3.35.1. Everything here is two
    short API calls; waiting is up to two minutes, which is longer than nginx
    (90s) and gunicorn (90s) will tolerate inside a request, and a worker killed
    mid-measurement takes every other request on it down with it.

    Returns ``{"probe": {...}, "measurement_id": int}`` and raises
    :class:`AtlasUnavailable` with a ``kind`` the UI maps onto a message.
    """
    await check_budget()
    probe = await select_probe(asn, country, origin)

    async with _client() as client:
        measurement_id = await _create(client, target, int(probe["id"]), af)
        # Recorded as spent the moment it is created, not when it succeeds: a
        # measurement that times out on our side has still cost the credits.
        record_spend(TRACEROUTE_CREDITS_PER_RESULT)
        log.info("event=atlas_measurement id=%s probe=%s target=%s",
                 measurement_id, probe.get("id"), tag(target))
    return {"probe": probe, "measurement_id": measurement_id}


async def collect_result(measurement_id: int) -> str:
    """Wait for a scheduled measurement and render it as traceroute text.

    Runs in the background, never in a request. Results are public, so this
    uses the keyless client.
    """
    async with _public_client() as public:
        results = await _await_result(public, measurement_id)
    return to_trace_text(results[0])
