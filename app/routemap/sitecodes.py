"""
Carrier site codes: the third geolocation source, offline and carrier-specific.

WHY THIS EXISTS
---------------
CAIDA Hoiho is the right first source, but its ruleset does not cover every
carrier. Measured on 2026-10-03 against ruleset 2024-08, it matched 0 of 5
Arelion/Twelve99 backbone hostnames, and the IP database is actively wrong for
exactly those routers: RIPEstat/MaxMind places 62.115.209.158, a router Arelion
itself names ``hnk-b4`` (Hong Kong), in Paris, and returns 0,0 for the
Singapore and Frankfurt ones. So on a Manila-to-Europe path, the two approved
sources between them could not place the Hong Kong, Singapore or Marseille
legs at all.

The information needed to place them is sitting in the hostname, published by
the carrier: Arelion's own looking glass says ``hnk-b4`` is "Hong Kong
(MEGA-i)". This module is that mapping, applied only to the carrier that
published it.

WHAT THIS IS NOT
----------------
It is not generic three-letter-code guessing. A hostname containing "sin" or
"lax" anywhere is not evidence of anything: ``lax`` appears in "relaxed" and
customer hostnames routinely contain city-ish fragments that mean nothing. So:

* a pattern applies only to hostnames under that carrier's own backbone
  namespace, and
* customer-facing namespaces are excluded, because a customer interconnect is
  named after the customer and not after the site. ``plusline-ic-323934.ip.
  twelve99-cust.net`` must not be read as a site code, and is not, because
  ``ip.twelve99-cust.net`` is excluded.
* a code that the carrier uses for two different cities is dropped at build
  time rather than guessed at (see ``ewr`` in tools/build_site_codes.py).

Every row records which published source it came from. See
app/routemap/data/README.md for how to add a carrier.

ORDER AND THE PHYSICS BOUND
---------------------------
Hoiho first, then this, then the IP database. A site-code location is a claim
like any other and goes through the same RTT check in app/routemap/geo.py: if
the hostname says Hong Kong but the round trip cannot reach Hong Kong, the hop
is not placed in Hong Kong.
"""
from __future__ import annotations

import pathlib
import re
import threading

DATA_FILE = pathlib.Path(__file__).resolve().parent / "data" / "site_codes.tsv"

SOURCE = "site-code"

# How a carrier's backbone hostnames are read. One entry per carrier, and the
# namespaces are deliberately narrow.
#
#   suffixes  hostnames under these zones may carry a site code
#   exclude   zones inside those that must NOT be read (customer interconnects)
#   code_of   leftmost label -> candidate site code
CARRIERS = {
    "arelion": {
        "name": "Arelion (AS1299, Twelve99)",
        # Verified against a real captured trace: hnk-b3-link.ip.twelve99.net,
        # which Arelion's looking glass lists as hnk-b3 "Hong Kong (Equinix HK1)".
        "suffixes": (".ip.twelve99.net",),
        # Customer interconnects: named for the customer, never for the site.
        "exclude": (".ip.twelve99-cust.net",),
        # "hnk-b4-link" -> "hnk", "ffm-bb2-link" -> "ffm".
        "code_of": lambda label: label.split("-", 1)[0],
    },
}

_lock = threading.Lock()
_table: dict | None = None


def _load() -> dict:
    """(carrier, code) -> {city, cc, lat, lon, source_ref}."""
    table: dict = {}
    if not DATA_FILE.exists():  # pragma: no cover - the file ships with the repo
        return table
    with DATA_FILE.open(encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 7:
                continue
            carrier, code, city, cc, lat, lon, source_ref = parts
            try:
                lat_f, lon_f = float(lat), float(lon)
            except ValueError:
                continue
            table[(carrier, code.lower())] = {
                "city": city, "cc": cc, "lat": lat_f, "lon": lon_f,
                "source_ref": source_ref,
            }
    return table


def table() -> dict:
    global _table
    if _table is None:
        with _lock:
            if _table is None:
                _table = _load()
    return _table


def count() -> int:
    return len(table())


def lookup(hostname: str) -> dict | None:
    """Locate *hostname* from its carrier's site code, or None.

    Returns ``{lat, lon, place, cc, carrier, code, source_ref}``. None means
    "this carrier does not name this hostname after a site I know", which is
    the normal answer for most hostnames on the internet.
    """
    name = (hostname or "").strip().strip(".").lower()
    if not name:
        return None

    for carrier_id, spec in CARRIERS.items():
        if any(name.endswith(zone) for zone in spec["exclude"]):
            continue
        suffix = next((z for z in spec["suffixes"] if name.endswith(z)), None)
        if suffix is None:
            continue
        label = name[: -len(suffix)].split(".")[-1]
        if not label:
            continue
        code = spec["code_of"](label)
        if not re.fullmatch(r"[a-z]{2,6}", code or ""):
            continue
        entry = table().get((carrier_id, code))
        if not entry:
            continue
        return {
            "lat": entry["lat"], "lon": entry["lon"],
            "place": f"{entry['city']}, {entry['cc']}" if entry["cc"] else entry["city"],
            "cc": entry["cc"],
            "carrier": spec["name"],
            "code": code,
            "source_ref": entry["source_ref"],
        }
    return None
