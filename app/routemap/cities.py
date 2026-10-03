"""
The bundled offline city list, for the Route Map origin picker.

WHAT IT IS AND WHERE IT CAME FROM
---------------------------------
``app/routemap/data/cities.tsv`` is GeoNames' ``cities15000`` dump (every
populated place above 15,000 people, 34,152 rows), trimmed to the seven columns
this feature uses and with the coordinates rounded to two decimal places.

Licence, checked against https://download.geonames.org/export/dump/readme.txt
on 2026-10-03, which states: "This work is licensed under a Creative Commons
Attribution 4.0 License, see https://creativecommons.org/licenses/by/4.0/".
CC BY 4.0 permits redistribution and modification, including commercially, on
condition of attribution. The attribution is carried in three places so it
cannot be lost by touching only one of them: the header of the data file, the
data-sources strip in the page footer, and the Acknowledgments section of the
README.

WHY IT IS BUNDLED AND NOT A SERVICE
-----------------------------------
The thing being resolved is the visitor's own location. Typing "Manila" into a
geocoding API to find out where Manila is would mean telling a third party where
the visitor is, to answer a question that has a fixed answer. A file in the
repository answers it with no request leaving the box.

MEMORY, AND WHY THE LOAD IS LAZY
--------------------------------
Parsed, the table is roughly 9 MB of Python objects per worker, which on a
1 GB box with three workers is not free. It is therefore loaded on the first
search and not at import: a worker that never serves the origin picker never
pays for it, which on an instance where nobody opens the Route Map tab is every
worker. :func:`loaded` exists so a test can assert that property rather than
trust this comment.
"""
from __future__ import annotations

import pathlib
import re
import threading
import unicodedata

DATA_FILE = pathlib.Path(__file__).resolve().parent / "data" / "cities.tsv"

ATTRIBUTION = ("City list from GeoNames (cities15000), used under "
               "Creative Commons Attribution 4.0.")
ATTRIBUTION_URL = "https://www.geonames.org/"
LICENCE_URL = "https://creativecommons.org/licenses/by/4.0/"

# How many rows one search may return. The picker shows a short list; a query
# like "san" matches hundreds and nobody scrolls them.
MAX_RESULTS = 12

_lock = threading.Lock()
_rows: list[tuple] | None = None


def _fold(text: str) -> str:
    """Match key: accents stripped, lowercased, non-alphanumerics removed.

    So "Sao Paulo" finds "Sao Paulo", and "ho chi minh" finds
    "Ho Chi Minh City" through the prefix rule below.
    """
    decomposed = unicodedata.normalize("NFKD", text or "")
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", "", stripped.lower())


def _load() -> list[tuple]:
    """Parse the TSV into (key, name, cc, admin1, lat, lon, population).

    The file is sorted by population descending when it is generated, so the
    search can keep first-seen order and get "most likely city first" without
    sorting 34,000 rows per query.
    """
    rows: list[tuple] = []
    with DATA_FILE.open(encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 7:
                continue
            name, ascii_name, cc, admin1, lat, lon, population = parts
            try:
                lat_f, lon_f, pop_i = float(lat), float(lon), int(population or 0)
            except ValueError:
                continue
            key = _fold(name)
            rows.append((key, name, cc, admin1, lat_f, lon_f, pop_i))
            # A separate key for the ASCII spelling, where GeoNames gives one
            # that differs, so a keyboard without diacritics still finds the
            # city ("sao paulo" -> "Sao Paulo" -> "Sao Paulo"). Note this is
            # transliteration only: the dump's alternate-names column, which is
            # where an exonym like "Kiev" for "Kyiv" lives, is not bundled.
            ascii_key = _fold(ascii_name) if ascii_name else ""
            if ascii_key and ascii_key != key:
                rows.append((ascii_key, name, cc, admin1, lat_f, lon_f, pop_i))
    return rows


def _table() -> list[tuple]:
    global _rows
    if _rows is None:
        with _lock:
            if _rows is None:
                _rows = _load()
    return _rows


def loaded() -> bool:
    """Whether the table is resident in this process yet."""
    return _rows is not None


def display(name: str, cc: str, admin1: str) -> str:
    """How a city is labelled in the UI: "San Jose, CA, US", "Manila, PH"."""
    parts = [name]
    if admin1:
        parts.append(admin1)
    if cc:
        parts.append(cc)
    return ", ".join(parts)


def _as_dict(row: tuple) -> dict:
    _key, name, cc, admin1, lat, lon, population = row
    return {"name": name, "cc": cc, "admin1": admin1, "lat": lat, "lon": lon,
            "population": population, "display": display(name, cc, admin1)}


def search(query: str, limit: int = MAX_RESULTS) -> list[dict]:
    """Cities matching *query*, best first, de-duplicated by display name.

    Ranked exact match, then prefix, then substring. Within a rank the file's
    own population order decides, so "san jose" offers the Californian one
    before the three in the Philippines.
    """
    key = _fold(query)
    if len(key) < 2:
        return []
    limit = max(1, min(int(limit or MAX_RESULTS), MAX_RESULTS))

    buckets: tuple[list[dict], list[dict], list[dict]] = ([], [], [])
    seen: set[str] = set()
    for row in _table():
        row_key = row[0]
        if key == row_key:
            rank = 0
        elif row_key.startswith(key):
            rank = 1
        elif key in row_key:
            rank = 2
        else:
            continue
        entry = _as_dict(row)
        if entry["display"] in seen:
            continue
        seen.add(entry["display"])
        buckets[rank].append(entry)
        # Enough exact matches to fill the answer means nothing weaker can
        # displace them, so the scan can stop.
        if rank == 0 and len(buckets[0]) >= limit:
            break

    return (buckets[0] + buckets[1] + buckets[2])[:limit]


def lookup(name: str) -> dict | None:
    """The single best city for a typed name, or None.

    Used when the origin arrives as a city string (the MCP tool, a scripted
    call) rather than through the picker, which sends coordinates.
    """
    results = search(name, limit=1)
    return results[0] if results else None


def nearest(lat: float, lon: float, max_km: float = 250.0) -> dict | None:
    """The bundled city that best labels (lat, lon), or None if nothing is near.

    This is what turns a coordinate into the label the UI shows ("Manila, PH"
    rather than "14.6, 121.0"). Coordinates stay as the secondary text, because
    the city is a convenience and the coordinates are the actual origin.

    Not simply the closest city. GeoNames' cities15000 contains city districts
    as rows of their own, so the nearest row to central Manila is Paco and the
    nearest to central Hannover is Nordstadt: both correct, both useless as a
    label for where somebody is. The pick is therefore the most *significant*
    nearby place, scoring population against distance:

        score = population / (1 + distance_km) ** 1.5

    which puts Manila (1.6M, 2 km) ahead of both Paco next door and Quezon City
    (2.9M, 8 km), and is the answer a person would give.

    ``max_km`` exists so a point in the middle of an ocean is reported honestly
    as coordinates rather than attached to the nearest populated place 900 km
    away. A full scan of 34,000 rows is a few milliseconds and happens once per
    origin, so there is no index to keep correct.
    """
    import math

    try:
        lat, lon = float(lat), float(lon)
    except (TypeError, ValueError):
        return None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None

    phi1 = math.radians(lat)
    cos_phi1 = math.cos(phi1)
    best = best_nearest = None
    best_score, best_km = -1.0, float("inf")

    for row in _table():
        _key, name, cc, admin1, row_lat, row_lon, population = row
        # Equirectangular approximation: accurate well inside the distances
        # that matter here, and avoids 34,000 haversines per call.
        dx = math.radians(row_lon - lon) * cos_phi1
        dy = math.radians(row_lat - lat)
        km = 6371.0088 * math.hypot(dx, dy)
        if km > max_km:
            continue
        if km < best_km:
            best_km, best_nearest = km, (name, cc, admin1, row_lat, row_lon, km)
        score = population / (1.0 + km) ** 1.5
        if score > best_score:
            best_score, best = score, (name, cc, admin1, row_lat, row_lon, km)

    # Every candidate had population 0, so significance cannot decide; fall
    # back to plain proximity.
    chosen = best if best_score > 0 else best_nearest
    if chosen is None:
        return None
    name, cc, admin1, row_lat, row_lon, km = chosen
    return {"name": name, "cc": cc, "admin1": admin1,
            "lat": row_lat, "lon": row_lon,
            "display": display(name, cc, admin1),
            "distance_km": round(km, 1)}
