#!/usr/bin/env python3
"""
Regenerate app/routemap/data/site_codes.tsv from each carrier's own published
router list.

Run it when a carrier publishes new sites:

    python3 tools/build_site_codes.py            # fetch live, rewrite the TSV
    python3 tools/build_site_codes.py --dry-run  # print what would change

WHY A GENERATOR AND NOT A HAND-MAINTAINED LIST
----------------------------------------------
Every row in the table is a claim about where somebody else's router is. A
hand-maintained list of those claims decays silently and cannot be audited: you
cannot tell, a year later, which rows came from the operator and which came
from somebody's recollection. So the table is generated from the operator's own
published mapping, each row records which source it came from, and this script
is how you re-derive it.

City coordinates come from the bundled GeoNames table (app/routemap/data/
cities.tsv, CC BY 4.0) rather than from anywhere new, so there is one source of
coordinates in the feature and the licence position does not change.

ADDING A CARRIER
----------------
See app/routemap/data/README.md. In short: add an entry to CARRIERS below whose
`fetch` returns {router_name: "City (facility)"}, confirm every city resolves,
and re-run. A carrier whose published list you cannot reach is a carrier that
does not go in the table.
"""
from __future__ import annotations

import argparse
import html
import json
import pathlib
import re
import sys
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[1]
DATA = REPO / "app" / "routemap" / "data"
CITIES = DATA / "cities.tsv"
OUT = DATA / "site_codes.tsv"

USER_AGENT = "FalconEye/3.35 (site-code table build; osintph.info)"

# GeoNames spells some cities differently from the way a carrier labels its own
# PoP. Each alias is a spelling difference, never a relocation: the left side is
# what the carrier calls the city, the right side is what GeoNames calls the
# same place.
CITY_ALIASES = {
    # Carrier spelling -> the spelling GeoNames uses for the same place.
    # Every one of these is a spelling difference, never a relocation. Verified
    # against app/routemap/data/cities.tsv on 2026-10-03.
    "hanover": "Hannover",
    "frankfurt": "Frankfurt am Main",
    "kiev": "Kyiv",
    "milano": "Milan",
    "st. petersburg": "Saint Petersburg",
    "dusseldorf": "Düsseldorf",
    "cologne": "Köln",
    "queretaro": "Santiago de Querétaro",
    "san luis potosi": "San Luis Potosí",
    "merida": "Mérida",
    "poznan": "Poznań",
    "zurich": "Zürich",
}


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=45) as response:
        return response.read().decode("utf-8", "replace")


# ------------------------------------------------------------------ carriers --

def fetch_arelion() -> dict:
    """Arelion (AS1299, Twelve99, formerly Telia Carrier).

    Their public looking glass embeds the full router list as a JavaScript
    object, grouped by region, mapping each router short name to the city and
    facility it sits in:

        var nodes = {"AS1299 Asia":{"hnk-b4":"Hong Kong (MEGA-i)", ...}, ...}

    That is Arelion describing its own network, which is the strongest source
    available short of asking them.
    """
    page = fetch("https://lg.twelve99.net/")
    match = re.search(r"var\s+nodes\s*=\s*(\{.*?\});", page, re.S)
    if not match:
        raise SystemExit("could not find the router list on the Arelion looking glass; "
                         "the page layout changed and this parser needs updating")
    nodes = json.loads(match.group(1))
    routers = {}
    for section, entries in nodes.items():
        # The GRX/IPX segment reuses the same site codes with a ".grx" suffix
        # and adds nothing, so it is skipped rather than duplicated.
        if "GRX" in section.upper() or "IPX" in section.upper():
            continue
        for router, label in entries.items():
            routers[router] = html.unescape(label)
    return routers


CARRIERS = [
    {
        "id": "arelion",
        "name": "Arelion (AS1299, Twelve99)",
        "source_ref": "arelion-lg",
        "source_url": "https://lg.twelve99.net/",
        "source_kind": "operator looking glass (router list published by the operator)",
        "fetch": fetch_arelion,
        # "hnk-b4" -> "hnk". The router name is <site>-b<N>; the site code is
        # everything before that trailing -b<N>.
        "code_of": lambda router: re.sub(r"-b+\d+$", "", router.split(".")[0]),
    },
]


# -------------------------------------------------------------------- cities --

def load_cities() -> dict:
    """Folded city name -> (name, cc, lat, lon), most populous spelling wins."""
    table = {}
    with CITIES.open(encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 7:
                continue
            name, ascii_name, cc, _admin1, lat, lon, _pop = parts
            for spelling in (name, ascii_name):
                if not spelling:
                    continue
                key = fold(spelling)
                # The file is population-ordered, so the first spelling seen is
                # the biggest city with that name and the right default.
                table.setdefault(key, (name, cc, float(lat), float(lon)))
    return table


def fold(text: str) -> str:
    import unicodedata
    decomposed = unicodedata.normalize("NFKD", text or "")
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]+", "", stripped.lower())


def city_of(label: str) -> str:
    """"Hong Kong (MEGA-i)" -> "Hong Kong"."""
    return re.sub(r"\s*\(.*$", "", label).strip()


# ---------------------------------------------------------------------- main --

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    cities = load_cities()
    rows, unresolved = [], []

    for carrier in CARRIERS:
        routers = carrier["fetch"]()
        print(f"{carrier['id']}: {len(routers)} routers from {carrier['source_url']}")
        seen = {}
        for router, label in sorted(routers.items()):
            code = carrier["code_of"](router)
            city = city_of(label)
            key = fold(CITY_ALIASES.get(city.lower(), city))
            hit = cities.get(key)
            if not hit:
                unresolved.append(f"{carrier['id']} {router} -> {city!r}")
                continue
            name, cc, lat, lon = hit
            # A code seen at several routers must agree with itself, otherwise
            # the code is not a site code and has no business in this table.
            if code in seen and seen[code][0] != city:
                unresolved.append(
                    f"{carrier['id']} code {code!r} maps to both "
                    f"{seen[code][0]!r} and {city!r}; skipped as ambiguous")
                seen[code] = (city, None)
                continue
            if code in seen:
                continue
            seen[code] = (city, (code, city, cc, lat, lon))

        for code, (city, row) in sorted(seen.items()):
            if row is None:
                continue
            _code, city, cc, lat, lon = row
            rows.append((carrier["id"], code, city, cc, f"{lat:.2f}", f"{lon:.2f}",
                         carrier["source_ref"]))

    if unresolved:
        print("\nNOT INCLUDED (resolve these before trusting the table):")
        for item in unresolved:
            print("  " + item)

    header = [
        "# Carrier site codes: the operator's own name for the site a router is in.",
        "# GENERATED by tools/build_site_codes.py. Do not hand-edit; add a carrier there.",
        "# Coordinates come from app/routemap/data/cities.tsv (GeoNames, CC BY 4.0).",
        "#",
        "# Sources, by source_ref:",
    ]
    for carrier in CARRIERS:
        header.append(f"#   {carrier['source_ref']}  {carrier['name']}")
        header.append(f"#     {carrier['source_kind']}")
        header.append(f"#     {carrier['source_url']}")
    header += [
        "#",
        "# carrier\tcode\tcity\tcc\tlat\tlon\tsource_ref",
    ]
    body = "\n".join(header) + "\n" + "".join("\t".join(r) + "\n" for r in rows)

    if args.dry_run:
        print(f"\n--dry-run: would write {len(rows)} rows to {OUT}")
        return 0
    OUT.write_text(body, encoding="utf-8")
    print(f"\nwrote {len(rows)} rows to {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
