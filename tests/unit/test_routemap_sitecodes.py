"""The carrier site-code table: narrow on purpose.

The danger with reading location out of a hostname is over-reach. A three
letter string is not evidence: "lax" is inside "relaxed", and customer
hostnames are full of city-ish fragments that mean nothing. So most of this
file is about what must NOT match.

See app/routemap/data/README.md for how to add a carrier.
"""
import pathlib
import re

import pytest

from app.routemap import sitecodes

DATA = pathlib.Path(sitecodes.DATA_FILE)


# ---------- the table itself ----------

def test_the_table_ships_and_is_not_empty():
    assert DATA.exists(), f"{DATA} is missing; run tools/build_site_codes.py"
    assert sitecodes.count() > 50


def test_every_row_is_well_formed_and_cites_a_source():
    seen = set()
    for line in DATA.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split("\t")
        assert len(parts) == 7, f"malformed row: {line!r}"
        carrier, code, city, cc, lat, lon, source_ref = parts
        assert carrier in sitecodes.CARRIERS, f"row for unknown carrier {carrier!r}"
        assert re.fullmatch(r"[a-z]{2,6}", code), f"implausible site code {code!r}"
        assert city.strip(), f"row {code!r} has no city"
        assert re.fullmatch(r"[A-Z]{2}", cc), f"row {code!r} has no country code"
        assert -90 <= float(lat) <= 90 and -180 <= float(lon) <= 180
        assert source_ref.strip(), f"row {code!r} cites no source"
        assert (carrier, code) not in seen, f"duplicate row for {carrier}/{code}"
        seen.add((carrier, code))


def test_the_header_names_the_source_of_every_source_ref():
    header = "\n".join(l for l in DATA.read_text(encoding="utf-8").splitlines()
                       if l.startswith("#"))
    refs = {line.split("\t")[6] for line in DATA.read_text(encoding="utf-8").splitlines()
            if not line.startswith("#") and line.strip()}
    for ref in refs:
        assert ref in header, (
            f"rows cite source_ref {ref!r} but the file header does not say "
            f"where that came from. Every claim in this table has to be traceable.")


def test_a_carrier_in_the_table_is_declared_in_the_module():
    """The data file and the matching rules cannot drift apart."""
    carriers = {line.split("\t")[0] for line in DATA.read_text(encoding="utf-8").splitlines()
                if not line.startswith("#") and line.strip()}
    assert carriers <= set(sitecodes.CARRIERS)
    for carrier, spec in sitecodes.CARRIERS.items():
        assert spec["suffixes"], f"{carrier} declares no backbone zone"


# ---------- what must resolve ----------

@pytest.mark.parametrize("hostname,city", [
    ("hnk-b4-link.ip.twelve99.net", "Hong Kong"),
    ("hnk-b3-link.ip.twelve99.net", "Hong Kong"),
    ("sng-b6-link.ip.twelve99.net", "Singapore"),
    ("mei-b6-link.ip.twelve99.net", "Marseille"),
    ("prs-bb2-link.ip.twelve99.net", "Paris"),
    ("ffm-bb2-link.ip.twelve99.net", "Frankfurt"),
    ("ffm-b16-link.ip.twelve99.net", "Frankfurt"),
])
def test_arelion_backbone_hostnames_resolve(hostname, city):
    """The five legs CAIDA Hoiho's 2024-08 ruleset cannot place."""
    record = sitecodes.lookup(hostname)
    assert record is not None, f"{hostname} did not resolve"
    assert city in record["place"]
    assert record["source_ref"], "the match does not say where the claim came from"


def test_case_and_trailing_dot_do_not_matter():
    assert sitecodes.lookup("HNK-B4-Link.IP.Twelve99.NET.") is not None


# ---------- what must NOT resolve ----------

@pytest.mark.parametrize("hostname", [
    # Customer interconnect: named for the customer, not the site. Reading
    # "plusline" as a site code is the exact over-reach this table avoids.
    "plusline-ic-323934.ip.twelve99-cust.net",
    "man-ic-123456.ip.twelve99-cust.net",
    # Other carriers: their naming scheme is not Arelion's.
    "if-bundle-2-2.qcore2.sqn-sanjose.as6453.net",
    "te2-2.c301.f.de.plusline.net",
    "122.2.187.146.static.pldt.net",
    # A city-ish fragment in an unrelated zone proves nothing.
    "lax-something.example.com",
    "hnk-b4-link.example.com",
    # "relaxed" contains "lax". It is not a site code.
    "relaxed.ip.twelve99.net",
    # Not a code at all.
    "www.twelve99.net",
    "",
])
def test_these_must_never_be_read_as_a_site_code(hostname):
    assert sitecodes.lookup(hostname) is None, (
        f"{hostname!r} was read as a site code; the table is over-reaching")


def test_an_ambiguous_code_is_absent_rather_than_guessed():
    """Arelion uses 'ewr' for both New York City and Piscataway facilities.

    The generator drops a code that maps to two cities instead of picking one.
    """
    assert ("arelion", "ewr") not in sitecodes.table()
    assert sitecodes.lookup("ewr-b13-link.ip.twelve99.net") is None
