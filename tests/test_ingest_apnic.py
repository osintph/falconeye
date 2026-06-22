from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from falconeye.db import get_connection
from falconeye.ingest.apnic import ingest, parse_ph_records

# Representative sample of the APNIC delegated stats format
_SAMPLE = """\
# APNIC Statistics Exchange
# Generated: Mon, 22 Jun 2026 12:00:00 UTC
#
2|apnic|20260622|50000|19830101|20260622|+1000
apnic|*|asn|*|4000|summary
apnic|*|ipv4|*|8000|summary
apnic|*|ipv6|*|3000|summary
apnic|PH|asn|4775|1|20011119|allocated
apnic|PH|asn|9299|1|20011001|allocated
apnic|PH|asn|10000|3|20200101|allocated
apnic|PH|ipv4|202.90.136.0|256|20020830|allocated
apnic|PH|ipv4|1.4.128.0|16384|20110811|allocated
apnic|PH|ipv6|2001:4400::|23|20040101|allocated
apnic|AU|asn|1221|1|20000101|allocated
apnic|AU|ipv4|1.0.0.0|256|20110811|allocated
apnic|PH|asn|99999|1|20200101|reserved
"""

# --- parse_ph_records ---

def test_parse_extracts_ph_asns():
    asns, _ = parse_ph_records(_SAMPLE)
    # 4775(1) + 9299(1) + 10000,10001,10002(3) = 5 ASNs
    assert sorted(asns) == [4775, 9299, 10000, 10001, 10002]


def test_parse_expands_asn_blocks():
    asns, _ = parse_ph_records(_SAMPLE)
    assert 10000 in asns
    assert 10001 in asns
    assert 10002 in asns


def test_parse_extracts_ipv4_prefixes():
    _, prefixes = parse_ph_records(_SAMPLE)
    ipv4 = [(p, t) for p, t in prefixes if t == "ipv4"]
    assert ("202.90.136.0/24", "ipv4") in ipv4   # 256 IPs → /24
    assert ("1.4.128.0/18", "ipv4") in ipv4       # 16384 IPs → /18


def test_parse_extracts_ipv6_prefixes():
    _, prefixes = parse_ph_records(_SAMPLE)
    ipv6 = [(p, t) for p, t in prefixes if t == "ipv6"]
    assert ("2001:4400::/23", "ipv6") in ipv6


def test_parse_excludes_non_ph():
    asns, prefixes = parse_ph_records(_SAMPLE)
    # AU ASN 1221 and AU IPv4 1.0.0.0 must not appear
    assert 1221 not in asns
    assert not any(p.startswith("1.0.0.0") for p, _ in prefixes)


def test_parse_excludes_summary_lines():
    asns, prefixes = parse_ph_records(_SAMPLE)
    # Summary lines have cc='*' and must not be parsed as records
    assert len(asns) == 5  # only the real PH ASNs


def test_parse_excludes_reserved_status():
    asns, _ = parse_ph_records(_SAMPLE)
    # ASN 99999 has status=reserved, must be excluded
    assert 99999 not in asns


def test_parse_empty_input():
    asns, prefixes = parse_ph_records("")
    assert asns == []
    assert prefixes == []


def test_parse_comments_only():
    asns, prefixes = parse_ph_records("# comment\n# another\n")
    assert asns == []
    assert prefixes == []


# --- IPv4 CIDR conversion ---

def test_ipv4_cidr_sizes():
    text = (
        "apnic|PH|ipv4|10.0.0.0|1|20200101|allocated\n"    # /32
        "apnic|PH|ipv4|10.0.1.0|512|20200101|allocated\n"   # /23
        "apnic|PH|ipv4|10.1.0.0|65536|20200101|allocated\n" # /16
    )
    _, prefixes = parse_ph_records(text)
    assert ("10.0.0.0/32", "ipv4") in prefixes
    assert ("10.0.1.0/23", "ipv4") in prefixes
    assert ("10.1.0.0/16", "ipv4") in prefixes


# --- ingest ---

@pytest.fixture
def db(tmp_path):
    return tmp_path / "test.db"


def test_ingest_stores_asns_and_prefixes(db):
    with patch("falconeye.ingest.apnic.fetch_delegated", return_value=_SAMPLE):
        asn_count, prefix_count, errors = ingest(db)

    assert asn_count == 5
    assert prefix_count == 3   # 2 IPv4 + 1 IPv6
    assert errors == 0

    conn = get_connection(db)
    asns_in_db = [r[0] for r in conn.execute("SELECT asn FROM ph_asns ORDER BY asn")]
    prefixes_in_db = [r[0] for r in conn.execute("SELECT prefix FROM ph_prefixes ORDER BY prefix")]
    conn.close()

    assert asns_in_db == [4775, 9299, 10000, 10001, 10002]
    assert "202.90.136.0/24" in prefixes_in_db
    assert "1.4.128.0/18" in prefixes_in_db
    assert "2001:4400::/23" in prefixes_in_db


def test_ingest_idempotent(db):
    with patch("falconeye.ingest.apnic.fetch_delegated", return_value=_SAMPLE):
        ingest(db)
        asn_count, prefix_count, errors = ingest(db)

    assert errors == 0
    conn = get_connection(db)
    assert conn.execute("SELECT COUNT(*) FROM ph_asns").fetchone()[0] == 5
    assert conn.execute("SELECT COUNT(*) FROM ph_prefixes").fetchone()[0] == 3
    conn.close()


def test_ingest_replaces_old_data(db):
    """Second run with different data fully replaces the first run's rows."""
    old_data = "apnic|PH|asn|1234|1|20200101|allocated\n"
    new_data = "apnic|PH|asn|5678|1|20210101|allocated\n"

    with patch("falconeye.ingest.apnic.fetch_delegated", return_value=old_data):
        ingest(db)
    with patch("falconeye.ingest.apnic.fetch_delegated", return_value=new_data):
        ingest(db)

    conn = get_connection(db)
    asns = [r[0] for r in conn.execute("SELECT asn FROM ph_asns")]
    conn.close()
    assert asns == [5678]
    assert 1234 not in asns


def test_ingest_handles_fetch_error(db):
    with patch(
        "falconeye.ingest.apnic.fetch_delegated",
        side_effect=requests.RequestException("timeout"),
    ):
        asn_count, prefix_count, errors = ingest(db)
    assert asn_count == 0
    assert prefix_count == 0
    assert errors == 1
