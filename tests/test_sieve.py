from __future__ import annotations

import ipaddress
from pathlib import Path
from unittest.mock import patch

import pytest

from falconeye.db import get_connection, init_db
from falconeye.sieve import (
    BrandEntry,
    _extract_host,
    _is_ip,
    _sieve_cve,
    _sieve_ioc,
    match_asn,
    match_brands,
    match_cpes,
    match_tld,
    run_sieve,
)

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

_PH_PREFIXES = [
    ipaddress.ip_network("202.90.136.0/24"),
    ipaddress.ip_network("1.4.128.0/18"),
    ipaddress.ip_network("2001:4400::/23"),
]

_BRANDS = [
    BrandEntry("BDO Unibank", ["BDO Unibank", "BDO"], require_context=False, context_terms=[]),
    BrandEntry("BPI", ["BPI"], require_context=True,
               context_terms=[".ph", "philippine", "philippines", "manila", "bangko sentral", "bsp"]),
    BrandEntry("Globe Telecom", ["Globe Telecom", "globe.com.ph"], require_context=False, context_terms=[]),
    BrandEntry("Globe", ["Globe"], require_context=True,
               context_terms=[".ph", "philippine", "philippines", "telco", "gcash", "pldt"]),
    BrandEntry("PLDT", ["PLDT"], require_context=False, context_terms=[]),
    BrandEntry("PhilHealth", ["PhilHealth"], require_context=False, context_terms=[]),
    BrandEntry("Smart Communications", ["Smart Communications", "smart.com.ph"], require_context=False, context_terms=[]),
    BrandEntry("Smart", ["Smart"], require_context=True,
               context_terms=[".ph", "philippine", "pldt", "smart.com.ph", "telco", "simcard"]),
    BrandEntry("DICT Philippines", ["DICT Philippines", "dict.gov.ph"], require_context=False, context_terms=[]),
]

_CPE_INVENTORY = [
    "cpe:2.3:o:cisco:ios",
    "cpe:2.3:a:microsoft:exchange_server",
    "cpe:2.3:a:apache:http_server",
]


# ---------------------------------------------------------------------------
# _extract_host
# ---------------------------------------------------------------------------

def test_extract_host_from_url():
    assert _extract_host("http://evil.ph/malware.exe") == "evil.ph"


def test_extract_host_ip_url():
    assert _extract_host("http://202.90.136.5/payload") == "202.90.136.5"


def test_extract_host_bare_domain():
    assert _extract_host("evil.ph") == "evil.ph"


def test_extract_host_empty():
    assert _extract_host("") is None


# ---------------------------------------------------------------------------
# _is_ip
# ---------------------------------------------------------------------------

def test_is_ip_v4():
    assert _is_ip("202.90.136.5") is True


def test_is_ip_v6():
    assert _is_ip("2001:4400::1") is True


def test_is_ip_domain():
    assert _is_ip("evil.ph") is False


# ---------------------------------------------------------------------------
# match_asn
# ---------------------------------------------------------------------------

def test_match_asn_hit():
    assert match_asn("202.90.136.5", _PH_PREFIXES) == "202.90.136.0/24"


def test_match_asn_miss():
    assert match_asn("8.8.8.8", _PH_PREFIXES) is None


def test_match_asn_invalid_ip():
    assert match_asn("not-an-ip", _PH_PREFIXES) is None


def test_match_asn_exact_boundary():
    assert match_asn("202.90.136.0", _PH_PREFIXES) == "202.90.136.0/24"
    assert match_asn("202.90.136.255", _PH_PREFIXES) == "202.90.136.0/24"


# ---------------------------------------------------------------------------
# match_tld
# ---------------------------------------------------------------------------

def test_match_tld_dot_ph():
    assert match_tld("evil.ph") is True


def test_match_tld_com_ph():
    assert match_tld("bank.com.ph") is True


def test_match_tld_gov_ph():
    assert match_tld("bir.gov.ph") is True


def test_match_tld_non_ph():
    assert match_tld("evil.com") is False
    assert match_tld("example.org") is False


def test_match_tld_ip():
    assert match_tld("202.90.136.5") is False


# ---------------------------------------------------------------------------
# match_brands
# ---------------------------------------------------------------------------

def test_match_brands_simple_hit():
    assert "BDO Unibank" in match_brands("BDO phishing page", _BRANDS)


def test_match_brands_case_insensitive():
    # Globe Telecom has require_context=False; "globe.com.ph" is an alias
    assert "Globe Telecom" in match_brands("globe.com.ph redirect", _BRANDS)


def test_match_brands_word_boundary():
    # 'BPI' must NOT match inside 'SBPI'
    assert match_brands("SBPI account", _BRANDS) == []


def test_match_brands_multi_word():
    assert "BDO Unibank" in match_brands("Fake BDO Unibank login page", _BRANDS)


def test_match_brands_no_match():
    assert match_brands("unrelated content about cats", _BRANDS) == []


def test_match_brands_empty_text():
    assert match_brands("", _BRANDS) == []


def test_match_brands_empty_brands():
    assert match_brands("BDO phishing", []) == []


# ---------------------------------------------------------------------------
# match_brands — disambiguation (require_context)
# ---------------------------------------------------------------------------

def test_match_brands_smart_no_ph_context_no_match():
    # "Smart" with require_context=True must not match Cisco Smart Licensing copy
    text = "Vulnerability in Cisco Smart Licensing Utility allows remote code execution"
    result = match_brands(text, _BRANDS)
    assert "Smart" not in result


def test_match_brands_smart_with_ph_context_matches():
    text = "Smart Communications smart.com.ph subscriber portal credential stuffing"
    result = match_brands(text, _BRANDS)
    # "Smart Communications" (require_context=False) matches first
    assert "Smart Communications" in result


def test_match_brands_smart_alias_with_ph_context_matches():
    text = "Phishing targeting Smart subscribers in Philippines via SMS"
    result = match_brands(text, _BRANDS)
    assert "Smart" in result


def test_match_brands_globe_github_no_match():
    text = "npm package globe v2.1.3 adds WebGL globe rendering to React apps"
    result = match_brands(text, _BRANDS)
    assert "Globe" not in result
    assert "Globe Telecom" not in result


def test_match_brands_globe_telco_context_matches():
    text = "Globe Telecom PH DITO rival suffers credential leak"
    result = match_brands(text, _BRANDS)
    assert "Globe Telecom" in result


def test_match_brands_globe_with_ph_context_matches():
    text = "Globe prepaid SIM philippines .ph phishing campaign"
    result = match_brands(text, _BRANDS)
    assert "Globe" in result


def test_match_brands_bpi_no_ph_context_no_match():
    text = "BPI calculation used in cryptographic protocol analysis"
    result = match_brands(text, _BRANDS)
    assert "BPI" not in result


def test_match_brands_bpi_ph_context_matches():
    text = "BPI phishing page targeting Bank of the Philippine Islands customers in Philippines"
    result = match_brands(text, _BRANDS)
    assert "BPI" in result


def test_match_brands_dict_philippines_matches():
    text = "dict.gov.ph DICT Philippines open data portal credential exposure"
    result = match_brands(text, _BRANDS)
    assert "DICT Philippines" in result


def test_match_brands_bare_dict_no_match():
    # "dict" alone should not match — no "dict" alias in _BRANDS, only "DICT Philippines"
    text = "wordtrans dictionary package (dict) remote buffer overflow"
    result = match_brands(text, _BRANDS)
    assert "DICT Philippines" not in result


# ---------------------------------------------------------------------------
# match_cpes
# ---------------------------------------------------------------------------

def test_match_cpes_prefix_hit():
    cve_cpes = ["cpe:2.3:o:cisco:ios:15.2:*:*:*:*:*:*:*"]
    assert "cpe:2.3:o:cisco:ios" in match_cpes(cve_cpes, _CPE_INVENTORY)


def test_match_cpes_no_hit():
    cve_cpes = ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]
    assert match_cpes(cve_cpes, _CPE_INVENTORY) == []


def test_match_cpes_empty():
    assert match_cpes([], _CPE_INVENTORY) == []
    assert match_cpes(["cpe:2.3:o:cisco:ios:15:*"], []) == []


# ---------------------------------------------------------------------------
# _sieve_ioc
# ---------------------------------------------------------------------------

def test_sieve_ioc_tld_match():
    matches = _sieve_ioc("http://phishing.bdo.com.ph/login", _PH_PREFIXES, _BRANDS)
    criteria = {m[0] for m in matches}
    assert "tld" in criteria


def test_sieve_ioc_asn_match():
    matches = _sieve_ioc("http://202.90.136.10/malware", _PH_PREFIXES, _BRANDS)
    criteria = {m[0] for m in matches}
    assert "asn" in criteria


def test_sieve_ioc_brand_in_url():
    matches = _sieve_ioc("http://evil.ru/fake-BDO-login", _PH_PREFIXES, _BRANDS)
    criteria = {m[0] for m in matches}
    assert "brand" in criteria


def test_sieve_ioc_no_match():
    matches = _sieve_ioc("http://malware.com/payload.exe", _PH_PREFIXES, _BRANDS)
    assert matches == []


def test_sieve_ioc_tld_and_brand():
    # URL is on a .ph domain AND contains a brand name
    matches = _sieve_ioc("http://bdo-alert.com.ph/verify", _PH_PREFIXES, _BRANDS)
    criteria = {m[0] for m in matches}
    assert "tld" in criteria
    assert "brand" in criteria


# ---------------------------------------------------------------------------
# _sieve_cve
# ---------------------------------------------------------------------------

def test_sieve_cve_brand_in_description():
    matches = _sieve_cve(
        "Vulnerability in BDO Unibank online banking portal",
        None, [], _BRANDS, _CPE_INVENTORY,
    )
    assert any(m[0] == "brand" and "BDO" in m[1] for m in matches)


def test_sieve_cve_brand_in_kev_vendor():
    import json
    kev = json.dumps({"vendor": "Globe Telecom", "product": "Router", "cwes": [], "notes": ""})
    matches = _sieve_cve(None, kev, [], _BRANDS, _CPE_INVENTORY)
    assert any(m[0] == "brand" and "Globe Telecom" in m[1] for m in matches)


def test_sieve_cve_cpe_match():
    cve_cpes = ["cpe:2.3:o:cisco:ios:15.2:sp1:*:*:*:*:*:*"]
    matches = _sieve_cve(None, None, cve_cpes, [], _CPE_INVENTORY)
    assert any(m[0] == "cpe" for m in matches)


def test_sieve_cve_no_match():
    matches = _sieve_cve("Unrelated Linux kernel bug", None, [], _BRANDS, _CPE_INVENTORY)
    assert matches == []


# ---------------------------------------------------------------------------
# run_sieve (integration)
# ---------------------------------------------------------------------------

@pytest.fixture
def db_with_data(tmp_path):
    db = tmp_path / "test.db"
    init_db(db)
    conn = get_connection(db)

    # IOC: .ph TLD
    conn.execute(
        "INSERT INTO iocs (ioc_type, ioc_value, source, source_id, fetched_at) "
        "VALUES ('url', 'http://evil.bdo.com.ph/phishing', 'urlhaus', 'u1', '2026-06-22T00:00:00Z')"
    )
    # IOC: PH IP
    conn.execute(
        "INSERT INTO iocs (ioc_type, ioc_value, source, source_id, fetched_at) "
        "VALUES ('url', 'http://202.90.136.10/malware.exe', 'urlhaus', 'u2', '2026-06-22T00:00:00Z')"
    )
    # IOC: no PH relevance
    conn.execute(
        "INSERT INTO iocs (ioc_type, ioc_value, source, source_id, fetched_at) "
        "VALUES ('url', 'http://evil.com/payload', 'urlhaus', 'u3', '2026-06-22T00:00:00Z')"
    )
    # CVE: KEV with Cisco IOS CPE
    conn.execute(
        "INSERT INTO cves (cve_id, source, fetched_at) "
        "VALUES ('CVE-2024-1001', 'kev', '2026-06-22T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO cve_cpe_matches (cve_id, cpe) "
        "VALUES ('CVE-2024-1001', 'cpe:2.3:o:cisco:ios:15.2:*:*:*:*:*:*:*')"
    )
    conn.commit()
    conn.close()

    # Populate ph_prefixes so ASN matching works
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO ph_prefixes (prefix, prefix_type, fetched_at) "
        "VALUES ('202.90.136.0/24', 'ipv4', '2026-06-22T00:00:00Z')"
    )
    conn.commit()
    conn.close()
    return db


_BRAND_YAML_BDO = """\
brands:
  - name: "BDO Unibank"
    aliases: ["BDO Unibank", "BDO", "bdo.com.ph"]
    require_context: false
"""

_BRAND_YAML_EMPTY = "brands: []\n"


def test_run_sieve_finds_tld_match(db_with_data, tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "brand_strings.yaml").write_text(_BRAND_YAML_BDO)
    (cfg / "cpe_inventory.yaml").write_text("cpes:\n  - cpe:2.3:o:cisco:ios\n")

    run_sieve(db_with_data, cfg)

    conn = get_connection(db_with_data)
    tld_matches = conn.execute(
        "SELECT record_id FROM sieve_matches WHERE match_criterion='tld'"
    ).fetchall()
    conn.close()
    assert len(tld_matches) == 1


def test_run_sieve_finds_asn_match(db_with_data, tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "brand_strings.yaml").write_text(_BRAND_YAML_EMPTY)
    (cfg / "cpe_inventory.yaml").write_text("cpes: []\n")

    run_sieve(db_with_data, cfg)

    conn = get_connection(db_with_data)
    asn_matches = conn.execute(
        "SELECT matched_value FROM sieve_matches WHERE match_criterion='asn'"
    ).fetchall()
    conn.close()
    assert len(asn_matches) == 1
    assert asn_matches[0][0] == "202.90.136.0/24"


def test_run_sieve_finds_cpe_match(db_with_data, tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "brand_strings.yaml").write_text(_BRAND_YAML_EMPTY)
    (cfg / "cpe_inventory.yaml").write_text("cpes:\n  - cpe:2.3:o:cisco:ios\n")

    run_sieve(db_with_data, cfg)

    conn = get_connection(db_with_data)
    cpe_matches = conn.execute(
        "SELECT matched_value FROM sieve_matches WHERE match_criterion='cpe'"
    ).fetchall()
    conn.close()
    assert len(cpe_matches) == 1


def test_run_sieve_idempotent(db_with_data, tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "brand_strings.yaml").write_text(_BRAND_YAML_BDO)
    (cfg / "cpe_inventory.yaml").write_text("cpes:\n  - cpe:2.3:o:cisco:ios\n")

    total1, _ = run_sieve(db_with_data, cfg)
    total2, _ = run_sieve(db_with_data, cfg)

    # Second run should produce the same count (delete-then-reinsert)
    assert total1 == total2

    conn = get_connection(db_with_data)
    count = conn.execute("SELECT COUNT(*) FROM sieve_matches").fetchone()[0]
    conn.close()
    assert count == total1
