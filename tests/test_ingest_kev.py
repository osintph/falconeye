from __future__ import annotations

import json
from unittest.mock import patch

import pytest
import requests

from falconeye.db import get_connection
from falconeye.ingest.kev import ingest, parse_vulnerabilities

_SAMPLE_DATA = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2026.06.22",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 contains a remote code execution vulnerability.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": "https://logging.apache.org/log4j/2.x/security.html",
            "cwes": ["CWE-917", "CWE-400"],
        },
        {
            "cveID": "CVE-2022-26134",
            "vendorProject": "Atlassian",
            "product": "Confluence Server and Data Center",
            "vulnerabilityName": "Atlassian Confluence Server OGNL Injection Vulnerability",
            "dateAdded": "2022-06-02",
            "shortDescription": "Atlassian Confluence Server contains an OGNL injection vulnerability.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2022-06-06",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": ["CWE-74"],
        },
    ],
}


# --- parse_vulnerabilities ---

def test_parse_vulnerabilities_returns_list():
    vulns = parse_vulnerabilities(_SAMPLE_DATA)
    assert len(vulns) == 2


def test_parse_vulnerabilities_empty_catalog():
    assert parse_vulnerabilities({}) == []
    assert parse_vulnerabilities({"vulnerabilities": []}) == []


# --- ingest ---

@pytest.fixture
def db(tmp_path):
    return tmp_path / "test.db"


def test_ingest_upserts_records(db):
    with patch("falconeye.ingest.kev.fetch_kev", return_value=_SAMPLE_DATA):
        upserted, errors = ingest(db)
    assert upserted == 2
    assert errors == 0

    conn = get_connection(db)
    rows = conn.execute("SELECT cve_id, description, kev_date_added FROM cves ORDER BY cve_id").fetchall()
    conn.close()

    assert len(rows) == 2
    assert rows[0]["cve_id"] == "CVE-2021-44228"
    assert rows[0]["description"] == "Apache Log4j2 Remote Code Execution Vulnerability"
    assert rows[0]["kev_date_added"] == "2021-12-10"


def test_ingest_kev_fields_stored(db):
    with patch("falconeye.ingest.kev.fetch_kev", return_value=_SAMPLE_DATA):
        ingest(db)

    conn = get_connection(db)
    row = conn.execute("SELECT * FROM cves WHERE cve_id='CVE-2021-44228'").fetchone()
    conn.close()

    assert row["kev_due_date"] == "2021-12-24"
    assert row["kev_ransomware_use"] == "Known"
    assert row["kev_required_action"] == "Apply updates per vendor instructions."
    notes = json.loads(row["kev_notes"])
    assert notes["vendor"] == "Apache"
    assert notes["product"] == "Log4j2"
    assert "CWE-917" in notes["cwes"]


def test_ingest_idempotent(db):
    with patch("falconeye.ingest.kev.fetch_kev", return_value=_SAMPLE_DATA):
        ingest(db)
        ingest(db)

    conn = get_connection(db)
    count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    conn.close()
    assert count == 2


def test_ingest_preserves_nvd_description_on_conflict(db):
    """When NVD has already set a description, KEV must not overwrite it."""
    from falconeye.db import init_db

    init_db(db)
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO cves (cve_id, description, source, fetched_at) "
        "VALUES ('CVE-2021-44228', 'NVD description text', 'nvd', '2026-06-22T00:00:00Z')"
    )
    conn.commit()
    conn.close()

    with patch("falconeye.ingest.kev.fetch_kev", return_value=_SAMPLE_DATA):
        ingest(db)

    conn = get_connection(db)
    row = conn.execute("SELECT description, kev_date_added FROM cves WHERE cve_id='CVE-2021-44228'").fetchone()
    conn.close()

    assert row["description"] == "NVD description text"   # not overwritten
    assert row["kev_date_added"] == "2021-12-10"          # KEV field was set


def test_ingest_sets_description_when_no_prior_row(db):
    """When KEV is the first source for a CVE, vulnerabilityName becomes description."""
    with patch("falconeye.ingest.kev.fetch_kev", return_value=_SAMPLE_DATA):
        ingest(db)

    conn = get_connection(db)
    row = conn.execute("SELECT description FROM cves WHERE cve_id='CVE-2022-26134'").fetchone()
    conn.close()
    assert "OGNL" in row["description"]


def test_ingest_handles_fetch_error(db):
    with patch("falconeye.ingest.kev.fetch_kev", side_effect=requests.RequestException("timeout")):
        upserted, errors = ingest(db)
    assert upserted == 0
    assert errors == 0


def test_ingest_skips_missing_cve_id(db):
    bad_data = {"vulnerabilities": [{"vendorProject": "Acme", "product": "Widget"}]}
    with patch("falconeye.ingest.kev.fetch_kev", return_value=bad_data):
        upserted, errors = ingest(db)
    assert upserted == 0
    assert errors == 1
