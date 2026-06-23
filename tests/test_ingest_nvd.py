from __future__ import annotations

from unittest.mock import patch

import pytest

from falconeye.db import get_connection, init_db
from falconeye.ingest.nvd import (
    _backfill_kev_severity,
    _trim_ts,
    extract_cpes,
    extract_cvss,
    extract_description,
    ingest,
)

# --- Fixtures ---

def _make_vuln(
    cve_id: str = "CVE-2024-1234",
    description: str = "A critical vulnerability.",
    score: float = 9.8,
    severity: str = "CRITICAL",
    cpes: list[str] | None = None,
    published: str = "2024-01-01T00:00:00.000",
    last_modified: str = "2024-01-02T00:00:00.000",
) -> dict:
    cpes = cpes or ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "lastModified": last_modified,
            "descriptions": [
                {"lang": "en", "value": description},
                {"lang": "es", "value": "Descripción."},
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "type": "Primary",
                        "cvssData": {"baseScore": score, "baseSeverity": severity},
                    }
                ]
            },
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": c} for c in cpes
                            ]
                        }
                    ]
                }
            ],
        }
    }


@pytest.fixture
def db(tmp_path):
    return tmp_path / "test.db"


# --- Helper function tests ---

def test_extract_description_english():
    cve = {"descriptions": [{"lang": "es", "value": "Nope"}, {"lang": "en", "value": "Yes"}]}
    assert extract_description(cve) == "Yes"


def test_extract_description_missing():
    assert extract_description({}) is None
    assert extract_description({"descriptions": []}) is None


def test_extract_cvss_primary():
    cve = _make_vuln(score=9.8, severity="CRITICAL")["cve"]
    score, sev = extract_cvss(cve)
    assert score == 9.8
    assert sev == "CRITICAL"


def test_extract_cvss_prefers_v31_over_v30():
    cve = {
        "metrics": {
            "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
            "cvssMetricV30": [{"type": "Primary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
        }
    }
    score, sev = extract_cvss(cve)
    assert score == 9.8


def test_extract_cvss_missing():
    assert extract_cvss({}) == (None, None)


def test_extract_cpes_vulnerable_only():
    cve = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [
                    {"vulnerable": True,  "criteria": "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"},
                    {"vulnerable": False, "criteria": "cpe:2.3:o:os:linux:*:*:*:*:*:*:*:*"},
                ]
            }]
        }]
    }
    assert extract_cpes(cve) == ["cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"]


def test_extract_cpes_deduplicates():
    cpe = "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"
    cve = {
        "configurations": [
            {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": cpe}]}]},
            {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": cpe}]}]},
        ]
    }
    assert extract_cpes(cve) == [cpe]


def test_trim_ts():
    assert _trim_ts("2024-01-01T12:34:56.789") == "2024-01-01T12:34:56Z"
    assert _trim_ts(None) is None


# --- ingest tests ---

def _mock_fetch_pages(vulns: list[dict]):
    """Return a context manager that patches fetch_pages to yield one batch."""
    return patch(
        "falconeye.ingest.nvd.fetch_pages",
        return_value=iter([vulns]),
    )


def test_ingest_upserts_cve(db):
    vulns = [_make_vuln("CVE-2024-0001", description="Test vuln", score=7.5, severity="HIGH")]
    with _mock_fetch_pages(vulns):
        upserted, errors = ingest(db, start_date="2024-01-01T00:00:00Z")
    assert upserted == 1
    assert errors == 0

    conn = get_connection(db)
    row = conn.execute("SELECT * FROM cves WHERE cve_id='CVE-2024-0001'").fetchone()
    conn.close()
    assert row["description"] == "Test vuln"
    assert row["cvss_v3_score"] == 7.5
    assert row["cvss_v3_severity"] == "HIGH"
    assert row["published_date"] == "2024-01-01T00:00:00Z"


def test_ingest_populates_cpe_matches(db):
    cpes = ["cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*", "cpe:2.3:a:v:p:2.0:*:*:*:*:*:*:*"]
    vulns = [_make_vuln("CVE-2024-0002", cpes=cpes)]
    with _mock_fetch_pages(vulns):
        ingest(db, start_date="2024-01-01T00:00:00Z")

    conn = get_connection(db)
    rows = conn.execute(
        "SELECT cpe FROM cve_cpe_matches WHERE cve_id='CVE-2024-0002' ORDER BY cpe"
    ).fetchall()
    conn.close()
    assert len(rows) == 2
    assert rows[0]["cpe"] == "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"


def test_ingest_idempotent(db):
    vulns = [_make_vuln("CVE-2024-0003")]
    with _mock_fetch_pages(vulns):
        ingest(db, start_date="2024-01-01T00:00:00Z")
    with _mock_fetch_pages(vulns):
        ingest(db, start_date="2024-01-01T00:00:00Z")

    conn = get_connection(db)
    count = conn.execute("SELECT COUNT(*) FROM cves WHERE cve_id='CVE-2024-0003'").fetchone()[0]
    cpe_count = conn.execute(
        "SELECT COUNT(*) FROM cve_cpe_matches WHERE cve_id='CVE-2024-0003'"
    ).fetchone()[0]
    conn.close()
    assert count == 1
    assert cpe_count == 1


def test_ingest_does_not_overwrite_kev_fields(db):
    """NVD worker must not touch kev_* columns on conflict."""
    init_db(db)
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO cves (cve_id, source, fetched_at, kev_date_added, kev_ransomware_use) "
        "VALUES ('CVE-2024-0004', 'kev', '2026-06-22T00:00:00Z', '2024-01-10', 'Known')"
    )
    conn.commit()
    conn.close()

    vulns = [_make_vuln("CVE-2024-0004", score=9.8, severity="CRITICAL")]
    with _mock_fetch_pages(vulns):
        ingest(db, start_date="2024-01-01T00:00:00Z")

    conn = get_connection(db)
    row = conn.execute("SELECT * FROM cves WHERE cve_id='CVE-2024-0004'").fetchone()
    conn.close()
    assert row["kev_date_added"] == "2024-01-10"   # preserved
    assert row["kev_ransomware_use"] == "Known"     # preserved
    assert row["cvss_v3_score"] == 9.8              # NVD data written


def test_ingest_skips_missing_cve_id(db):
    vulns = [{"cve": {"id": "", "descriptions": [], "metrics": {}, "configurations": []}}]
    with _mock_fetch_pages(vulns):
        upserted, errors = ingest(db, start_date="2024-01-01T00:00:00Z")
    assert upserted == 0
    assert errors == 1


def test_ingest_handles_fetch_error(db):
    import requests
    with patch("falconeye.ingest.nvd.fetch_pages", side_effect=requests.RequestException("timeout")):
        upserted, errors = ingest(db, start_date="2024-01-01T00:00:00Z")
    assert upserted == 0
    assert errors == 0


def test_ingest_full_sync_uses_no_date_params(db):
    called_with = {}

    def capture_pages(extra_params=None, api_key=None):
        called_with["extra_params"] = extra_params
        return iter([[]])

    with patch("falconeye.ingest.nvd.fetch_pages", side_effect=capture_pages):
        ingest(db, full_sync=True)

    assert called_with["extra_params"] is None


def test_ingest_incremental_uses_last_modified(db):
    """After an NVD run, the next call should pass lastModStartDate."""
    init_db(db)
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO cves (cve_id, source, source_id, fetched_at, last_modified) "
        "VALUES ('CVE-2024-0005', 'nvd', 'CVE-2024-0005', '2026-06-22T00:00:00Z', '2026-06-22T00:00:00Z')"
    )
    conn.commit()
    conn.close()

    called_with = {}

    def capture_pages(extra_params=None, api_key=None):
        called_with["extra_params"] = extra_params
        return iter([[]])

    with patch("falconeye.ingest.nvd.fetch_pages", side_effect=capture_pages):
        ingest(db)

    assert called_with["extra_params"] is not None
    assert "lastModStartDate" in called_with["extra_params"]


# ---------------------------------------------------------------------------
# _backfill_kev_severity
# ---------------------------------------------------------------------------

def _db_with_kev_cve(tmp_path, cve_id="CVE-2024-9000", severity=None):
    """Return a db path with a KEV CVE that has a sieve_match, optionally with severity."""
    db = tmp_path / "back.db"
    init_db(db)
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO cves (cve_id, description, cvss_v3_severity, cvss_v3_score, "
        "source, source_id, fetched_at) VALUES (?, 'Test', ?, ?, 'kev', ?, '2026-06-22T00:00:00Z')",
        (cve_id, severity, None, cve_id),
    )
    cve_db_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO sieve_matches (record_type, record_id, match_criterion, matched_value, matched_at) "
        "VALUES ('cve', ?, 'cpe', 'cpe:2.3:o:cisco:ios', '2026-06-22T00:00:00Z')",
        (cve_db_id,),
    )
    conn.commit()
    conn.close()
    return db


def _nvd_response(cve_id, severity="HIGH", score=7.5):
    return {
        "vulnerabilities": [{
            "cve": {
                "id": cve_id,
                "metrics": {
                    "cvssMetricV31": [{
                        "type": "Primary",
                        "cvssData": {"baseScore": score, "baseSeverity": severity},
                    }]
                },
            }
        }]
    }


def test_backfill_updates_null_severity(tmp_path):
    db = _db_with_kev_cve(tmp_path, cve_id="CVE-2024-9000", severity=None)
    conn = get_connection(db)

    with patch("falconeye.ingest.nvd._fetch_page",
               return_value=_nvd_response("CVE-2024-9000", severity="HIGH", score=7.5)), \
         patch("falconeye.ingest.nvd.time.sleep"):
        updated = _backfill_kev_severity(conn, api_key=None)

    assert updated == 1
    row = conn.execute("SELECT cvss_v3_severity FROM cves WHERE cve_id='CVE-2024-9000'").fetchone()
    assert row[0] == "HIGH"
    conn.close()


def test_backfill_skips_already_populated(tmp_path):
    db = _db_with_kev_cve(tmp_path, cve_id="CVE-2024-9001", severity="CRITICAL")
    conn = get_connection(db)

    fetch_calls = []
    with patch("falconeye.ingest.nvd._fetch_page", side_effect=fetch_calls.append):
        updated = _backfill_kev_severity(conn, api_key=None)

    assert updated == 0
    assert len(fetch_calls) == 0
    conn.close()


def test_backfill_handles_fetch_error(tmp_path):
    db = _db_with_kev_cve(tmp_path, cve_id="CVE-2024-9002", severity=None)
    conn = get_connection(db)

    with patch("falconeye.ingest.nvd._fetch_page", side_effect=Exception("network error")), \
         patch("falconeye.ingest.nvd.time.sleep"):
        updated = _backfill_kev_severity(conn, api_key=None)

    assert updated == 0
    conn.close()


def test_backfill_caps_at_50(tmp_path):
    db = tmp_path / "cap.db"
    init_db(db)
    conn = get_connection(db)
    # Insert 51 KEV CVEs all with NULL severity and sieve_matches
    for i in range(51):
        cid = f"CVE-2024-{9100 + i:04d}"
        conn.execute(
            "INSERT INTO cves (cve_id, description, source, source_id, fetched_at) "
            "VALUES (?, 'Test', 'kev', ?, '2026-06-22T00:00:00Z')",
            (cid, cid),
        )
        db_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO sieve_matches (record_type, record_id, match_criterion, matched_value, matched_at) "
            "VALUES ('cve', ?, 'cpe', 'cpe:2.3:o:cisco:ios', '2026-06-22T00:00:00Z')",
            (db_id,),
        )
    conn.commit()

    fetch_calls = []

    def fake_fetch(params, api_key, pre_delay):
        cve_id = params["cveId"]
        fetch_calls.append(cve_id)
        return _nvd_response(cve_id, "HIGH", 7.5)

    with patch("falconeye.ingest.nvd._fetch_page", side_effect=fake_fetch), \
         patch("falconeye.ingest.nvd.time.sleep"):
        _backfill_kev_severity(conn, api_key=None)

    assert len(fetch_calls) == 50
    conn.close()
