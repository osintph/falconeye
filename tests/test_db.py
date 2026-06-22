import sqlite3
import pytest
from falconeye.db import get_connection, init_db

EXPECTED_TABLES = {"iocs", "cves", "cve_cpe_matches", "ph_asns", "ph_prefixes", "sieve_matches"}


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "test.db"
    init_db(path)
    return path


def test_init_creates_all_tables(db):
    conn = get_connection(db)
    tables = {
        row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        if not row[0].startswith("sqlite_")
    }
    conn.close()
    assert tables == EXPECTED_TABLES


def test_wal_mode_enabled(db):
    conn = get_connection(db)
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    conn.close()
    assert mode == "wal"


def test_init_is_idempotent(db):
    # Running init_db a second time must not raise or corrupt the schema.
    init_db(db)
    conn = get_connection(db)
    tables = {
        row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        if not row[0].startswith("sqlite_")
    }
    conn.close()
    assert tables == EXPECTED_TABLES


def test_iocs_unique_constraint(db):
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO iocs (ioc_type, ioc_value, source, source_id, fetched_at) "
        "VALUES ('url', 'http://evil.ph/', 'urlhaus', 'uh-001', '2026-06-22T00:00:00Z')"
    )
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO iocs (ioc_type, ioc_value, source, source_id, fetched_at) "
            "VALUES ('url', 'http://other.ph/', 'urlhaus', 'uh-001', '2026-06-22T01:00:00Z')"
        )
    conn.close()


def test_cves_unique_cve_id(db):
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO cves (cve_id, source, fetched_at) "
        "VALUES ('CVE-2024-1234', 'nvd', '2026-06-22T00:00:00Z')"
    )
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO cves (cve_id, source, fetched_at) "
            "VALUES ('CVE-2024-1234', 'kev', '2026-06-22T01:00:00Z')"
        )
    conn.close()


def test_cve_cpe_matches_unique(db):
    conn = get_connection(db)
    conn.execute("INSERT INTO cve_cpe_matches (cve_id, cpe) VALUES ('CVE-2024-1234', 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*')")
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO cve_cpe_matches (cve_id, cpe) VALUES ('CVE-2024-1234', 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*')")
    conn.close()


def test_ph_asns_unique(db):
    conn = get_connection(db)
    conn.execute("INSERT INTO ph_asns (asn, fetched_at) VALUES (9299, '2026-06-22T00:00:00Z')")
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO ph_asns (asn, fetched_at) VALUES (9299, '2026-06-22T01:00:00Z')")
    conn.close()


def test_ph_prefixes_unique(db):
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO ph_prefixes (prefix, prefix_type, fetched_at) "
        "VALUES ('1.2.3.0/24', 'ipv4', '2026-06-22T00:00:00Z')"
    )
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO ph_prefixes (prefix, prefix_type, fetched_at) "
            "VALUES ('1.2.3.0/24', 'ipv4', '2026-06-22T01:00:00Z')"
        )
    conn.close()


def test_sieve_matches_insert(db):
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO sieve_matches (record_type, record_id, match_criterion, matched_value, matched_at) "
        "VALUES ('ioc', 1, 'tld', '.ph', '2026-06-22T00:00:00Z')"
    )
    conn.commit()
    row = conn.execute("SELECT * FROM sieve_matches WHERE record_id=1").fetchone()
    conn.close()
    assert row["match_criterion"] == "tld"
    assert row["matched_value"] == ".ph"
