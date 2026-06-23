import sqlite3
import pytest
from falconeye.db import get_connection, init_db

EXPECTED_TABLES = {
    "iocs", "cves", "cve_cpe_matches", "ph_asns", "ph_prefixes", "sieve_matches",
    "ip_enrichments", "campaigns", "campaign_iocs", "ingest_state",
}


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


def test_ip_enrichments_insert(db):
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO ip_enrichments (ip_address, ports, fetched_at, source_url) "
        "VALUES ('1.2.3.4', '[80,443]', '2026-06-23T00:00:00Z', 'https://internetdb.shodan.io/1.2.3.4')"
    )
    conn.commit()
    row = conn.execute("SELECT * FROM ip_enrichments WHERE ip_address='1.2.3.4'").fetchone()
    conn.close()
    assert row["ports"] == "[80,443]"


def test_campaigns_insert_and_unique_slug(db):
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO campaigns (slug, name, campaign_type, cluster_key, generated_at) "
        "VALUES ('test-slug-20260623', 'Test Campaign', 'domain', 'evil.com.ph', '2026-06-23T00:00:00Z')"
    )
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO campaigns (slug, name, campaign_type, cluster_key, generated_at) "
            "VALUES ('test-slug-20260623', 'Duplicate', 'domain', 'evil.com.ph', '2026-06-23T01:00:00Z')"
        )
    conn.close()


def test_campaign_iocs_unique_pair(db):
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO campaign_iocs (campaign_id, ioc_id) VALUES (1, 42)"
    )
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO campaign_iocs (campaign_id, ioc_id) VALUES (1, 42)")
    conn.close()


# ---------------------------------------------------------------------------
# v0.2.2 schema additions
# ---------------------------------------------------------------------------

def test_ingest_state_table_created(db):
    conn = get_connection(db)
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='ingest_state'"
    ).fetchone()
    conn.close()
    assert row is not None


def test_cves_cvss_version_column_exists(db):
    conn = get_connection(db)
    cols = [r["name"] for r in conn.execute("PRAGMA table_info(cves)")]
    conn.close()
    assert "cvss_version" in cols


def test_init_db_migration_idempotent(tmp_path):
    """Calling init_db on a database that already has cvss_version must not raise."""
    path = tmp_path / "migrate.db"
    init_db(path)
    init_db(path)
