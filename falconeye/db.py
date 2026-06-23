from __future__ import annotations

import sqlite3
from pathlib import Path

# All CREATE TABLE / CREATE INDEX statements.  PRAGMAs are handled by
# get_connection() so they apply to every connection, not just first-run.
_DDL = """
CREATE TABLE IF NOT EXISTS iocs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type         TEXT    NOT NULL,        -- 'url', 'ip', 'domain', 'hash'
    ioc_value        TEXT    NOT NULL,
    threat_type      TEXT,
    tags             TEXT,                    -- JSON-encoded list
    confidence       INTEGER,                 -- 0-100
    first_seen       TEXT,                    -- ISO8601 UTC
    last_seen        TEXT,                    -- ISO8601 UTC
    source           TEXT    NOT NULL,
    source_id        TEXT,
    fetched_at       TEXT    NOT NULL,        -- ISO8601 UTC
    source_url       TEXT,
    manifest_version TEXT,
    UNIQUE(source, source_id)
);

CREATE TABLE IF NOT EXISTS cves (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id               TEXT    NOT NULL UNIQUE,
    published_date       TEXT,                -- ISO8601 UTC
    last_modified        TEXT,                -- ISO8601 UTC
    description          TEXT,
    -- cvss_v3_score / cvss_v3_severity: pre-v0.2.2 these were populated with CVSS v3
    -- data only.  From v0.2.2 forward they may also hold CVSS v2 values when v3 is
    -- unavailable (most CVEs published before 2015).  The cvss_version column records
    -- which CVSS version supplied each row's score: 'v3.1', 'v3.0', or 'v2.0'.
    -- Existing pre-2007 records in production databases receive cvss_version
    -- retroactively as the backfill loop re-reaches them; this is expected, not an error.
    cvss_v3_score        REAL,
    cvss_v3_severity     TEXT,               -- 'CRITICAL','HIGH','MEDIUM','LOW','NONE'
    cvss_version         TEXT,               -- 'v3.1', 'v3.0', 'v2.0', or NULL (not yet scored)
    -- KEV-specific fields; NULL for CVEs sourced only from NVD
    kev_date_added       TEXT,
    kev_due_date         TEXT,
    kev_required_action  TEXT,
    kev_ransomware_use   TEXT,               -- 'Known' or 'Unknown'
    kev_notes            TEXT,
    source               TEXT    NOT NULL,
    source_id            TEXT,
    fetched_at           TEXT    NOT NULL,   -- ISO8601 UTC
    source_url           TEXT,
    manifest_version     TEXT
);

CREATE TABLE IF NOT EXISTS cve_cpe_matches (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id  TEXT    NOT NULL,
    cpe     TEXT    NOT NULL,
    UNIQUE(cve_id, cpe)
);

CREATE TABLE IF NOT EXISTS ph_asns (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    asn              INTEGER NOT NULL UNIQUE,
    name             TEXT,
    source           TEXT    NOT NULL DEFAULT 'apnic',
    fetched_at       TEXT    NOT NULL,
    source_url       TEXT,
    manifest_version TEXT
);

CREATE TABLE IF NOT EXISTS ph_prefixes (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix           TEXT    NOT NULL UNIQUE,  -- CIDR, e.g. '1.2.3.0/24'
    prefix_type      TEXT    NOT NULL,          -- 'ipv4' or 'ipv6'
    asn              INTEGER,
    source           TEXT    NOT NULL DEFAULT 'apnic',
    fetched_at       TEXT    NOT NULL,
    source_url       TEXT,
    manifest_version TEXT
);

CREATE TABLE IF NOT EXISTS sieve_matches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    record_type     TEXT    NOT NULL,   -- 'ioc' or 'cve'
    record_id       INTEGER NOT NULL,   -- FK into iocs.id or cves.id
    match_criterion TEXT    NOT NULL,   -- 'asn', 'tld', 'brand', 'cpe'
    matched_value   TEXT    NOT NULL,   -- the specific string/ASN that matched
    matched_at      TEXT    NOT NULL    -- ISO8601 UTC
);

CREATE TABLE IF NOT EXISTS ip_enrichments (
    ip_address  TEXT    NOT NULL PRIMARY KEY,
    ports       TEXT,           -- JSON list of integers
    cpes        TEXT,           -- JSON list of CPE strings
    hostnames   TEXT,           -- JSON list of strings
    tags        TEXT,           -- JSON list of strings (e.g. ["iot","self-signed"])
    vulns       TEXT,           -- JSON list of CVE IDs reported by Shodan
    fetched_at  TEXT    NOT NULL,
    source_url  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    slug            TEXT    NOT NULL UNIQUE,
    name            TEXT    NOT NULL,
    summary         TEXT,
    campaign_type   TEXT    NOT NULL,    -- 'domain', 'asn_tag', 'prefix24'
    cluster_key     TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'active',  -- 'active','dormant','expired'
    ioc_count       INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT,
    last_seen       TEXT,
    expired_at      TEXT,                -- set when status transitions to 'expired'
    generated_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS campaign_iocs (
    campaign_id INTEGER NOT NULL,
    ioc_id      INTEGER NOT NULL,
    UNIQUE(campaign_id, ioc_id)
);

CREATE TABLE IF NOT EXISTS ingest_state (
    source         TEXT PRIMARY KEY,
    backfill_done  INTEGER NOT NULL DEFAULT 0,  -- 1 when full backfill is complete
    oldest_reached TEXT,                         -- ISO8601 UTC; earliest pubEndDate fetched so far
    last_run       TEXT NOT NULL                 -- ISO8601 UTC of last successful ingest
);

CREATE INDEX IF NOT EXISTS idx_iocs_value            ON iocs(ioc_value);
CREATE INDEX IF NOT EXISTS idx_iocs_fetched          ON iocs(fetched_at);
CREATE INDEX IF NOT EXISTS idx_cves_fetched          ON cves(fetched_at);
CREATE INDEX IF NOT EXISTS idx_sieve_record          ON sieve_matches(record_type, record_id);
CREATE INDEX IF NOT EXISTS idx_ip_enrichments_fetched ON ip_enrichments(fetched_at);
CREATE INDEX IF NOT EXISTS idx_campaigns_status      ON campaigns(status);
CREATE INDEX IF NOT EXISTS idx_campaigns_generated   ON campaigns(generated_at);
CREATE INDEX IF NOT EXISTS idx_campaign_iocs_campaign ON campaign_iocs(campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaign_iocs_ioc     ON campaign_iocs(ioc_id);
CREATE INDEX IF NOT EXISTS idx_cves_published        ON cves(published_date);
"""


def get_connection(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str | Path) -> None:
    """Create the database file and apply the schema (idempotent)."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db_path)
    conn.executescript(_DDL)
    # Column migration for databases created before v0.2.2.
    # SQLite has no ADD COLUMN IF NOT EXISTS; the try/except is idiomatic.
    try:
        conn.execute("ALTER TABLE cves ADD COLUMN cvss_version TEXT")
        conn.commit()
    except Exception:
        pass  # column already exists in this database
    conn.close()
