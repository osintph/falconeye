import sqlite3
import os

DB_PATH = os.getenv("FALCONEYE_DB", "/opt/falconeye/data/falconeye.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.executescript("""
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS phishing_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_hash TEXT UNIQUE,
    target_brand TEXT,
    phishing_url TEXT NOT NULL,
    telegram_bot_id TEXT,
    kit_indicators TEXT,
    is_live INTEGER DEFAULT 1,
    ingest_source TEXT DEFAULT 'manual',
    date_scanned DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS news_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_category TEXT NOT NULL,
    feed_source TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    summary TEXT,
    published_at TEXT,
    fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_news_category ON news_cache(feed_category);
CREATE INDEX IF NOT EXISTS idx_news_fetched ON news_cache(fetched_at);
CREATE INDEX IF NOT EXISTS idx_phishing_hash ON phishing_scans(url_hash);

CREATE TABLE IF NOT EXISTS domain_intel_cache (
    domain TEXT PRIMARY KEY,
    rdap_json TEXT,
    whois_text TEXT,
    dns_json TEXT,
    ct_json TEXT,
    network_json TEXT,
    fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_domain_cache_fetched ON domain_intel_cache(fetched_at);

CREATE TABLE IF NOT EXISTS telegram_cache (
    channel TEXT PRIMARY KEY,
    response_json TEXT,
    fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_telegram_cache_fetched ON telegram_cache(fetched_at);

CREATE TABLE IF NOT EXISTS ip_intel_cache (
    ip TEXT PRIMARY KEY,
    response_json TEXT,
    fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sandbox_cache (
    indicator_key TEXT PRIMARY KEY,
    response_json TEXT,
    fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ip_cache_fetched ON ip_intel_cache(fetched_at);
CREATE INDEX IF NOT EXISTS idx_sandbox_cache_fetched ON sandbox_cache(fetched_at);

CREATE TABLE IF NOT EXISTS threat_pulse_cache (
    id TEXT PRIMARY KEY,
    response_json TEXT,
    fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS prospect_investigations (
    investigation_id  TEXT PRIMARY KEY,
    domain            TEXT NOT NULL,
    generated_at      TEXT NOT NULL,
    dossier_json_path TEXT NOT NULL,
    ip_hash           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_prospect_domain ON prospect_investigations(domain);
CREATE INDEX IF NOT EXISTS idx_prospect_generated ON prospect_investigations(generated_at);
""")

conn.commit()
conn.close()
print(f"Database initialized at {DB_PATH}")
