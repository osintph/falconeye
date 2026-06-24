import sqlite3
import os

DB_PATH = "/opt/falconeye/data/falconeye.db"
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.executescript("""
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS scam_texts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256_hash TEXT NOT NULL UNIQUE,
    brand_tag TEXT NOT NULL,
    sender_id TEXT,
    message_content TEXT NOT NULL,
    extracted_url TEXT,
    date_reported DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS phishing_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_brand TEXT,
    phishing_url TEXT NOT NULL,
    telegram_bot_id TEXT,
    kit_indicators TEXT,
    is_live INTEGER DEFAULT 1,
    date_scanned DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'pending',
    result TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scam_texts_brand ON scam_texts(brand_tag);
CREATE INDEX IF NOT EXISTS idx_scam_texts_date ON scam_texts(date_reported);
CREATE INDEX IF NOT EXISTS idx_phishing_scans_url ON phishing_scans(phishing_url);
""")

conn.commit()
conn.close()
print(f"Database initialized at {DB_PATH}")
