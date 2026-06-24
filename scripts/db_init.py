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
""")

conn.commit()
conn.close()
print(f"Database initialized at {DB_PATH}")
