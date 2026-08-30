"""GET /api/scanner/history is unauthenticated, so it must not return secrets.

The finding was `SELECT *`: whatever the phishing_scans table happens to hold ends
up in an anonymous response. Today that includes telegram_bot_id — the live bot
token lifted out of a kit's exfiltration call. Returning it burns the token for
investigative use and hands it to whoever asks.

Written against the bug CLASS: the assertion is "the response carries only the
columns this endpoint explicitly allows", so a sensitive column added to the table
later fails these tests instead of quietly shipping.
"""
import os
import sqlite3

import pytest

os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from slowapi import _rate_limit_exceeded_handler  # noqa: E402
from slowapi.errors import RateLimitExceeded  # noqa: E402

from app.database import get_db  # noqa: E402
from app.routers import scanner  # noqa: E402
from app.routers.scanner import _HISTORY_COLUMNS  # noqa: E402

# A real-shaped Telegram bot token: the exact value that must never be served.
FAKE_TOKEN = "7612345678:AAHxYz-ThisIsAFakeBotTokenForTestingOnly1234"

SCHEMA = """
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
"""


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "history.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.execute(
        "INSERT INTO phishing_scans (url_hash, target_brand, phishing_url, "
        "telegram_bot_id, kit_indicators, is_live) VALUES (?,?,?,?,?,?)",
        ("hash1", "BPI", "https://bpi-secure.example/login", FAKE_TOKEN,
         '["telegram_exfil"]', 1),
    )
    conn.commit()
    conn.close()

    def _override():
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # Only the scanner router is mounted, not app.main: importing the whole app
    # drags in qr_analyzer -> pyzbar, a native dependency that is not present in
    # every dev environment. The endpoint under test needs neither.
    app = FastAPI()
    app.state.limiter = scanner.limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(scanner.router)
    app.dependency_overrides[get_db] = _override

    with TestClient(app) as test_client:
        yield test_client


def test_history_never_returns_the_extracted_token(client):
    res = client.get("/api/scanner/history")
    assert res.status_code == 200
    assert FAKE_TOKEN not in res.text
    assert "telegram_bot_id" not in res.text


def test_history_returns_only_allowlisted_columns(client):
    """Any column added to phishing_scans is withheld until listed on purpose."""
    rows = client.get("/api/scanner/history").json()
    assert rows, "the endpoint must still return records"
    for row in rows:
        assert set(row) == set(_HISTORY_COLUMNS)


def test_the_allowlist_itself_excludes_the_token_column():
    assert "telegram_bot_id" not in _HISTORY_COLUMNS


def test_history_still_returns_useful_records(client):
    """Stripping the token must not gut the endpoint."""
    rows = client.get("/api/scanner/history").json()
    row = rows[0]
    assert row["phishing_url"] == "https://bpi-secure.example/login"
    assert row["target_brand"] == "BPI"
    assert row["kit_indicators"] == '["telegram_exfil"]'
    assert row["url_hash"] == "hash1"
    assert row["date_scanned"]
