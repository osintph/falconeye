import os

# Point the DB at a throwaway temp file before any app module is imported, so
# the kit cache and rate-limit tables self-initialize somewhere writable
# (mirrors tests/abuse and tests/prospect).
os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import sqlite3

import pytest

from app.config import DB_PATH

_KIT_TABLES = (
    "kit_analysis_cache",
    "kit_report_rate_limit",
)


@pytest.fixture(autouse=True)
def _clean_kit_tables():
    """Start every test with empty kit tables so cache and quota do not leak."""
    conn = sqlite3.connect(DB_PATH)
    for table in _KIT_TABLES:
        try:
            conn.execute(f"DELETE FROM {table}")
        except Exception:
            pass
    conn.commit()
    conn.close()
    yield
