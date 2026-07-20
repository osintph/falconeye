import os
import sqlite3

os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import pytest

# Disable the slowapi burst limiter on the IP router so endpoint tests that make
# several lookups don't trip it (the real quota is unrelated to these tests).
from app.routers import ip_intel as _ip_intel

_ip_intel.limiter.enabled = False


@pytest.fixture(autouse=True)
def _fresh_env(monkeypatch):
    # Start each test from a known key state; individual tests set what they need.
    for var in ("ABUSEIPDB_KEY", "VT_KEY", "OTX_API_KEY", "CENSYS_PAT", "CENSYS_ORG_ID", "ABUSECH_AUTH_KEY"):
        monkeypatch.delenv(var, raising=False)
    # Clear the IP cache so tests don't hit rows cached by other suites/runs
    # (e.g. an 8.8.8.8 row from the older ip_intel regression test).
    try:
        conn = sqlite3.connect(os.getenv("FALCONEYE_DB", "/tmp/falconeye_test.db"))
        conn.execute("DELETE FROM ip_intel_cache")
        conn.commit()
        conn.close()
    except Exception:
        pass
    yield
