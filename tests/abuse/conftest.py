import os

# Point the DB at a throwaway temp file before any app module is imported, so
# the abuse tables self-initialize somewhere writable (mirrors tests/prospect).
os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import pytest

from app.abuse import store
from app.abuse import routes as _abuse_routes

# The slowapi burst limiter (10/min) has process-global in-memory state that
# leaks across tests; disable it so endpoint tests are deterministic. The real
# rate limits (SQLite quotas) are covered at the service level.
_abuse_routes.limiter.enabled = False

_ABUSE_TABLES = (
    "abuse_contact_cache",
    "abuse_lookup_rate_limit",
    "abuse_compose_rate_limit",
    "abuse_send_rate_limit",
    "abuse_send_audit",
)


@pytest.fixture(autouse=True)
def _clean_abuse_tables():
    """Ensure tables exist and start empty for every test (rate-limit isolation)."""
    store.init_tables()
    conn = store._connect()
    for table in _ABUSE_TABLES:
        try:
            conn.execute(f"DELETE FROM {table}")
        except Exception:
            pass
    conn.commit()
    conn.close()
    yield
