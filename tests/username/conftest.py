import os

os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import pytest

from app.username import store
from app.username import routes as _username_routes

# The slowapi burst limiter (5/min) is a separate load guard with process-global
# in-memory state that would leak across tests; disable it so tests exercise the
# SQLite quota (the actual rate-limit feature) deterministically.
_username_routes.limiter.enabled = False


@pytest.fixture(autouse=True)
def _clean_username_tables():
    store.init_tables()
    conn = store._connect()
    try:
        conn.execute("DELETE FROM username_rate_limit")
        conn.commit()
    except Exception:
        pass
    conn.close()
    yield
