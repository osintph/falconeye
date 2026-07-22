import os

os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import pytest

from app.breach import store
from app.breach import routes as _breach_routes

# The slowapi burst limiter (10/min) has process-global in-memory state that
# leaks across tests; disable it so endpoint tests are deterministic.
_breach_routes.limiter.enabled = False


@pytest.fixture(autouse=True)
def _clean_breach_tables():
    store.init_tables()
    conn = store._connect()
    try:
        conn.execute("DELETE FROM breach_cache")
        conn.execute("DELETE FROM breach_rate_limit")
        conn.commit()
    finally:
        conn.close()
    yield
