import os

os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import pytest

from app.telegram import store
from app.telegram import routes as _telegram_routes

# The slowapi burst limiter (10/min) has process-global in-memory state that
# leaks across tests; disable it so endpoint tests are deterministic.
_telegram_routes.limiter.enabled = False


@pytest.fixture(autouse=True)
def _clean_telegram_cache():
    store.init_tables()
    conn = store._connect()
    try:
        conn.execute("DELETE FROM telegram_lookup_cache")
        conn.commit()
    finally:
        conn.close()
    yield
