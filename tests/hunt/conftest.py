import os

os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")
os.environ.setdefault("ASM_SIGNING_KEY", "test-asm-signing-key-not-a-secret")

import pytest

from app.asm import store
from app.routers import hunt as _hunt_routes

_hunt_routes.limiter.enabled = False

_TABLES = ("asm_scans", "asm_result_cache", "asm_scan_audit", "asm_rate_limit")


@pytest.fixture(autouse=True)
def _clean():
    store.init_tables()
    conn = store._connect()
    for t in _TABLES:
        try:
            conn.execute(f"DELETE FROM {t}")
        except Exception:
            pass
    conn.commit()
    conn.close()
    yield
