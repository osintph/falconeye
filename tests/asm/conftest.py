import os

# Point the DB at a throwaway temp file before any app module is imported, so the
# ASM tables self-initialize somewhere writable (mirrors tests/abuse).
os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import pytest

from app.asm import store
from app.routers import asm as _asm_routes

# The slowapi burst limiter has process-global state that leaks across tests.
_asm_routes.limiter.enabled = False

_ASM_TABLES = (
    "asm_domains", "asm_verifications", "asm_grants", "asm_scans", "asm_hosts",
    "asm_findings", "asm_snapshots", "asm_operator_sessions", "asm_operator_audit",
    "asm_rate_limit",
)


@pytest.fixture(autouse=True)
def _clean_asm_tables():
    store.init_tables()
    conn = store._connect()
    for table in _ASM_TABLES:
        try:
            conn.execute(f"DELETE FROM {table}")
        except Exception:
            pass
    conn.commit()
    conn.close()
    yield
