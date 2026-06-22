from __future__ import annotations

import logging
import os

from falconeye.config import get_db_path
from falconeye.sieve import _DEFAULT_CONFIG_DIR, run_sieve

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

_db = get_db_path()
_cfg = os.environ.get("FALCONEYE_CONFIG_DIR", str(_DEFAULT_CONFIG_DIR))
matches, errs = run_sieve(_db, _cfg)
print(f"Sieve complete: {matches} matches, {errs} errors")
