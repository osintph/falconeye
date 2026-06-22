from __future__ import annotations

import logging
import os

from falconeye.ssg import run_ssg

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

_db = os.environ.get("FALCONEYE_DB_PATH", "db/falconeye.db")
_out = os.environ.get("FALCONEYE_OUTPUT_DIR", "public")

total, errs = run_ssg(_db, _out)
print(f"SSG complete: {total} PH items rendered, {errs} errors → {_out}/")
