from __future__ import annotations

import logging

from falconeye.config import get_db_path, get_output_dir
from falconeye.ssg import run_ssg

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

_db = get_db_path()
_out = get_output_dir()

total, errs = run_ssg(_db, _out)
print(f"SSG complete: {total} PH items rendered, {errs} errors → {_out}/")
