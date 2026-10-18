"""One sweep for everything FalconEye promises to delete on a schedule.

Run every 15 minutes by deploy/falconeye-sweep.timer
(``python -m app.sweep``), which scripts/lib/common.sh installs from both
upgrade.sh and provision.sh. Added in v3.39.0. Before it, the Attack Surface and
Phishing Hunt results were swept only lazily, on the next hunt start or result
poll, so an idle box kept them indefinitely, and nothing deleted Company
dossiers or Image Search temp files orphaned by a restart.

Each part runs on its own: one failing does not stop the others, and the exit
status is non-zero if any failed, so `systemctl status falconeye-sweep` shows it.

  1. Attack Surface and Hunt results (payload and PDF) older than
     ASM_RESULT_TTL_SECONDS (default one hour).
  2. Run rows still holding a plain domain or keyword past that TTL (a run that
     died mid-flight), replaced with their HMAC.
  3. Company dossiers older than PROSPECT_RETENTION_DAYS (default 30).
  4. Image Search temp files older than their 15-minute lifetime.

No em dashes in this module.
"""
from __future__ import annotations

import logging
import sys

log = logging.getLogger("falconeye.sweep")


def run() -> int:
    from app import config

    failed = 0
    results = {}

    def part(name, fn):
        nonlocal failed
        try:
            results[name] = fn()
        except Exception as exc:  # noqa: BLE001 - one part must not stop the rest
            failed += 1
            results[name] = "failed"
            log.warning("sweep part %s failed: %s", name, exc)

    def _results():
        from app.asm import store
        return store.sweep_results(config.ASM_RESULT_TTL_SECONDS)

    def _redact():
        from app.asm import store
        return store.redact_stale_scans(config.ASM_RESULT_TTL_SECONDS)

    def _dossiers():
        from app.prospect import investigations
        return investigations.sweep_expired()

    def _image_temp():
        from app.image_search import upload
        return upload.sweep_expired()

    part("results", _results)
    part("redacted_runs", _redact)
    part("dossiers", _dossiers)
    part("image_temp", _image_temp)
    log.info("sweep done %s", " ".join(f"{k}={v}" for k, v in results.items()))
    return 1 if failed else 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
    sys.exit(run())
