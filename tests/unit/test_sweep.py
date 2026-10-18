"""The 15-minute sweep (app/sweep.py, v3.39.0) and the Image Search temp clean.

Before v3.39.0 one-time results were swept only on the next hunt start or result
poll, so an idle box kept them; Company dossiers and Image Search temp files
orphaned by a restart were never deleted at all.
"""
import os
import time

from app import sweep
from app.image_search import upload


def test_the_sweep_runs_every_part_and_reports_failure(monkeypatch):
    calls = []
    from app.asm import store
    from app.prospect import investigations
    monkeypatch.setattr(store, "sweep_results", lambda ttl: calls.append(("results", ttl)) or 0)
    monkeypatch.setattr(store, "redact_stale_scans", lambda ttl: calls.append(("redact", ttl)) or 0)
    monkeypatch.setattr(investigations, "sweep_expired", lambda: calls.append(("dossiers",)) or {})
    monkeypatch.setattr(upload, "sweep_expired", lambda: calls.append(("image",)) or 0)
    assert sweep.run() == 0
    from app import config
    assert ("results", config.ASM_RESULT_TTL_SECONDS) in calls
    assert ("redact", config.ASM_RESULT_TTL_SECONDS) in calls
    assert ("dossiers",) in calls and ("image",) in calls

    def boom(*a):
        raise RuntimeError("x")
    monkeypatch.setattr(store, "sweep_results", boom)
    calls.clear()
    assert sweep.run() == 1, "a failed part must make the unit fail"
    assert ("image",) in calls, "one failing part stopped the rest"


def test_image_temp_files_past_their_lifetime_are_deleted(tmp_path, monkeypatch):
    monkeypatch.setattr(upload, "_UPLOAD_DIR", tmp_path)
    old = tmp_path / "a.png"
    old.write_bytes(b"x")
    past = time.time() - upload._CLEANUP_DELAY - 60
    os.utime(old, (past, past))
    fresh = tmp_path / "b.png"
    fresh.write_bytes(b"x")
    assert upload.sweep_expired() == 1
    assert not old.exists() and fresh.exists()


def test_the_service_cleans_image_temp_on_startup():
    src = open("app/main.py", encoding="utf-8").read()
    assert "from app.image_search.upload import sweep_expired as _sweep_image_temp" in src
    assert "_sweep_image_temp()" in src
