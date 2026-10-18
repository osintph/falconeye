"""
Lightweight investigation log for the Prospect/Company tab.

On every cache miss, a row is written to the `prospect_investigations` SQLite
table and the full dossier JSON is saved to disk under {DATA_DIR}/prospect/.

Retention (v3.39.0): sweep_expired() deletes dossiers older than
PROSPECT_RETENTION_DAYS (default 30), run every 15 minutes by app/sweep.py from
falconeye-sweep.timer. Until v3.39.0 they were kept forever, together with an
unsalted SHA-256 of the caller's IP that nothing ever read; the IP is no longer
stored at all, and the 3.39.0 release action drops the column.

No history UI exists yet; this is scaffolding for a future view.
"""
import json
import logging
import os
import pathlib
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from app import config
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.prospect.investigations")

_DB_PATH = os.getenv("FALCONEYE_DB", "/opt/falconeye/data/falconeye.db")
_DATA_DIR = pathlib.Path(os.path.dirname(_DB_PATH))
_PROSPECT_DIR = _DATA_DIR / "prospect"


def _init_table() -> None:
    conn = sqlite3.connect(_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS prospect_investigations (
            investigation_id TEXT PRIMARY KEY,
            domain           TEXT NOT NULL,
            generated_at     TEXT NOT NULL,
            dossier_json_path TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _has_ip_column(conn: sqlite3.Connection) -> bool:
    """True on a database the 3.39.0 release action has not migrated yet, where
    the old NOT NULL ip_hash column still exists. The insert then writes an empty
    string into it rather than an IP hash."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(prospect_investigations)")]
    return "ip_hash" in cols


_init_table()


def write_investigation(domain: str, generated_at: str, dossier: dict) -> str:
    """Persist a dossier to disk and record the investigation in SQLite.

    Returns the investigation_id (UUID4 string).
    Silently skips on any IO or DB error to avoid breaking the request.
    """
    investigation_id = str(uuid.uuid4())
    rel_path = f"prospect/{investigation_id}.json"

    try:
        _PROSPECT_DIR.mkdir(parents=True, exist_ok=True)
        (_DATA_DIR / rel_path).write_text(json.dumps(dossier, indent=2), encoding="utf-8")
    except Exception as exc:
        log.warning("Could not write dossier JSON for %s: %s", tag(domain), exc)
        return investigation_id

    try:
        conn = sqlite3.connect(_DB_PATH)
        if _has_ip_column(conn):
            conn.execute(
                "INSERT INTO prospect_investigations "
                "(investigation_id, domain, generated_at, dossier_json_path, ip_hash) "
                "VALUES (?, ?, ?, ?, '')",
                (investigation_id, domain, generated_at, rel_path),
            )
        else:
            conn.execute(
                "INSERT INTO prospect_investigations "
                "(investigation_id, domain, generated_at, dossier_json_path) VALUES (?, ?, ?, ?)",
                (investigation_id, domain, generated_at, rel_path),
            )
        conn.commit()
        conn.close()
    except Exception as exc:
        log.warning("Could not write investigation row for %s: %s", tag(domain), exc)

    return investigation_id


def _parse_ts(value: str):
    try:
        ts = datetime.fromisoformat((value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def sweep_expired(days: int | None = None) -> dict:
    """Delete dossiers older than *days* (PROSPECT_RETENTION_DAYS by default):
    the row and its JSON file, plus any JSON file in the dossier directory with no
    row that is older than the cutoff by modification time. A row whose timestamp
    cannot be parsed is judged by its file's modification time, and a row whose
    file is missing by its timestamp alone. Returns {"rows": n, "files": n}."""
    days = config.PROSPECT_RETENTION_DAYS if days is None else days
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out = {"rows": 0, "files": 0}
    try:
        conn = sqlite3.connect(_DB_PATH)
    except sqlite3.Error as exc:
        log.warning("prospect sweep: cannot open the database: %s", exc)
        return out
    try:
        rows = conn.execute(
            "SELECT investigation_id, generated_at, dossier_json_path FROM prospect_investigations"
        ).fetchall()
        known = set()
        for inv_id, generated_at, rel_path in rows:
            path = _DATA_DIR / rel_path if rel_path else None
            if path is not None:
                known.add(path.name)
            ts = _parse_ts(generated_at)
            if ts is None and path is not None and path.exists():
                ts = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            if ts is None or ts >= cutoff:
                continue
            if path is not None:
                try:
                    path.unlink(missing_ok=True)
                    out["files"] += 1
                except OSError as exc:
                    log.warning("prospect sweep: could not delete a dossier file: %s", exc)
                    continue
            conn.execute("DELETE FROM prospect_investigations WHERE investigation_id = ?", (inv_id,))
            out["rows"] += 1
        conn.commit()
    finally:
        conn.close()
    if _PROSPECT_DIR.is_dir():
        for path in _PROSPECT_DIR.glob("*.json"):
            if path.name in known:
                continue
            try:
                if datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) < cutoff:
                    path.unlink()
                    out["files"] += 1
            except OSError:
                pass
    return out
