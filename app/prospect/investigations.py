"""
Lightweight investigation log for the Prospect/Company tab.

On every cache miss, a row is written to the `prospect_investigations` SQLite
table and the full dossier JSON is saved to disk under {DATA_DIR}/prospect/.
The ip_hash stores a SHA-256 of the client IP so the raw address is never persisted.

No history UI exists yet; this is scaffolding for a future view.
"""
import hashlib
import json
import logging
import os
import pathlib
import sqlite3
import uuid

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
            dossier_json_path TEXT NOT NULL,
            ip_hash          TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


_init_table()


def write_investigation(domain: str, generated_at: str, dossier: dict, client_ip: str) -> str:
    """Persist a dossier to disk and record the investigation in SQLite.

    Returns the investigation_id (UUID4 string).
    Silently skips on any IO or DB error to avoid breaking the request.
    """
    investigation_id = str(uuid.uuid4())
    ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()
    rel_path = f"prospect/{investigation_id}.json"

    try:
        _PROSPECT_DIR.mkdir(parents=True, exist_ok=True)
        (_DATA_DIR / rel_path).write_text(json.dumps(dossier, indent=2), encoding="utf-8")
    except Exception as exc:
        log.warning("Could not write dossier JSON for %s: %s", domain, exc)
        return investigation_id

    try:
        conn = sqlite3.connect(_DB_PATH)
        conn.execute(
            """
            INSERT INTO prospect_investigations
                (investigation_id, domain, generated_at, dossier_json_path, ip_hash)
            VALUES (?, ?, ?, ?, ?)
            """,
            (investigation_id, domain, generated_at, rel_path, ip_hash),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        log.warning("Could not write investigation row for %s: %s", domain, exc)

    return investigation_id
