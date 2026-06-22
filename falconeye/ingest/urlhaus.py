from __future__ import annotations

import csv
import io
import json
import logging
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import requests

from falconeye.db import get_connection, init_db

log = logging.getLogger(__name__)

# Recent-URLs bulk CSV (~14 days), no auth required.
# Auth-Key is forwarded when available; improves rate limits per abuse.ch policy.
_BULK_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _manifest_version() -> str:
    return datetime.now(timezone.utc).strftime("%Y.%j.%H")


def fetch_csv(auth_key: str | None = None) -> str:
    """Download the URLhaus recent-URLs CSV and return as plain text."""
    headers = {"Auth-Key": auth_key} if auth_key else {}
    resp = requests.get(_BULK_CSV_URL, headers=headers, timeout=30)
    resp.raise_for_status()

    # Bulk downloads are served as a ZIP archive.
    if resp.content[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            return zf.read(zf.namelist()[0]).decode("utf-8", errors="replace")

    content = resp.text
    # Guard: HTML response means the endpoint returned an error page.
    if content.lstrip().startswith("<"):
        raise ValueError(f"URLhaus returned unexpected HTML (status {resp.status_code})")
    return content


# URLhaus embeds its column spec inside a comment line, not as a real CSV header.
# Fieldnames are hardcoded against the stable abuse.ch schema.
_FIELDS = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]


def parse_records(text: str) -> list[dict]:
    """Strip # comment/header lines from URLhaus CSV and return parsed rows."""
    data_lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    if not data_lines:
        return []
    reader = csv.DictReader(io.StringIO("\n".join(data_lines)), fieldnames=_FIELDS)
    return list(reader)


def _split_tags(raw: str) -> list[str]:
    return [t.strip() for t in raw.split(",") if t.strip()]


def ingest(db_path: str | Path, auth_key: str | None = None) -> tuple[int, int]:
    """Fetch URLhaus CSV and upsert records into iocs. Returns (upserted, errors)."""
    init_db(db_path)
    fetched_at = _now_utc()
    mv = _manifest_version()

    try:
        text = fetch_csv(auth_key)
    except (requests.RequestException, ValueError) as exc:
        log.error("URLhaus fetch failed: %s", exc)
        return 0, 0

    records = parse_records(text)
    log.info("URLhaus: parsed %d records from feed", len(records))

    conn = get_connection(db_path)
    upserted = errors = 0

    for row in records:
        url = (row.get("url") or "").strip()
        row_id = (row.get("id") or "").strip()
        if not url or not row_id:
            errors += 1
            continue

        tags_json = json.dumps(_split_tags(row.get("tags", "")))
        try:
            conn.execute(
                """
                INSERT INTO iocs
                    (ioc_type, ioc_value, threat_type, tags,
                     first_seen, last_seen,
                     source, source_id, fetched_at, source_url, manifest_version)
                VALUES ('url', ?, ?, ?, ?, ?, 'urlhaus', ?, ?, ?, ?)
                ON CONFLICT(source, source_id) DO UPDATE SET
                    last_seen        = excluded.last_seen,
                    fetched_at       = excluded.fetched_at,
                    manifest_version = excluded.manifest_version
                """,
                (
                    url,
                    row.get("threat"),
                    tags_json,
                    row.get("dateadded"),
                    row.get("last_online") or None,
                    f"uh-{row_id}",
                    fetched_at,
                    row.get("urlhaus_link"),
                    mv,
                ),
            )
            upserted += 1
        except Exception as exc:
            log.warning("URLhaus: skipped row id=%s: %s", row_id, exc)
            errors += 1

    conn.commit()
    conn.close()
    log.info("URLhaus ingest: %d upserted, %d errors", upserted, errors)
    return upserted, errors


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _auth = os.environ.get("URLHAUS_AUTH_KEY")
    from falconeye.config import get_db_path
    _db = get_db_path()
    ups, errs = ingest(_db, _auth)
    print(f"URLhaus ingest complete: {ups} upserted, {errs} errors")
