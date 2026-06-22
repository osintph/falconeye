from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import requests

from falconeye.db import get_connection, init_db

log = logging.getLogger(__name__)

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _manifest_version() -> str:
    return datetime.now(timezone.utc).strftime("%Y.%j.%H")


def fetch_kev(url: str = _KEV_URL) -> dict:
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()


def parse_vulnerabilities(data: dict) -> list[dict]:
    return data.get("vulnerabilities", [])


def ingest(db_path: str | Path) -> tuple[int, int]:
    """Fetch CISA KEV JSON and upsert into cves. Returns (upserted, errors)."""
    init_db(db_path)
    fetched_at = _now_utc()
    mv = _manifest_version()

    try:
        data = fetch_kev()
    except requests.RequestException as exc:
        log.error("CISA KEV fetch failed: %s", exc)
        return 0, 0

    vulns = parse_vulnerabilities(data)
    log.info("CISA KEV: parsed %d vulnerabilities", len(vulns))

    conn = get_connection(db_path)
    upserted = errors = 0

    for v in vulns:
        cve_id = (v.get("cveID") or "").strip()
        if not cve_id:
            errors += 1
            continue

        # vendor, product, cwes, and the raw notes field packed into kev_notes JSON
        # so the brand sieve can reach vendor/product without extra columns.
        kev_notes = json.dumps({
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "cwes": v.get("cwes", []),
            "notes": v.get("notes", ""),
        })

        try:
            conn.execute(
                """
                INSERT INTO cves
                    (cve_id, description,
                     kev_date_added, kev_due_date, kev_required_action,
                     kev_ransomware_use, kev_notes,
                     source, source_id, fetched_at, source_url, manifest_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'kev', ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    kev_date_added      = excluded.kev_date_added,
                    kev_due_date        = excluded.kev_due_date,
                    kev_required_action = excluded.kev_required_action,
                    kev_ransomware_use  = excluded.kev_ransomware_use,
                    kev_notes           = excluded.kev_notes,
                    description = CASE
                        WHEN description IS NULL THEN excluded.description
                        ELSE description
                    END,
                    fetched_at       = excluded.fetched_at,
                    manifest_version = excluded.manifest_version
                """,
                (
                    cve_id,
                    v.get("vulnerabilityName"),
                    v.get("dateAdded"),
                    v.get("dueDate"),
                    v.get("requiredAction"),
                    v.get("knownRansomwareCampaignUse"),
                    kev_notes,
                    cve_id,
                    fetched_at,
                    _KEV_URL,
                    mv,
                ),
            )
            upserted += 1
        except Exception as exc:
            log.warning("CISA KEV: skipped %s: %s", cve_id, exc)
            errors += 1

    conn.commit()
    conn.close()
    log.info("CISA KEV ingest: %d upserted, %d errors", upserted, errors)
    return upserted, errors


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    from falconeye.config import get_db_path
    _db = get_db_path()
    ups, errs = ingest(_db)
    print(f"CISA KEV ingest complete: {ups} upserted, {errs} errors")
