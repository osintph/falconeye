from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import requests

from falconeye.db import get_connection, init_db

log = logging.getLogger(__name__)

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_RESULTS_PER_PAGE = 2000


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _fmt(dt: datetime) -> str:
    """Format a datetime for the NVD API lastModStartDate/lastModEndDate params."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _manifest_version() -> str:
    return datetime.now(timezone.utc).strftime("%Y.%j.%H%M%S")


# --- Extraction helpers ---

def extract_description(cve: dict) -> str | None:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value")
    return None


def extract_cvss(cve: dict) -> tuple[float | None, str | None]:
    """Return (baseScore, baseSeverity) from CVSSv3.1, falling back to v3.0."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        primary = next((e for e in entries if e.get("type") == "Primary"), None)
        entry = primary or (entries[0] if entries else None)
        if entry:
            data = entry.get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity")
    return None, None


def extract_cpes(cve: dict) -> list[str]:
    """Return deduplicated list of vulnerable CPE strings from configurations."""
    cpes: set[str] = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and match.get("criteria"):
                    cpes.add(match["criteria"])
    return list(cpes)


def _trim_ts(raw: str | None) -> str | None:
    """Trim NVD timestamp to seconds-precision ISO 8601 UTC."""
    if not raw:
        return None
    return raw[:19] + "Z"


# --- Fetching ---

def _fetch_page(params: dict, api_key: str | None, pre_delay: float) -> dict:
    if pre_delay > 0:
        time.sleep(pre_delay)
    headers = {"apiKey": api_key} if api_key else {}
    resp = requests.get(_NVD_URL, headers=headers, params=params, timeout=60)
    if resp.status_code == 429:
        log.warning("NVD: rate limited (429), backing off 30s")
        time.sleep(30)
        resp = requests.get(_NVD_URL, headers=headers, params=params, timeout=60)
    resp.raise_for_status()
    return resp.json()


def fetch_pages(
    extra_params: dict | None = None,
    api_key: str | None = None,
) -> Iterator[list[dict]]:
    """
    Yield batches of raw vulnerability dicts from NVD, paginating automatically.

    Delay between pages: 6s without API key (stays within 5/30s limit),
    0.6s with key (stays within 50/30s limit).
    """
    delay = 0.6 if api_key else 6.0
    params: dict = {"resultsPerPage": _RESULTS_PER_PAGE, "startIndex": 0}
    if extra_params:
        params.update(extra_params)

    data = _fetch_page(params, api_key, pre_delay=0)
    total = data.get("totalResults", 0)
    vulns = data.get("vulnerabilities", [])
    log.info("NVD: totalResults=%d", total)
    yield vulns

    fetched = len(vulns)
    while fetched < total:
        params = {**params, "startIndex": fetched}
        data = _fetch_page(params, api_key, pre_delay=delay)
        batch = data.get("vulnerabilities", [])
        if not batch:
            break
        yield batch
        fetched += len(batch)
        log.info("NVD: fetched %d / %d", fetched, total)


# --- State ---

def _last_nvd_modified(conn) -> str | None:
    row = conn.execute(
        "SELECT MAX(last_modified) FROM cves WHERE source='nvd' AND last_modified IS NOT NULL"
    ).fetchone()
    return row[0] if row and row[0] else None


# --- Upsert ---

def _upsert_batch(conn, batch: list[dict], fetched_at: str, mv: str) -> tuple[int, int]:
    upserted = errors = 0
    for item in batch:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "").strip()
        if not cve_id:
            errors += 1
            continue

        description = extract_description(cve)
        score, severity = extract_cvss(cve)
        cpes = extract_cpes(cve)

        try:
            conn.execute(
                """
                INSERT INTO cves
                    (cve_id, published_date, last_modified, description,
                     cvss_v3_score, cvss_v3_severity,
                     source, source_id, fetched_at, source_url, manifest_version)
                VALUES (?, ?, ?, ?, ?, ?, 'nvd', ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    published_date   = excluded.published_date,
                    last_modified    = excluded.last_modified,
                    description      = excluded.description,
                    cvss_v3_score    = excluded.cvss_v3_score,
                    cvss_v3_severity = excluded.cvss_v3_severity,
                    fetched_at       = excluded.fetched_at,
                    manifest_version = excluded.manifest_version
                """,
                (
                    cve_id,
                    _trim_ts(cve.get("published")),
                    _trim_ts(cve.get("lastModified")),
                    description,
                    score,
                    severity,
                    cve_id,
                    fetched_at,
                    _NVD_URL,
                    mv,
                ),
            )
            for cpe in cpes:
                conn.execute(
                    "INSERT OR IGNORE INTO cve_cpe_matches (cve_id, cpe) VALUES (?, ?)",
                    (cve_id, cpe),
                )
            upserted += 1
        except Exception as exc:
            log.warning("NVD: skipped %s: %s", cve_id, exc)
            errors += 1

    return upserted, errors


# --- Severity backfill ---

def _backfill_kev_severity(conn, api_key: str | None) -> int:
    """
    Fetch NVD severity for sieve-matched CVEs that still have NULL cvss_v3_severity.

    KEV CVEs inserted before the first NVD full sync have NULL severity.
    Incremental NVD pulls only cover recently modified CVEs, so old KEV entries
    never get their severity populated unless we explicitly fetch them.

    Queries one CVE at a time via ?cveId= and caps at 50 per run to avoid
    blocking the main ingest cycle. Returns the count of CVEs updated.
    """
    rows = conn.execute("""
        SELECT DISTINCT c.cve_id
          FROM cves c
          JOIN sieve_matches s ON s.record_id = c.id AND s.record_type = 'cve'
         WHERE c.cvss_v3_severity IS NULL
         LIMIT 50
    """).fetchall()

    if not rows:
        return 0

    updated = 0
    for (cve_id,) in rows:
        time.sleep(0.6)
        try:
            data = _fetch_page({"cveId": cve_id}, api_key, pre_delay=0)
        except Exception as exc:
            log.warning("NVD backfill: error fetching %s: %s", cve_id, exc)
            continue
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            continue
        cve = vulns[0].get("cve", {})
        score, severity = extract_cvss(cve)
        if severity is None:
            continue
        conn.execute(
            "UPDATE cves SET cvss_v3_score=?, cvss_v3_severity=? WHERE cve_id=?",
            (score, severity, cve_id),
        )
        updated += 1

    conn.commit()
    if updated:
        log.info("NVD backfill: updated severity for %d CVEs", updated)
    return updated


# --- Public entry point ---

def ingest(
    db_path: str | Path,
    api_key: str | None = None,
    full_sync: bool = False,
    start_date: str | None = None,
) -> tuple[int, int]:
    """
    Fetch NVD CVEs and upsert into cves + cve_cpe_matches.

    Mode selection (in priority order):
      start_date provided  → incremental from that date to now
      full_sync=True       → full backfill, no date filter
      default              → incremental from MAX(last_modified) in DB,
                             or full backfill if no NVD records exist yet

    Returns (upserted, errors).
    """
    init_db(db_path)
    now = _now_utc()
    fetched_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    mv = _manifest_version()

    if start_date:
        start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
        extra_params = {
            "lastModStartDate": _fmt(start_dt),
            "lastModEndDate": _fmt(now),
        }
        log.info("NVD: incremental from %s to %s (manual start_date)", _fmt(start_dt), _fmt(now))
    elif full_sync:
        extra_params = None
        log.info("NVD: full backfill (--full-sync)")
    else:
        conn = get_connection(db_path)
        last_mod = _last_nvd_modified(conn)
        conn.close()

        if last_mod:
            start_dt = datetime.fromisoformat(last_mod.replace("Z", "+00:00"))
            start_dt -= timedelta(minutes=5)
            extra_params = {
                "lastModStartDate": _fmt(start_dt),
                "lastModEndDate": _fmt(now),
            }
            log.info("NVD: incremental from %s to %s", _fmt(start_dt), _fmt(now))
        else:
            extra_params = None
            log.info("NVD: full backfill (no prior NVD records in DB)")

    upserted = errors = 0

    try:
        for batch in fetch_pages(extra_params, api_key):
            conn = get_connection(db_path)
            u, e = _upsert_batch(conn, batch, fetched_at, mv)
            conn.commit()
            conn.close()
            upserted += u
            errors += e
    except requests.RequestException as exc:
        log.error("NVD fetch failed: %s", exc)

    log.info("NVD ingest: %d upserted, %d errors", upserted, errors)

    conn = get_connection(db_path)
    _backfill_kev_severity(conn, api_key)
    conn.close()

    return upserted, errors


if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    parser = argparse.ArgumentParser(description="FalconEye NVD CVE ingest worker")
    parser.add_argument("--full-sync", action="store_true", help="Force full backfill")
    parser.add_argument(
        "--start-date",
        metavar="ISO8601",
        help="Override start date for incremental pull (e.g. 2026-06-22T20:00:00Z)",
    )
    args = parser.parse_args()

    _api_key = os.environ.get("NVD_API_KEY")
    from falconeye.config import get_db_path
    _db = get_db_path()
    ups, errs = ingest(_db, api_key=_api_key, full_sync=args.full_sync, start_date=args.start_date)
    print(f"NVD ingest complete: {ups} upserted, {errs} errors")
