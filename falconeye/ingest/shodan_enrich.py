"""Shodan InternetDB enrichment for PH-matched IOC IPs."""
from __future__ import annotations

import ipaddress
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

from falconeye.db import get_connection, init_db

log = logging.getLogger(__name__)

_INTERNETDB_BASE = "https://internetdb.shodan.io"
_DAILY_CAP = 10_000
_STALENESS_HOURS = 6
# Exponential backoff sequence on 429: 5s → 10s → 20s → 40s → 60s → bail
_BACKOFF_SEQUENCE = (5.0, 10.0, 20.0, 40.0, 60.0)


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _extract_ipv4(ioc_value: str, ioc_type: str) -> str | None:
    """Return the IPv4 address from an IOC value, or None for non-IPv4 IOCs."""
    if ioc_type == "ip":
        candidate = ioc_value.strip()
    elif ioc_type == "url":
        try:
            candidate = urlparse(ioc_value).hostname or ""
        except Exception:
            return None
    else:
        return None
    try:
        addr = ipaddress.ip_address(candidate)
        return str(addr) if isinstance(addr, ipaddress.IPv4Address) else None
    except ValueError:
        return None


def _fetch_internetdb(ip: str, session: requests.Session) -> dict | None:
    """
    Fetch Shodan InternetDB data for an IP.

    Returns parsed JSON on success, {} on 404 (no data), None on unrecoverable error.
    Exponential backoff on 429: 5s, 10s, 20s, 40s, 60s, then bail.
    """
    url = f"{_INTERNETDB_BASE}/{ip}"
    backoffs = iter(_BACKOFF_SEQUENCE)
    while True:
        try:
            resp = session.get(url, timeout=10)
        except requests.RequestException as exc:
            log.error("Shodan: network error for %s: %s", ip, exc)
            return None

        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404:
            return {}
        if resp.status_code == 429:
            wait = next(backoffs, None)
            if wait is None:
                log.warning("Shodan: still rate-limited after max backoff for %s, skipping", ip)
                return None
            log.warning("Shodan: 429 rate-limited for %s, backing off %.0fs", ip, wait)
            time.sleep(wait)
            continue
        log.error("Shodan: unexpected HTTP %d for %s", resp.status_code, ip)
        return None


def _daily_count(conn) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM ip_enrichments WHERE date(fetched_at) = ?",
        (_today_utc(),),
    ).fetchone()[0]


def _is_stale(conn, ip: str) -> bool:
    """Return True if this IP has no enrichment or its enrichment is older than STALENESS_HOURS."""
    row = conn.execute(
        "SELECT fetched_at FROM ip_enrichments WHERE ip_address = ?", (ip,)
    ).fetchone()
    if not row:
        return True
    try:
        fetched = datetime.fromisoformat(row["fetched_at"].replace("Z", "+00:00"))
        age_hours = (datetime.now(timezone.utc) - fetched).total_seconds() / 3600
        return age_hours >= _STALENESS_HOURS
    except (ValueError, TypeError):
        return True


def run_shodan_enrich(db_path: str | Path) -> tuple[int, int]:
    """
    Enrich PH-matched IOC IPs with Shodan InternetDB data.

    Skips IPs enriched within the last 6 hours.
    Hard daily cap of 10,000 requests per UTC day — logs WARNING when hit.
    Returns (enriched, skipped_fresh).
    """
    init_db(db_path)

    conn = get_connection(db_path)
    count = _daily_count(conn)
    if count >= _DAILY_CAP:
        log.warning(
            "Shodan: daily cap of %d already reached for %s, aborting run",
            _DAILY_CAP, _today_utc(),
        )
        conn.close()
        return 0, 0

    rows = conn.execute("""
        SELECT DISTINCT i.ioc_value, i.ioc_type
        FROM sieve_matches s
        JOIN iocs i ON i.id = s.record_id AND s.record_type = 'ioc'
        WHERE s.match_criterion = 'asn'
    """).fetchall()
    conn.close()

    ip_set: set[str] = set()
    for row in rows:
        ip = _extract_ipv4(row["ioc_value"], row["ioc_type"])
        if ip:
            ip_set.add(ip)

    if not ip_set:
        log.info("Shodan: no PH-matched IPv4 addresses to enrich")
        return 0, 0

    log.info("Shodan: %d distinct IPs to check (daily usage so far: %d/%d)",
             len(ip_set), count, _DAILY_CAP)

    session = requests.Session()
    session.headers["User-Agent"] = "FalconEye/0.2 (https://falconeye.osintph.info)"
    enriched = skipped = 0

    for ip in sorted(ip_set):
        conn = get_connection(db_path)

        if not _is_stale(conn, ip):
            conn.close()
            skipped += 1
            continue

        count = _daily_count(conn)
        conn.close()

        if count >= _DAILY_CAP:
            log.warning("Shodan: daily cap of %d reached mid-run, stopping", _DAILY_CAP)
            break

        data = _fetch_internetdb(ip, session)
        if data is None:
            continue

        now = _now_utc()
        conn = get_connection(db_path)
        conn.execute(
            """INSERT INTO ip_enrichments
               (ip_address, ports, cpes, hostnames, tags, vulns, fetched_at, source_url)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(ip_address) DO UPDATE SET
                 ports=excluded.ports, cpes=excluded.cpes, hostnames=excluded.hostnames,
                 tags=excluded.tags, vulns=excluded.vulns, fetched_at=excluded.fetched_at,
                 source_url=excluded.source_url""",
            (
                ip,
                json.dumps(data.get("ports") or []),
                json.dumps(data.get("cpes") or []),
                json.dumps(data.get("hostnames") or []),
                json.dumps(data.get("tags") or []),
                json.dumps(data.get("vulns") or []),
                now,
                f"{_INTERNETDB_BASE}/{ip}",
            ),
        )
        conn.commit()
        conn.close()
        enriched += 1
        log.info("Shodan: enriched %s — %d ports, %d vulns, %d cpes",
                 ip, len(data.get("ports") or []),
                 len(data.get("vulns") or []), len(data.get("cpes") or []))

    log.info("Shodan: done — %d enriched, %d skipped (fresh)", enriched, skipped)
    return enriched, skipped


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    from falconeye.config import get_db_path
    _db = get_db_path()
    _enriched, _skipped = run_shodan_enrich(_db)
    print(f"Shodan enrichment complete: {_enriched} enriched, {_skipped} skipped")
