"""RIPEstat prefix-to-ASN enrichment worker.

Reads PH prefixes with NULL asn or stale fetched_at and resolves their
origin ASN via RIPEstat's free routing-status API. For each newly discovered
ASN, fetches the holder name via as-overview and upserts into ph_asns.

No API key required. Rate-limited to 0.5s between requests. Aborts the
current cycle after 3 consecutive HTTP 429 responses.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from falconeye.db import get_connection, init_db

log = logging.getLogger(__name__)

_ROUTING_STATUS_URL = "https://stat.ripe.net/data/routing-status/data.json"
_AS_OVERVIEW_URL    = "https://stat.ripe.net/data/as-overview/data.json"
_HEADERS = {
    "User-Agent": "FalconEye/0.2.3 (osintph.info; https://github.com/osintph/falconeye)",
}
_STALE_DAYS      = 7
_RATE_SLEEP      = 0.5
_BACKOFF_START   = 5.0
_BACKOFF_CAP     = 60.0
_MAX_CONSECUTIVE_429 = 3


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fetch(url: str, params: dict, state: dict) -> dict | None:
    """
    GET a RIPEstat endpoint.  state['consecutive_429s'] is incremented on 429
    and reset to 0 on success.  Returns None on any failure so the caller can
    check state and abort.
    """
    backoff = _BACKOFF_START
    while True:
        try:
            resp = requests.get(url, params=params, headers=_HEADERS, timeout=30)
        except requests.RequestException as exc:
            log.warning("RIPEstat: network error %s params=%s: %s", url, params, exc)
            return None

        if resp.status_code == 429:
            state["consecutive_429s"] += 1
            if state["consecutive_429s"] >= _MAX_CONSECUTIVE_429:
                log.warning("RIPEstat: %d consecutive 429s — aborting cycle",
                            _MAX_CONSECUTIVE_429)
                return None
            log.warning("RIPEstat: 429 — backing off %gs", backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, _BACKOFF_CAP)
            continue

        state["consecutive_429s"] = 0
        if not resp.ok:
            log.warning("RIPEstat: HTTP %d for %s params=%s", resp.status_code, url, params)
            return None
        return resp.json()


def _origin_asn(data: dict, prefix: str) -> int | None:
    """Parse the primary origin ASN from a routing-status response."""
    vis = (data.get("data") or {}).get("visibility") or {}
    for ver in ("v4", "v6"):
        origins = (vis.get(ver) or {}).get("origins") or []
        if origins:
            raw = origins[0]
            try:
                return int(str(raw).lstrip("AS").strip())
            except (ValueError, AttributeError):
                log.debug("RIPEstat: unexpected origin format %r for %s", raw, prefix)
    return None


def _asn_holder(data: dict) -> str | None:
    """Parse holder name from an as-overview response."""
    return (data.get("data") or {}).get("holder")


def enrich(db_path, config_dir=None) -> tuple[int, int]:
    """
    Enrich ph_prefixes.asn from RIPEstat routing-status; upsert ph_asns names.

    Processes prefixes where asn IS NULL or fetched_at is older than 7 days.
    Prefixes not announced in BGP have their fetched_at updated but asn left NULL.
    Returns (prefixes_updated, errors).
    """
    init_db(db_path)
    stale_cutoff = (
        datetime.now(timezone.utc) - timedelta(days=_STALE_DAYS)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_connection(db_path)
    to_process = conn.execute("""
        SELECT prefix FROM ph_prefixes
         WHERE asn IS NULL OR fetched_at < ?
         ORDER BY prefix
    """, (stale_cutoff,)).fetchall()
    conn.close()

    if not to_process:
        log.info("RIPEstat prefix enrich: nothing to process")
        return 0, 0

    log.info("RIPEstat prefix enrich: %d prefixes to process", len(to_process))

    state = {"consecutive_429s": 0}
    now = _now_utc()
    updated = errors = 0
    new_asns: set[int] = set()

    for row in to_process:
        if state["consecutive_429s"] >= _MAX_CONSECUTIVE_429:
            log.warning("RIPEstat: aborting remaining %d prefixes after repeated 429s",
                        len(to_process))
            break

        prefix = row["prefix"]
        time.sleep(_RATE_SLEEP)

        data = _fetch(_ROUTING_STATUS_URL, {"resource": prefix}, state)
        if data is None:
            if state["consecutive_429s"] >= _MAX_CONSECUTIVE_429:
                break
            errors += 1
            continue

        asn = _origin_asn(data, prefix)

        conn = get_connection(db_path)
        if asn is None:
            log.debug("RIPEstat: %s not announced in BGP — updating fetched_at only", prefix)
            conn.execute(
                "UPDATE ph_prefixes SET fetched_at=? WHERE prefix=?",
                (now, prefix),
            )
        else:
            conn.execute(
                "UPDATE ph_prefixes SET asn=?, fetched_at=? WHERE prefix=?",
                (asn, now, prefix),
            )
            new_asns.add(asn)
            updated += 1
        conn.commit()
        conn.close()

    # Fetch holder names for all newly discovered ASNs
    for asn_int in sorted(new_asns):
        if state["consecutive_429s"] >= _MAX_CONSECUTIVE_429:
            break
        time.sleep(_RATE_SLEEP)
        data = _fetch(_AS_OVERVIEW_URL, {"resource": f"AS{asn_int}"}, state)
        if data is None:
            continue
        name = _asn_holder(data)
        conn = get_connection(db_path)
        conn.execute("""
            INSERT INTO ph_asns (asn, name, source, fetched_at, source_url)
            VALUES (?, ?, 'ripestat', ?, ?)
            ON CONFLICT(asn) DO UPDATE SET
                name       = COALESCE(excluded.name, ph_asns.name),
                source     = excluded.source,
                fetched_at = excluded.fetched_at,
                source_url = excluded.source_url
        """, (asn_int, name, now,
              f"{_AS_OVERVIEW_URL}?resource=AS{asn_int}"))
        conn.commit()
        conn.close()
        log.info("RIPEstat: upserted AS%d (%s)", asn_int, name or "unknown")

    log.info("RIPEstat prefix enrich: %d prefixes updated, %d errors", updated, errors)
    return updated, errors


if __name__ == "__main__":
    import os
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    from falconeye.config import get_db_path
    _db = get_db_path()
    ups, errs = enrich(_db)
    print(f"Prefix enrich complete: {ups} updated, {errs} errors")
