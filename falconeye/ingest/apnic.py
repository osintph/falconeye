from __future__ import annotations

import logging
import math
import os
from datetime import datetime, timezone
from pathlib import Path

import requests

from falconeye.db import get_connection, init_db

log = logging.getLogger(__name__)

_DELEGATED_URL = "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
_PH_CC = "PH"
_VALID_STATUSES = frozenset(("allocated", "assigned"))


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _manifest_version() -> str:
    return datetime.now(timezone.utc).strftime("%Y.%j.%H")


def fetch_delegated(url: str = _DELEGATED_URL) -> str:
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    return resp.text


def parse_ph_records(text: str) -> tuple[list[int], list[tuple[str, str]]]:
    """
    Parse the APNIC delegated stats file and return PH allocations.

    Returns:
        asns     — list of individual PH ASN integers (blocks expanded)
        prefixes — list of (cidr_string, "ipv4"|"ipv6") tuples
    """
    asns: list[int] = []
    prefixes: list[tuple[str, str]] = []

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split("|")

        # Format/version line starts with a digit (e.g. "2|apnic|...")
        # Summary lines have "*" as the cc field.
        # Both are caught by requiring exactly 7 pipe-delimited fields
        # and cc == PH.
        if len(parts) < 7:
            continue

        registry, cc, rec_type, start, value, date, status = parts[:7]

        if cc != _PH_CC:
            continue
        if status not in _VALID_STATUSES:
            continue

        try:
            count = int(value)
        except ValueError:
            log.debug("APNIC: unparseable value %r in line: %s", value, line)
            continue

        if rec_type == "asn":
            try:
                asn_start = int(start)
            except ValueError:
                continue
            for offset in range(count):
                asns.append(asn_start + offset)

        elif rec_type == "ipv4":
            if count <= 0 or (count & (count - 1)) != 0:
                # count must be a power of 2 per the RIR format spec
                log.warning("APNIC: non-power-of-2 IPv4 count %d for %s, skipping", count, start)
                continue
            prefix_len = 32 - int(math.log2(count))
            prefixes.append((f"{start}/{prefix_len}", "ipv4"))

        elif rec_type == "ipv6":
            # For IPv6 in the delegated stats format, 'value' is the prefix length.
            prefixes.append((f"{start}/{count}", "ipv6"))

    return asns, prefixes


def ingest(db_path: str | Path) -> tuple[int, int, int]:
    """
    Fetch the APNIC delegated file and atomically replace ph_asns / ph_prefixes.

    Returns (asn_count, prefix_count, errors).
    """
    init_db(db_path)
    fetched_at = _now_utc()
    mv = _manifest_version()

    try:
        text = fetch_delegated()
    except requests.RequestException as exc:
        log.error("APNIC fetch failed: %s", exc)
        return 0, 0, 1

    asns, prefixes = parse_ph_records(text)
    log.info("APNIC: parsed %d PH ASNs, %d PH prefixes", len(asns), len(prefixes))

    conn = get_connection(db_path)
    # Full snapshot replacement — delete old rows inside the same transaction
    # so the switch is atomic.
    conn.execute("DELETE FROM ph_asns")
    conn.execute("DELETE FROM ph_prefixes")

    errors = 0
    for asn in asns:
        try:
            conn.execute(
                "INSERT INTO ph_asns (asn, fetched_at, source_url, manifest_version) "
                "VALUES (?, ?, ?, ?)",
                (asn, fetched_at, _DELEGATED_URL, mv),
            )
        except Exception as exc:
            log.warning("APNIC: skipped ASN %d: %s", asn, exc)
            errors += 1

    for prefix, prefix_type in prefixes:
        try:
            conn.execute(
                "INSERT INTO ph_prefixes (prefix, prefix_type, fetched_at, source_url, manifest_version) "
                "VALUES (?, ?, ?, ?, ?)",
                (prefix, prefix_type, fetched_at, _DELEGATED_URL, mv),
            )
        except Exception as exc:
            log.warning("APNIC: skipped prefix %s: %s", prefix, exc)
            errors += 1

    conn.commit()
    conn.close()
    log.info("APNIC ingest: %d ASNs, %d prefixes, %d errors", len(asns), len(prefixes), errors)
    return len(asns), len(prefixes), errors


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    from falconeye.config import get_db_path
    _db = get_db_path()
    asn_count, prefix_count, errs = ingest(_db)
    print(f"APNIC ingest complete: {asn_count} ASNs, {prefix_count} prefixes, {errs} errors")
