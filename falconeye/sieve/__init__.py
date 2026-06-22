from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import tldextract
import yaml

from falconeye.db import get_connection, init_db

log = logging.getLogger(__name__)

# Resolved at import time so it works whether installed with pip install -e .
# or run directly with WorkingDirectory=/opt/falconeye/src.
# Production deployments override via FALCONEYE_CONFIG_DIR.
_DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------

def _build_prefix_list(conn) -> list[ipaddress.ip_network]:
    """Load PH IP prefixes from the database as ipaddress.ip_network objects."""
    result = []
    for row in conn.execute("SELECT prefix FROM ph_prefixes"):
        try:
            result.append(ipaddress.ip_network(row[0], strict=False))
        except ValueError:
            log.warning("Sieve: skipping invalid prefix %s", row[0])
    return result


def _load_brands(config_dir: Path) -> list[str]:
    """Flatten all sections of brand_strings.yaml into a single list."""
    path = config_dir / "brand_strings.yaml"
    if not path.exists():
        log.warning("Sieve: %s not found — brand matching disabled", path)
        return []
    with path.open() as f:
        data = yaml.safe_load(f) or {}
    brands: list[str] = []
    for section in data.values():
        if isinstance(section, list):
            brands.extend(str(b) for b in section if b)
    return brands


def _load_cpe_inventory(config_dir: Path) -> list[str]:
    """Return the list of CPE prefix strings from cpe_inventory.yaml."""
    path = config_dir / "cpe_inventory.yaml"
    if not path.exists():
        log.warning("Sieve: %s not found — CPE matching disabled", path)
        return []
    with path.open() as f:
        data = yaml.safe_load(f) or {}
    return [str(c) for c in (data.get("cpes") or []) if c]


# ---------------------------------------------------------------------------
# Host extraction
# ---------------------------------------------------------------------------

def _extract_host(value: str) -> str | None:
    """Return the hostname/IP from a URL, or the value itself if not a URL."""
    value = value.strip()
    if "://" in value:
        try:
            return urlparse(value).hostname or None
        except Exception:
            return None
    return value or None


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Four matchers
# ---------------------------------------------------------------------------

def match_asn(ip_str: str, prefixes: list[ipaddress.ip_network]) -> str | None:
    """Return the first PH prefix containing ip_str, or None."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for net in prefixes:
        if addr in net:
            return str(net)
    return None


def match_tld(host: str) -> bool:
    """Return True if host's public suffix is .ph or ends with .ph."""
    try:
        suffix = tldextract.extract(host).suffix
        return suffix == "ph" or suffix.endswith(".ph")
    except Exception:
        return False


def match_brands(text: str, brands: list[str]) -> list[str]:
    """
    Return all brand strings that appear as whole tokens in text.
    Case-insensitive; uses \\b word boundaries to avoid short-acronym
    false positives (e.g. 'BPI' won't match inside 'SBPI').
    """
    if not text or not brands:
        return []
    return [
        brand for brand in brands
        if re.search(r"\b" + re.escape(brand) + r"\b", text, re.IGNORECASE)
    ]


def match_cpes(cve_cpes: list[str], inventory: list[str]) -> list[str]:
    """
    Return all inventory CPE prefixes that are a prefix of at least one
    CVE CPE string.  E.g. inventory entry 'cpe:2.3:a:cisco:ios' matches
    'cpe:2.3:a:cisco:ios:15.2:...'.
    """
    if not cve_cpes or not inventory:
        return []
    matched = []
    for inv in inventory:
        if any(actual.startswith(inv) for actual in cve_cpes):
            matched.append(inv)
    return matched


# ---------------------------------------------------------------------------
# Per-record sieve logic
# ---------------------------------------------------------------------------

def _sieve_ioc(
    ioc_value: str,
    prefixes: list[ipaddress.ip_network],
    brands: list[str],
) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    host = _extract_host(ioc_value)
    if not host:
        return results

    if _is_ip(host):
        prefix = match_asn(host, prefixes)
        if prefix:
            results.append(("asn", prefix))
    else:
        if match_tld(host):
            results.append(("tld", host))

    # Brand search over the full URL — catches brand names in path/subdomain
    for brand in match_brands(ioc_value, brands):
        results.append(("brand", brand))

    return results


def _sieve_cve(
    description: str | None,
    kev_notes_raw: str | None,
    cve_cpes: list[str],
    brands: list[str],
    cpe_inventory: list[str],
) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []

    # Build search text from description + kev_notes vendor/product
    parts = [description or ""]
    if kev_notes_raw:
        try:
            kev = json.loads(kev_notes_raw)
            parts += [
                kev.get("vendor") or "",
                kev.get("product") or "",
                kev.get("notes") or "",
            ]
        except (json.JSONDecodeError, AttributeError):
            pass
    search_text = " ".join(parts)

    for brand in match_brands(search_text, brands):
        results.append(("brand", brand))

    for inv_cpe in match_cpes(cve_cpes, cpe_inventory):
        results.append(("cpe", inv_cpe))

    return results


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_sieve(
    db_path: str | Path,
    config_dir: str | Path | None = None,
) -> tuple[int, int]:
    """
    Apply the PH sieve to all IOCs and CVEs in the database and write
    matches to sieve_matches.

    Clears existing matches before each run so results are always current.
    Returns (total_matches, errors).
    """
    init_db(db_path)
    cfg = Path(config_dir) if config_dir else _DEFAULT_CONFIG_DIR
    now = _now_utc()

    # Load sieve data
    conn = get_connection(db_path)
    prefixes = _build_prefix_list(conn)
    conn.close()

    brands = _load_brands(cfg)
    cpe_inventory = _load_cpe_inventory(cfg)

    log.info(
        "Sieve: %d PH prefixes, %d brand strings, %d CPE inventory entries",
        len(prefixes), len(brands), len(cpe_inventory),
    )

    conn = get_connection(db_path)
    conn.execute("DELETE FROM sieve_matches")

    total = errors = 0

    # --- IOCs ---
    for ioc in conn.execute("SELECT id, ioc_value FROM iocs"):
        for criterion, value in _sieve_ioc(ioc["ioc_value"] or "", prefixes, brands):
            try:
                conn.execute(
                    "INSERT INTO sieve_matches "
                    "(record_type, record_id, match_criterion, matched_value, matched_at) "
                    "VALUES ('ioc', ?, ?, ?, ?)",
                    (ioc["id"], criterion, value, now),
                )
                total += 1
            except Exception as exc:
                log.warning("Sieve: IOC %d insert failed: %s", ioc["id"], exc)
                errors += 1

    # --- CVEs ---
    for cve in conn.execute("SELECT id, cve_id, description, kev_notes FROM cves"):
        cve_cpes = [
            r[0] for r in conn.execute(
                "SELECT cpe FROM cve_cpe_matches WHERE cve_id=?", (cve["cve_id"],)
            )
        ]
        for criterion, value in _sieve_cve(
            cve["description"], cve["kev_notes"], cve_cpes, brands, cpe_inventory
        ):
            try:
                conn.execute(
                    "INSERT INTO sieve_matches "
                    "(record_type, record_id, match_criterion, matched_value, matched_at) "
                    "VALUES ('cve', ?, ?, ?, ?)",
                    (cve["id"], criterion, value, now),
                )
                total += 1
            except Exception as exc:
                log.warning("Sieve: CVE %d insert failed: %s", cve["id"], exc)
                errors += 1

    conn.commit()
    conn.close()
    log.info("Sieve: %d matches written, %d errors", total, errors)
    return total, errors


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _db = os.environ.get("FALCONEYE_DB_PATH", "db/falconeye.db")
    _cfg = os.environ.get("FALCONEYE_CONFIG_DIR", str(_DEFAULT_CONFIG_DIR))
    matches, errs = run_sieve(_db, _cfg)
    print(f"Sieve complete: {matches} matches, {errs} errors")
