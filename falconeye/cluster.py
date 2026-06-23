"""Campaign clustering for PH-matched IOCs."""
from __future__ import annotations

import ipaddress
import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse

import tldextract
import yaml

from falconeye.db import get_connection, init_db

log = logging.getLogger(__name__)

_DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
_ROLLING_DAYS = 14
_MIN_CLUSTER = 3
# Domain component of PSL entries for known cloud hosting platforms.
# For these, group by the account subdomain rather than the PSL entry itself.
_HOSTING_PSL_DOMAINS = frozenset({"workers", "pages", "github", "netlify", "vercel", "glitch"})


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_asn_operators(config_dir: Path) -> dict[int, dict]:
    path = config_dir / "asn_operators.yaml"
    if not path.exists():
        log.warning("Cluster: asn_operators.yaml not found at %s", path)
        return {}
    with path.open() as f:
        data = yaml.safe_load(f) or {}
    return {int(k): v for k, v in (data.get("operators") or {}).items()}


def _load_tag_priority(config_dir: Path) -> list[dict]:
    path = config_dir / "cluster_tag_priority.yaml"
    if not path.exists():
        log.warning(
            "Cluster: cluster_tag_priority.yaml not found at %s"
            " — ASN+tag clustering disabled", path,
        )
        return []
    with path.open() as f:
        data = yaml.safe_load(f) or {}
    return data.get("priority_levels") or []


def _select_primary_tag(tags: list[str], priority_levels: list[dict]) -> str | None:
    """
    Return the single highest-priority tag from an IOC's tag list.

    Checks priority_levels in order; within a matching level picks the
    alphabetically-first tag (case-insensitive comparison, original case returned).
    Returns None if no tag matches any level — the caller should skip the IOC
    from ASN+tag clustering.
    """
    if not tags or not priority_levels:
        return None
    normalized = {t.strip().lower(): t.strip() for t in tags if t.strip()}
    for level in priority_levels:
        level_tags_lower = [t.lower() for t in (level.get("tags") or [])]
        matches = [(lt, normalized[lt]) for lt in level_tags_lower if lt in normalized]
        if matches:
            return sorted(matches, key=lambda x: x[0])[0][1]
    return None


def effective_grouping_domain(host: str) -> str | None:
    """
    Return the campaign cluster key for a hostname.

    For most domains: the registered domain (e.g. evil.com.ph).
    For known CDN/hosting PSL entries (workers.dev, github.io, etc.):
    group by the account subdomain instead (e.g. chris-smart.workers.dev).
    """
    try:
        ext = tldextract.extract(host)
    except Exception:
        return None
    if not ext.domain:
        return None
    if ext.domain in _HOSTING_PSL_DOMAINS and ext.subdomain:
        account = ext.subdomain.split(".")[-1]
        return f"{account}.{ext.domain}.{ext.suffix}"
    return f"{ext.domain}.{ext.suffix}"


def _host_if_domain(ioc_value: str, ioc_type: str) -> str | None:
    """Return the hostname from an IOC only if it is a domain (not an IP)."""
    if ioc_type == "url":
        try:
            host = urlparse(ioc_value).hostname or ""
        except Exception:
            return None
    elif ioc_type == "domain":
        host = ioc_value.strip()
    else:
        return None
    try:
        ipaddress.ip_address(host)
        return None  # it's an IP — skip
    except ValueError:
        return host or None


def _ipv4_from_ioc(ioc_value: str, ioc_type: str) -> str | None:
    """Return the IPv4 address from an IOC, or None."""
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


def make_slug(campaign_type: str, cluster_key: str) -> str:
    """Derive a stable URL-safe slug from campaign type and cluster key."""
    prefix = {"domain": "dom", "asn_tag": "ast", "prefix24": "pfx"}[campaign_type]
    safe = re.sub(r"[^a-z0-9]+", "-", cluster_key.lower()).strip("-")
    return f"{prefix}-{safe}"[:80]


def _campaign_status(last_seen_iso: str) -> str:
    try:
        last = datetime.fromisoformat(last_seen_iso.replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - last).total_seconds() / 86400
    except (ValueError, AttributeError):
        return "active"
    if age_days <= 7:
        return "active"
    if age_days <= 30:
        return "dormant"
    return "expired"


def _most_common_threat_type(rows: list) -> str:
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        tt = (row["threat_type"] if hasattr(row, "__getitem__") else getattr(row, "threat_type", None)) or "unknown"
        counts[tt] += 1
    return max(counts, key=counts.__getitem__) if counts else "unknown"


def run_clustering(
    db_path,
    config_dir=None,
) -> tuple[int, int]:
    """
    Cluster PH-matched IOCs into campaigns.

    Idempotent upsert by slug: existing campaigns get their fields refreshed
    and junction rows replaced. Campaigns absent from the current run are
    marked status='expired' with expired_at set. New slugs are inserted.
    Returns (campaigns_written, errors).
    """
    init_db(db_path)
    cfg = Path(config_dir) if config_dir else _DEFAULT_CONFIG_DIR
    asn_map = _load_asn_operators(cfg)
    tag_priority = _load_tag_priority(cfg)
    now = _now_utc()
    cutoff_iso = (datetime.now(timezone.utc) - timedelta(days=_ROLLING_DAYS)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    conn = get_connection(db_path)

    all_matched = conn.execute("""
        SELECT i.id, i.ioc_value, i.ioc_type, i.threat_type, i.tags,
               i.first_seen, i.fetched_at, s.match_criterion, s.matched_value
        FROM sieve_matches s
        JOIN iocs i ON i.id = s.record_id AND s.record_type = 'ioc'
    """).fetchall()

    prefix_to_asn: dict[str, int | None] = {
        row["prefix"]: row["asn"]
        for row in conn.execute("SELECT prefix, asn FROM ph_prefixes")
    }

    existing: dict[str, int] = {
        row["slug"]: row["id"]
        for row in conn.execute("SELECT slug, id FROM campaigns")
    }

    # ── Bucket 1: domain clustering (all time) ────────────────────────────────
    domain_buckets: dict[str, list] = defaultdict(list)
    for row in all_matched:
        host = _host_if_domain(row["ioc_value"], row["ioc_type"])
        if not host:
            continue
        gd = effective_grouping_domain(host)
        if gd:
            domain_buckets[gd].append(row)

    # ── Bucket 2: ASN+tag clustering (14-day rolling window) ─────────────────
    asn_tag_buckets: dict[tuple, list] = defaultdict(list)
    for row in all_matched:
        if row["match_criterion"] != "asn":
            continue
        if (row["fetched_at"] or "") < cutoff_iso:
            continue
        asn = prefix_to_asn.get(row["matched_value"])
        tags = json.loads(row["tags"] or "[]") if row["tags"] else []
        primary_tag = _select_primary_tag(tags, tag_priority)
        if primary_tag is None:
            if tags:
                log.warning(
                    "Cluster: IOC %s has unrecognized tags %s — skipped from ASN+tag clustering",
                    row["id"], tags,
                )
            continue
        asn_tag_buckets[(asn, row["matched_value"], primary_tag)].append(row)

    # ── Bucket 3: /24 clustering (14-day rolling window) ─────────────────────
    prefix24_buckets: dict[str, list] = defaultdict(list)
    for row in all_matched:
        if row["match_criterion"] != "asn":
            continue
        if (row["fetched_at"] or "") < cutoff_iso:
            continue
        ip = _ipv4_from_ioc(row["ioc_value"], row["ioc_type"])
        if not ip:
            continue
        try:
            net24 = str(ipaddress.ip_interface(f"{ip}/24").network)
        except ValueError:
            continue
        prefix24_buckets[net24].append(row)

    # ── Filter, name, and upsert ──────────────────────────────────────────────
    written = errors = 0
    new_slugs: set[str] = set()

    def _upsert(ctype: str, cluster_key: str, name: str, summary: str, rows: list) -> None:
        nonlocal written, errors
        if len(rows) < _MIN_CLUSTER:
            return
        slug = make_slug(ctype, cluster_key)
        new_slugs.add(slug)
        ioc_ids = list({row["id"] for row in rows})
        first_seen = min(
            (row["first_seen"] or row["fetched_at"]) for row in rows
        )
        last_seen = max(row["fetched_at"] for row in rows)
        status = _campaign_status(last_seen)
        expired_at = now if status == "expired" else None

        try:
            if slug in existing:
                campaign_id = existing[slug]
                conn.execute(
                    "UPDATE campaigns SET name=?, summary=?, status=?, ioc_count=?, "
                    "first_seen=?, last_seen=?, expired_at=?, generated_at=? WHERE slug=?",
                    (name, summary, status, len(ioc_ids), first_seen,
                     last_seen, expired_at, now, slug),
                )
                conn.execute(
                    "DELETE FROM campaign_iocs WHERE campaign_id=?", (campaign_id,)
                )
            else:
                conn.execute(
                    "INSERT INTO campaigns (slug, name, summary, campaign_type, cluster_key, "
                    "status, ioc_count, first_seen, last_seen, expired_at, generated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (slug, name, summary, ctype, cluster_key, status,
                     len(ioc_ids), first_seen, last_seen, expired_at, now),
                )
                existing[slug] = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

            conn.executemany(
                "INSERT OR IGNORE INTO campaign_iocs (campaign_id, ioc_id) VALUES (?, ?)",
                [(existing[slug], iid) for iid in ioc_ids],
            )
            written += 1
        except Exception as exc:
            log.error("Cluster: failed to write campaign %s: %s", slug, exc)
            errors += 1

    for domain, rows in domain_buckets.items():
        tt = _most_common_threat_type(rows)
        _upsert(
            "domain", domain,
            f"{tt} staging on {domain}",
            f"{len(rows)} IOCs sharing staging domain {domain}.",
            rows,
        )

    for (asn, prefix, tag), rows in asn_tag_buckets.items():
        ck = f"AS{asn}:{tag}" if asn else f"{prefix}:{tag}"
        if asn:
            op = asn_map.get(asn, {}).get("short") or f"AS{asn}"
            name = f"{tag} on {op} (AS{asn})"
        else:
            name = f"{tag} activity on {prefix}"
        _upsert(
            "asn_tag", ck, name,
            f"{len(rows)} {tag}-tagged IOCs on {name.split(' on ', 1)[-1]} "
            f"in the last {_ROLLING_DAYS} days.",
            rows,
        )

    for net24, rows in prefix24_buckets.items():
        _upsert(
            "prefix24", net24,
            f"Multi-type activity on {net24}",
            f"{len(rows)} IOCs across {net24} in a {_ROLLING_DAYS}-day window.",
            rows,
        )

    # Mark disappeared campaigns as expired
    disappeared = set(existing.keys()) - new_slugs
    if disappeared:
        conn.executemany(
            "UPDATE campaigns SET status='expired', expired_at=? "
            "WHERE slug=? AND status != 'expired'",
            [(now, slug) for slug in disappeared],
        )
        log.info("Cluster: marked %d campaigns as expired", len(disappeared))

    conn.commit()
    conn.close()
    log.info("Cluster: %d campaigns written, %d errors", written, errors)
    return written, errors


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    from falconeye.config import get_db_path
    _db = get_db_path()
    _written, _errors = run_clustering(_db)
    print(f"Clustering complete: {_written} campaigns, {_errors} errors")
