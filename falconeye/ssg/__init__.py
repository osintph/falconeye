from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jinja2
from feedgen.feed import FeedGenerator

from falconeye.db import get_connection, init_db

log = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_SITE_URL = "https://falconeye.osintph.info"
_FEED_LIMIT = 200  # max items in RSS / JSON Feed per run

_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=jinja2.select_autoescape(["html"]),
)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _manifest_version(now: datetime) -> str:
    return now.strftime("%Y.%j.%H")


def _parse_ts(s: str | None) -> datetime:
    if not s:
        return _now_utc()
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return _now_utc()


# ---------------------------------------------------------------------------
# DB queries
# ---------------------------------------------------------------------------

def _query_ph_iocs(conn) -> list[dict]:
    rows = conn.execute("""
        SELECT i.id, i.ioc_type, i.ioc_value, i.threat_type, i.tags,
               i.first_seen, i.fetched_at, i.source,
               GROUP_CONCAT(s.match_criterion || ': ' || s.matched_value, '; ') AS why
          FROM sieve_matches s
          JOIN iocs i ON i.id = s.record_id AND s.record_type = 'ioc'
         GROUP BY i.id
         ORDER BY i.fetched_at DESC
         LIMIT 500
    """).fetchall()

    result = []
    for r in rows:
        tags_raw = r["tags"] or "[]"
        try:
            tags_list = json.loads(tags_raw)
        except (json.JSONDecodeError, ValueError):
            tags_list = []
        result.append({
            "id":          r["id"],
            "ioc_type":    r["ioc_type"],
            "ioc_value":   r["ioc_value"],
            "threat_type": r["threat_type"],
            "tags":        tags_raw,
            "tags_list":   tags_list,
            "first_seen":  r["first_seen"],
            "fetched_at":  r["fetched_at"],
            "source":      r["source"],
            "why":         r["why"] or "",
        })
    return result


def _query_ph_cves(conn) -> list[dict]:
    rows = conn.execute("""
        SELECT c.id, c.cve_id, c.description, c.cvss_v3_score, c.cvss_v3_severity,
               c.kev_date_added, c.kev_ransomware_use, c.kev_notes,
               c.source, c.fetched_at,
               GROUP_CONCAT(s.match_criterion || ': ' || s.matched_value, '; ') AS why
          FROM sieve_matches s
          JOIN cves c ON c.id = s.record_id AND s.record_type = 'cve'
         GROUP BY c.id
         ORDER BY c.kev_date_added DESC, c.fetched_at DESC
    """).fetchall()

    return [
        {
            "id":                r["id"],
            "cve_id":            r["cve_id"],
            "description":       r["description"],
            "cvss_v3_score":     r["cvss_v3_score"],
            "cvss_v3_severity":  r["cvss_v3_severity"],
            "kev_date_added":    r["kev_date_added"],
            "kev_ransomware_use": r["kev_ransomware_use"],
            "kev_notes":         r["kev_notes"],
            "source":            r["source"],
            "fetched_at":        r["fetched_at"],
            "why":               r["why"] or "",
        }
        for r in rows
    ]


def _query_stats(conn) -> dict:
    def one(sql, *params):
        row = conn.execute(sql, params).fetchone()
        return row[0] if row else None

    return {
        "ph_iocs":      one("SELECT COUNT(DISTINCT record_id) FROM sieve_matches WHERE record_type='ioc'"),
        "ph_cves":      one("SELECT COUNT(DISTINCT record_id) FROM sieve_matches WHERE record_type='cve'"),
        "total_iocs":   one("SELECT COUNT(*) FROM iocs"),
        "total_cves":   one("SELECT COUNT(*) FROM cves"),
        "ph_asns":      one("SELECT COUNT(*) FROM ph_asns"),
        "ph_prefixes":  one("SELECT COUNT(*) FROM ph_prefixes"),
        "urlhaus_last": one("SELECT MAX(fetched_at) FROM iocs WHERE source='urlhaus'"),
        "urlhaus_rows": one("SELECT COUNT(*) FROM iocs WHERE source='urlhaus'"),
        "kev_last":     one("SELECT MAX(fetched_at) FROM cves WHERE source='kev'"),
        "kev_rows":     one("SELECT COUNT(*) FROM cves WHERE source='kev'"),
        "nvd_last":     one("SELECT MAX(fetched_at) FROM cves WHERE source='nvd'"),
        "nvd_rows":     one("SELECT COUNT(*) FROM cves"),
        "apnic_last":   one("SELECT MAX(fetched_at) FROM ph_asns"),
        "apnic_rows":   one("SELECT COUNT(*) FROM ph_asns") or 0
                        + (one("SELECT COUNT(*) FROM ph_prefixes") or 0),
    }


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def _render_html(path: Path, iocs: list[dict], cves: list[dict],
                 stats: dict, now: datetime) -> None:
    tmpl = _jinja_env.get_template("index.html.j2")
    html = tmpl.render(
        iocs=iocs,
        cves=cves,
        stats=stats,
        generated_at=now.strftime("%Y-%m-%d %H:%M"),
    )
    path.write_text(html, encoding="utf-8")
    log.info("SSG: wrote %s (%d bytes)", path.name, len(html))


def _build_feed_items(iocs: list[dict], cves: list[dict], now: datetime) -> list[dict]:
    """Return items matched in the last 24 h, newest first, capped at _FEED_LIMIT."""
    cutoff = now - timedelta(hours=24)
    items = []

    for ioc in iocs:
        ts = _parse_ts(ioc["fetched_at"])
        if ts < cutoff:
            continue
        v = ioc["ioc_value"]
        items.append({
            "uid":     f"ioc-{ioc['id']}",
            "title":   f"[IOC] {ioc['threat_type'] or 'malware'} — {v[:70]}",
            "summary": (
                f"Type: {ioc['ioc_type']}\n"
                f"Value: {v}\n"
                f"PH signal: {ioc['why']}\n"
                f"Source: {ioc['source']}"
            ),
            "pub_date": ts,
        })

    for cve in cves:
        ts = _parse_ts(cve["fetched_at"])
        if ts < cutoff:
            continue
        sev = cve.get("cvss_v3_severity") or "?"
        desc = (cve.get("description") or "")[:120]
        items.append({
            "uid":     f"cve-{cve['cve_id']}",
            "title":   f"[CVE] {cve['cve_id']} ({sev}) — {desc}",
            "summary": (
                f"CVE: {cve['cve_id']}\n"
                f"Severity: {sev}\n"
                f"Score: {cve.get('cvss_v3_score') or 'N/A'}\n"
                f"KEV added: {cve.get('kev_date_added') or 'N/A'}\n"
                f"PH signal: {cve['why']}\n"
                f"Description: {desc}"
            ),
            "pub_date": ts,
        })

    items.sort(key=lambda x: x["pub_date"], reverse=True)
    return items[:_FEED_LIMIT]


def _render_rss(path: Path, items: list[dict]) -> None:
    fg = FeedGenerator()
    fg.id(f"{_SITE_URL}/feed.xml")
    fg.title("FalconEye PH Threat Intelligence")
    fg.link(href=_SITE_URL, rel="alternate")
    fg.link(href=f"{_SITE_URL}/feed.xml", rel="self")
    fg.description("PH-relevant threat intelligence from FalconEye by OSINT-PH")
    fg.language("en")

    for item in items:
        fe = fg.add_entry()
        fe.id(f"{_SITE_URL}/#{item['uid']}")
        fe.title(item["title"])
        fe.summary(item["summary"])
        fe.pubDate(item["pub_date"])

    path.write_bytes(fg.rss_str(pretty=True))
    log.info("SSG: wrote %s (%d items)", path.name, len(items))


def _render_json_feed(path: Path, items: list[dict], now: datetime) -> None:
    feed = {
        "version": "https://jsonfeed.org/version/1.1",
        "title": "FalconEye PH Threat Intelligence",
        "home_page_url": f"{_SITE_URL}/",
        "feed_url": f"{_SITE_URL}/feed.json",
        "description": "PH-relevant threat intelligence from FalconEye by OSINT-PH",
        "items": [
            {
                "id": f"{_SITE_URL}/#{item['uid']}",
                "title": item["title"],
                "content_text": item["summary"],
                "date_published": item["pub_date"].strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            for item in items
        ],
    }
    path.write_text(json.dumps(feed, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("SSG: wrote %s (%d items)", path.name, len(items))


def _render_manifest(path: Path, stats: dict, now: datetime, mv: str) -> None:
    manifest = {
        "schema_version": "1",
        "manifest_version": mv,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": {
            "urlhaus": {
                "last_fetched": stats["urlhaus_last"],
                "row_count":    stats["urlhaus_rows"],
            },
            "kev": {
                "last_fetched": stats["kev_last"],
                "row_count":    stats["kev_rows"],
            },
            "nvd": {
                "last_fetched": stats["nvd_last"],
                "row_count":    stats["nvd_rows"],
            },
            "apnic": {
                "last_fetched":     stats["apnic_last"],
                "ph_asn_count":     stats["ph_asns"],
                "ph_prefix_count":  stats["ph_prefixes"],
            },
        },
        "ph_matches": {
            "iocs":  stats["ph_iocs"],
            "cves":  stats["ph_cves"],
            "total": (stats["ph_iocs"] or 0) + (stats["ph_cves"] or 0),
        },
        "license": {
            "falconeye": "AGPL-3.0",
            "urlhaus":   "Community use (abuse.ch)",
            "kev":       "US Government public domain",
            "nvd":       "US Government public domain",
            "apnic":     "APNIC member services",
        },
    }
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("SSG: wrote %s", path.name)


def _render_healthz(path: Path, stats: dict, now: datetime, mv: str) -> None:
    def age(last_ts: str | None) -> int | None:
        if not last_ts:
            return None
        try:
            dt = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
            return max(0, int((now - dt).total_seconds()))
        except ValueError:
            return None

    healthz = {
        "status": "ok",
        "manifest_version": mv,
        "last_regeneration_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": {
            "urlhaus": {
                "last_success_utc": stats["urlhaus_last"],
                "row_count":        stats["urlhaus_rows"],
                "age_seconds":      age(stats["urlhaus_last"]),
            },
            "kev": {
                "last_success_utc": stats["kev_last"],
                "row_count":        stats["kev_rows"],
                "age_seconds":      age(stats["kev_last"]),
            },
            "nvd": {
                "last_success_utc": stats["nvd_last"],
                "row_count":        stats["nvd_rows"],
                "age_seconds":      age(stats["nvd_last"]),
            },
            "apnic": {
                "last_success_utc": stats["apnic_last"],
                "row_count":        (stats["ph_asns"] or 0) + (stats["ph_prefixes"] or 0),
                "age_seconds":      age(stats["apnic_last"]),
            },
        },
    }
    path.write_text(json.dumps(healthz, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("SSG: wrote %s", path.name)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_ssg(
    db_path: str | Path,
    output_dir: str | Path,
) -> tuple[int, int]:
    """
    Regenerate all static output files from the current DB state.
    Returns (total_ph_items, errors).
    """
    init_db(db_path)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    now = _now_utc()
    mv = _manifest_version(now)

    conn = get_connection(db_path)
    iocs  = _query_ph_iocs(conn)
    cves  = _query_ph_cves(conn)
    stats = _query_stats(conn)
    conn.close()

    log.info("SSG: %d PH IOCs, %d PH CVEs", len(iocs), len(cves))

    errors = 0
    feed_items = _build_feed_items(iocs, cves, now)

    for fn, renderer in [
        ("index.html",  lambda p: _render_html(p, iocs, cves, stats, now)),
        ("feed.xml",    lambda p: _render_rss(p, feed_items)),
        ("feed.json",   lambda p: _render_json_feed(p, feed_items, now)),
        ("manifest.json", lambda p: _render_manifest(p, stats, now, mv)),
        ("healthz.json",  lambda p: _render_healthz(p, stats, now, mv)),
    ]:
        try:
            renderer(output / fn)
        except Exception as exc:
            log.error("SSG: failed to write %s: %s", fn, exc)
            errors += 1

    total = len(iocs) + len(cves)
    log.info("SSG: complete — %d PH items, %d errors", total, errors)
    return total, errors
