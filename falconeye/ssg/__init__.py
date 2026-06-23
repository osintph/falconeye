from __future__ import annotations

import ipaddress
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jinja2
import yaml
from feedgen.feed import FeedGenerator

from falconeye.db import get_connection, init_db
from falconeye.stix import (
    campaign_to_stix,
    campaign_uses_indicator,
    cve_to_vulnerability,
    ioc_to_indicator,
    make_bundle,
)

log = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"
_SITE_URL = "https://falconeye.osintph.info"
_FEED_LIMIT = 200  # max items in RSS / JSON Feed per run

_jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=jinja2.select_autoescape(["html"]),
)
_jinja_env.filters["from_json"] = lambda s: json.loads(s or "[]")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _manifest_version(now: datetime) -> str:
    return now.strftime("%Y.%j.%H%M%S")


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

def _render_html(path: Path, iocs: list[dict], cves: list[dict], stats: dict,
                 campaigns: list[dict], asns: list[dict], now: datetime) -> None:
    top_campaigns = [c for c in campaigns if c["status"] == "active"][:5]
    active_asns = [a for a in asns if (a.get("ioc_count") or 0) > 0][:10]
    tmpl = _jinja_env.get_template("index.html.j2")
    html = tmpl.render(
        iocs=iocs,
        cves=cves,
        stats=stats,
        top_campaigns=top_campaigns,
        active_asns=active_asns,
        generated_at=now.strftime("%Y-%m-%d %H:%M"),
    )
    path.write_text(html, encoding="utf-8")
    log.info("SSG: wrote %s (%d bytes)", path.name, len(html))


def _build_ioc_feed_items(iocs: list[dict], cves: list[dict], now: datetime) -> list[dict]:
    """Per-IOC/CVE feed items (last 24h). Used for secondary feed-iocs.* files."""
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
            "url":      None,
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
                f"Description: {desc}"
            ),
            "url":      f"https://nvd.nist.gov/vuln/detail/{cve['cve_id']}",
            "pub_date": ts,
        })

    items.sort(key=lambda x: x["pub_date"], reverse=True)
    return items[:_FEED_LIMIT]


# Keep legacy alias so existing test_ssg.py tests that import this name still pass
_build_feed_items = _build_ioc_feed_items


def _build_campaign_feed_items(campaigns: list[dict]) -> list[dict]:
    """Campaign-centric feed items for active and dormant campaigns."""
    items = []
    for camp in campaigns:
        if camp["status"] == "expired":
            continue
        items.append({
            "uid":     f"campaign-{camp['slug']}",
            "title":   f"[Campaign] {camp['name']} — {camp['ioc_count']} IOCs",
            "summary": (
                f"{camp['summary'] or ''}\n"
                f"Status: {camp['status']}\n"
                f"Last seen: {(camp['last_seen'] or '')[:10]}\n"
                f"Type: {camp['campaign_type']}"
            ),
            "url":      f"{_SITE_URL}/campaign/{camp['slug']}/",
            "pub_date": _parse_ts(camp["last_seen"] or camp["generated_at"]),
        })
    items.sort(key=lambda x: x["pub_date"], reverse=True)
    return items[:_FEED_LIMIT]


def _render_rss(path: Path, items: list[dict], feed_url: str, title: str,
                description: str) -> None:
    fg = FeedGenerator()
    fg.id(feed_url)
    fg.title(title)
    fg.link(href=_SITE_URL, rel="alternate")
    fg.link(href=feed_url, rel="self")
    fg.description(description)
    fg.language("en")

    for item in items:
        fe = fg.add_entry()
        fe.id(f"{_SITE_URL}/#{item['uid']}")
        fe.title(item["title"])
        fe.summary(item["summary"])
        if item.get("url"):
            fe.link(href=item["url"])
        fe.pubDate(item["pub_date"])

    path.write_bytes(fg.rss_str(pretty=True))
    log.info("SSG: wrote %s (%d items)", path.name, len(items))


def _render_json_feed(path: Path, items: list[dict], feed_url: str, title: str,
                      description: str) -> None:
    feed = {
        "version": "https://jsonfeed.org/version/1.1",
        "title": title,
        "home_page_url": f"{_SITE_URL}/",
        "feed_url": feed_url,
        "description": description,
        "items": [
            {
                "id":              f"{_SITE_URL}/#{item['uid']}",
                "title":           item["title"],
                "content_text":    item["summary"],
                "url":             item.get("url") or f"{_SITE_URL}/",
                "date_published":  item["pub_date"].strftime("%Y-%m-%dT%H:%M:%SZ"),
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
# Config loaders
# ---------------------------------------------------------------------------

def _load_action_templates(config_dir: Path) -> list[dict]:
    path = config_dir / "action_templates.yaml"
    if not path.exists():
        return []
    with path.open() as f:
        data = yaml.safe_load(f) or {}
    return data.get("templates") or []


# ---------------------------------------------------------------------------
# ASN helpers
# ---------------------------------------------------------------------------

def _load_asn_operators(config_dir: Path) -> dict[int, dict]:
    path = config_dir / "asn_operators.yaml"
    if not path.exists():
        return {}
    with path.open() as f:
        data = yaml.safe_load(f) or {}
    return {int(k): v for k, v in (data.get("operators") or {}).items()}


def _build_12_week_counts(weekly_rows: list, now: datetime) -> list[int]:
    """Convert sparse (week_label, count) rows into a 12-element list."""
    labels = [
        (now - timedelta(weeks=i)).strftime("%Y-%W")
        for i in range(11, -1, -1)
    ]
    week_map = {row["week"]: row["cnt"] for row in weekly_rows}
    return [week_map.get(lbl, 0) for lbl in labels]


def _sparkline_svg(counts: list[int], width: int = 120, height: int = 30) -> str:
    """Return an inline SVG polyline sparkline for a list of counts."""
    if not counts or max(counts, default=0) == 0:
        return ""
    max_val = max(counts)
    n = len(counts)
    points = []
    for i, c in enumerate(counts):
        x = round(i * width / max(n - 1, 1), 1) if n > 1 else width // 2
        y = round(height - (c / max_val) * (height - 4) - 2, 1)
        points.append(f"{x},{y}")
    pts = " ".join(points)
    return (
        f'<svg width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" aria-hidden="true" class="sparkline">'
        f'<polyline fill="none" stroke="currentColor" stroke-width="1.5" '
        f'points="{pts}"/></svg>'
    )


def _query_asns_with_ioc_counts(
    conn, asn_map: dict[int, dict] | None = None
) -> list[dict]:
    """
    Return ASNs with IOC counts via CIDR containment against asn_map ip_ranges.

    ph_prefixes.asn is always NULL in the APNIC basic delegated file (separate ASN
    and prefix allocation records with no cross-reference), so the direct SQL join
    ph_asns → ph_prefixes → sieve_matches always yields ioc_count=0.

    Instead: query sieve_matches for 'asn' criterion matches (matched_value holds the
    matched CIDR prefix string), then attribute each prefix to an ASN in Python using
    subnet_of() against asn_map ip_ranges. Only matches from the last 14 days are counted.
    """
    if not asn_map:
        return []

    cutoff = (datetime.now(timezone.utc) - timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = conn.execute("""
        SELECT matched_value AS prefix,
               COUNT(DISTINCT record_id) AS ioc_count,
               MAX(matched_at)           AS last_seen
          FROM sieve_matches
         WHERE match_criterion = 'asn' AND record_type = 'ioc'
           AND matched_at >= ?
         GROUP BY matched_value
    """, (cutoff,)).fetchall()

    if not rows:
        return []

    # Parse ip_ranges from asn_map once
    asn_networks: list[tuple[int, list]] = []
    for asn_int, op in asn_map.items():
        nets = []
        for cidr in (op.get("ip_ranges") or []):
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                log.warning("asn_operators.yaml: invalid CIDR %r for AS%d", cidr, asn_int)
        if nets:
            asn_networks.append((asn_int, nets))

    # Attribute each matched prefix to an ASN via CIDR containment
    asn_counts: dict[int, dict] = {}
    for row in rows:
        try:
            prefix_net = ipaddress.ip_network(row["prefix"], strict=False)
        except ValueError:
            continue
        for asn_int, nets in asn_networks:
            for net in nets:
                try:
                    matched = prefix_net.subnet_of(net)
                except TypeError:
                    matched = False  # mixed IPv4/IPv6 versions
                if matched:
                    entry = asn_counts.setdefault(asn_int, {
                        "asn": asn_int,
                        "name": asn_map[asn_int].get("name") or f"AS{asn_int}",
                        "ioc_count": 0,
                        "last_seen": None,
                    })
                    entry["ioc_count"] += row["ioc_count"]
                    ls = row["last_seen"]
                    if ls and (entry["last_seen"] is None or ls > entry["last_seen"]):
                        entry["last_seen"] = ls
                    break

    return sorted(asn_counts.values(), key=lambda a: (-a["ioc_count"], a["asn"]))


def _query_asn_detail(conn, asn: int, now: datetime) -> dict:
    cutoff_30d = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cutoff_12w = (now - timedelta(weeks=12)).strftime("%Y-%m-%dT%H:%M:%SZ")

    iocs = conn.execute("""
        SELECT i.id, i.ioc_value, i.ioc_type, i.threat_type, i.tags, i.fetched_at
          FROM ph_prefixes p
          JOIN sieve_matches s ON s.matched_value = p.prefix
               AND s.match_criterion = 'asn' AND s.record_type = 'ioc'
          JOIN iocs i ON i.id = s.record_id
         WHERE p.asn = ? AND i.fetched_at >= ?
         ORDER BY i.fetched_at DESC
         LIMIT 500
    """, (asn, cutoff_30d)).fetchall()

    weekly_rows = conn.execute("""
        SELECT strftime('%Y-%W', i.fetched_at) AS week, COUNT(*) AS cnt
          FROM ph_prefixes p
          JOIN sieve_matches s ON s.matched_value = p.prefix
               AND s.match_criterion = 'asn' AND s.record_type = 'ioc'
          JOIN iocs i ON i.id = s.record_id
         WHERE p.asn = ? AND i.fetched_at >= ?
         GROUP BY week
         ORDER BY week
    """, (asn, cutoff_12w)).fetchall()

    # Shodan enrichment for IP-type IOCs on this ASN
    enrichments = conn.execute("""
        SELECT e.ip_address, e.ports, e.cpes, e.tags, e.vulns, e.fetched_at
          FROM ip_enrichments e
          JOIN iocs i ON i.ioc_value = e.ip_address AND i.ioc_type = 'ip'
          JOIN sieve_matches s ON s.record_id = i.id
               AND s.match_criterion = 'asn' AND s.record_type = 'ioc'
          JOIN ph_prefixes p ON p.prefix = s.matched_value AND p.asn = ?
         LIMIT 100
    """, (asn,)).fetchall()

    prefixes = conn.execute(
        "SELECT prefix, prefix_type FROM ph_prefixes WHERE asn = ? ORDER BY prefix",
        (asn,),
    ).fetchall()

    return {
        "iocs":          [dict(r) for r in iocs],
        "weekly_counts": _build_12_week_counts(weekly_rows, now),
        "enrichments":   [dict(r) for r in enrichments],
        "prefixes":      [dict(r) for r in prefixes],
    }


def _render_asn_index(output: Path, asns: list[dict], asn_map: dict[int, dict],
                      now: datetime) -> None:
    asn_dir = output / "asn"
    asn_dir.mkdir(parents=True, exist_ok=True)
    tmpl = _jinja_env.get_template("asn_index.html.j2")
    rows = []
    for a in asns:
        op = asn_map.get(a["asn"], {})
        rows.append({**a, "short": op.get("short") or a.get("name") or f"AS{a['asn']}"})
    html = tmpl.render(asns=rows, generated_at=now.strftime("%Y-%m-%d %H:%M"))
    (asn_dir / "index.html").write_text(html, encoding="utf-8")
    log.info("SSG: wrote asn/index.html (%d ASNs)", len(rows))


def _render_asn_pages(output: Path, conn, asn_map: dict[int, dict],
                      now: datetime) -> int:
    """Render per-ASN pages. Returns count of pages written."""
    tmpl = _jinja_env.get_template("asn.html.j2")
    written = 0
    for row in conn.execute("SELECT asn, name FROM ph_asns ORDER BY asn"):
        asn_num = row["asn"]
        op = asn_map.get(asn_num, {})
        operator_name = op.get("name") or row["name"] or f"AS{asn_num}"
        operator_short = op.get("short") or operator_name

        detail = _query_asn_detail(conn, asn_num, now)
        svg = _sparkline_svg(detail["weekly_counts"])

        page_dir = output / "asn" / f"AS{asn_num}"
        page_dir.mkdir(parents=True, exist_ok=True)

        html = tmpl.render(
            asn=asn_num,
            operator_name=operator_name,
            operator_short=operator_short,
            iocs=detail["iocs"],
            enrichments=detail["enrichments"],
            prefixes=detail["prefixes"],
            weekly_counts=detail["weekly_counts"],
            sparkline_svg=svg,
            generated_at=now.strftime("%Y-%m-%d %H:%M"),
        )
        (page_dir / "index.html").write_text(html, encoding="utf-8")
        written += 1
    log.info("SSG: wrote %d per-ASN pages", written)
    return written


# ---------------------------------------------------------------------------
# Campaign helpers
# ---------------------------------------------------------------------------

def _query_campaigns(conn) -> list[dict]:
    rows = conn.execute("""
        SELECT id, slug, name, summary, campaign_type, cluster_key,
               status, ioc_count, first_seen, last_seen, generated_at
          FROM campaigns
         ORDER BY
           CASE status WHEN 'active' THEN 0 WHEN 'dormant' THEN 1 ELSE 2 END,
           ioc_count DESC
    """).fetchall()
    return [dict(r) for r in rows]


def _query_campaign_iocs(conn, campaign_id: int) -> list[dict]:
    rows = conn.execute("""
        SELECT i.id, i.ioc_value, i.ioc_type, i.threat_type, i.tags, i.fetched_at
          FROM campaign_iocs ci
          JOIN iocs i ON i.id = ci.ioc_id
         WHERE ci.campaign_id = ?
         ORDER BY i.fetched_at DESC
         LIMIT 500
    """, (campaign_id,)).fetchall()
    return [dict(r) for r in rows]


def _match_action_templates(iocs: list[dict], templates: list[dict]) -> list[dict]:
    """Return action guidance blocks relevant to the tags seen in this campaign's IOCs."""
    all_tags: set[str] = set()
    for ioc in iocs:
        try:
            all_tags.update(t.lower() for t in json.loads(ioc["tags"] or "[]"))
        except (json.JSONDecodeError, TypeError):
            pass

    matched = []
    seen_titles: set[str] = set()
    for tmpl in templates:
        mt = (tmpl.get("match_tag") or "").lower()
        if mt and mt in all_tags:
            title = tmpl.get("title", "")
            if title not in seen_titles:
                matched.append(tmpl)
                seen_titles.add(title)
    return matched


def _render_campaign_index(output: Path, campaigns: list[dict], now: datetime) -> None:
    camp_dir = output / "campaign"
    camp_dir.mkdir(parents=True, exist_ok=True)
    tmpl = _jinja_env.get_template("campaign_index.html.j2")
    html = tmpl.render(campaigns=campaigns, generated_at=now.strftime("%Y-%m-%d %H:%M"))
    (camp_dir / "index.html").write_text(html, encoding="utf-8")
    log.info("SSG: wrote campaign/index.html (%d campaigns)", len(campaigns))


def _render_campaign_pages(output: Path, conn, campaigns: list[dict],
                           action_templates: list[dict], now: datetime) -> int:
    """Render per-campaign pages. Returns count written."""
    tmpl = _jinja_env.get_template("campaign.html.j2")
    written = 0
    for camp in campaigns:
        iocs = _query_campaign_iocs(conn, camp["id"])
        guidance = _match_action_templates(iocs, action_templates)
        page_dir = output / "campaign" / camp["slug"]
        page_dir.mkdir(parents=True, exist_ok=True)
        html = tmpl.render(
            campaign=camp,
            iocs=iocs,
            guidance=guidance,
            generated_at=now.strftime("%Y-%m-%d %H:%M"),
        )
        (page_dir / "index.html").write_text(html, encoding="utf-8")
        written += 1
    log.info("SSG: wrote %d per-campaign pages", written)
    return written


# ---------------------------------------------------------------------------
# STIX / TAXII-like static output
# ---------------------------------------------------------------------------

def _render_taxii(output: Path, iocs: list[dict], cves: list[dict],
                  campaigns: list[dict], conn, now: datetime) -> None:
    """Write static TAXII-like JSON files under output/api/v1/taxii/."""
    taxii_root = output / "api" / "v1" / "taxii"
    collections_dir = taxii_root / "collections"
    collections_dir.mkdir(parents=True, exist_ok=True)

    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Discovery document
    discovery = {
        "title": "FalconEye PH Threat Intelligence",
        "description": "Philippine-scoped STIX 2.1 threat intelligence from OSINT-PH",
        "contact": "sigmund@osintph.info",
        "api_roots": [f"{_SITE_URL}/api/v1/taxii/"],
    }
    (taxii_root / "index.json").write_text(
        json.dumps(discovery, indent=2), encoding="utf-8"
    )

    # Collections list
    collection_meta = [
        {"id": "ph-iocs",      "title": "PH IOC Indicators",
         "description": "STIX 2.1 indicators for PH-matched IOCs",
         "can_read": True, "can_write": False,
         "media_types": ["application/taxii+json;version=2.1"]},
        {"id": "ph-cves",      "title": "PH CVE Vulnerabilities",
         "description": "STIX 2.1 vulnerabilities for PH-relevant CVEs",
         "can_read": True, "can_write": False,
         "media_types": ["application/taxii+json;version=2.1"]},
        {"id": "ph-campaigns", "title": "PH Campaigns",
         "description": "STIX 2.1 campaigns and relationships",
         "can_read": True, "can_write": False,
         "media_types": ["application/taxii+json;version=2.1"]},
    ]
    (collections_dir / "index.json").write_text(
        json.dumps({"collections": collection_meta}, indent=2), encoding="utf-8"
    )

    # ph-iocs collection
    ioc_indicators = [obj for ioc in iocs if (obj := ioc_to_indicator(ioc))]
    ioc_dir = collections_dir / "ph-iocs"
    ioc_dir.mkdir(exist_ok=True)
    (ioc_dir / "objects.json").write_text(
        json.dumps(make_bundle(ioc_indicators), indent=2), encoding="utf-8"
    )

    # ph-cves collection
    vuln_objects = [cve_to_vulnerability(c) for c in cves]
    cve_dir = collections_dir / "ph-cves"
    cve_dir.mkdir(exist_ok=True)
    (cve_dir / "objects.json").write_text(
        json.dumps(make_bundle(vuln_objects), indent=2), encoding="utf-8"
    )

    # ph-campaigns collection: campaign objects + relationship objects
    camp_dir = collections_dir / "ph-campaigns"
    camp_dir.mkdir(exist_ok=True)
    campaign_objects: list[dict] = []

    # Build indicator ID map for relationship linking
    ioc_stix_map = {ioc["id"]: obj for ioc in iocs if (obj := ioc_to_indicator(ioc))}

    for camp in campaigns:
        camp_obj = campaign_to_stix(camp)
        campaign_objects.append(camp_obj)

        # Add relationship objects for IOCs in this campaign
        ioc_ids = [
            r[0] for r in conn.execute(
                "SELECT ioc_id FROM campaign_iocs WHERE campaign_id=?", (camp["id"],)
            )
        ]
        for ioc_id in ioc_ids:
            if ioc_id in ioc_stix_map:
                rel = campaign_uses_indicator(
                    camp_obj["id"], ioc_stix_map[ioc_id]["id"], now_iso
                )
                campaign_objects.append(rel)

    (camp_dir / "objects.json").write_text(
        json.dumps(make_bundle(campaign_objects), indent=2), encoding="utf-8"
    )

    log.info(
        "SSG: TAXII — %d indicators, %d vulnerabilities, %d campaign objects",
        len(ioc_indicators), len(vuln_objects), len(campaign_objects),
    )


# ---------------------------------------------------------------------------
# robots.txt + sitemap.xml
# ---------------------------------------------------------------------------

def _render_robots(path: Path) -> None:
    path.write_text(
        f"User-agent: *\nAllow: /\nSitemap: {_SITE_URL}/sitemap.xml\n",
        encoding="utf-8",
    )


def _render_sitemap(
    path: Path,
    campaigns: list[dict],
    asns: list[dict],
    now: datetime,
) -> None:
    lastmod = now.strftime("%Y-%m-%d")
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']

    static_paths = ["/", "/asn/", "/campaign/", "/api/v1/taxii/"]
    for p in static_paths:
        lines.append(
            f"  <url><loc>{_SITE_URL}{p}</loc><lastmod>{lastmod}</lastmod></url>"
        )

    for c in campaigns:
        if c.get("status") in ("active", "dormant"):
            slug = c["slug"]
            lines.append(
                f"  <url><loc>{_SITE_URL}/campaign/{slug}/</loc>"
                f"<lastmod>{lastmod}</lastmod></url>"
            )

    for a in asns:
        if (a.get("ioc_count") or 0) > 0:
            asn = a["asn"]
            lines.append(
                f"  <url><loc>{_SITE_URL}/asn/{asn}/</loc>"
                f"<lastmod>{lastmod}</lastmod></url>"
            )

    lines.append("</urlset>")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_ssg(
    db_path: str | Path,
    output_dir: str | Path,
    config_dir: str | Path | None = None,
) -> tuple[int, int]:
    """
    Regenerate all static output files from the current DB state.
    Returns (total_ph_items, errors).
    """
    init_db(db_path)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    cfg = Path(config_dir) if config_dir else _DEFAULT_CONFIG_DIR

    now = _now_utc()
    mv = _manifest_version(now)
    asn_map = _load_asn_operators(cfg)
    action_templates = _load_action_templates(cfg)

    conn = get_connection(db_path)
    iocs      = _query_ph_iocs(conn)
    cves      = _query_ph_cves(conn)
    stats     = _query_stats(conn)
    asns      = _query_asns_with_ioc_counts(conn, asn_map)
    campaigns = _query_campaigns(conn)

    log.info("SSG: %d PH IOCs, %d PH CVEs, %d ASNs, %d campaigns",
             len(iocs), len(cves), len(asns), len(campaigns))

    errors = 0
    campaign_items = _build_campaign_feed_items(campaigns)
    ioc_items      = _build_ioc_feed_items(iocs, cves, now)
    _CAMP_DESC = "PH campaign-level threat intelligence from FalconEye by OSINT-PH"
    _IOC_DESC  = "PH raw IOC and CVE stream from FalconEye by OSINT-PH"

    for fn, renderer in [
        ("index.html",    lambda p: _render_html(p, iocs, cves, stats, campaigns, asns, now)),
        ("feed.xml",      lambda p: _render_rss(p, campaign_items,
                              f"{_SITE_URL}/feed.xml", "FalconEye PH Campaigns", _CAMP_DESC)),
        ("feed.json",     lambda p: _render_json_feed(p, campaign_items,
                              f"{_SITE_URL}/feed.json", "FalconEye PH Campaigns", _CAMP_DESC)),
        ("feed-iocs.xml", lambda p: _render_rss(p, ioc_items,
                              f"{_SITE_URL}/feed-iocs.xml", "FalconEye PH IOC Stream", _IOC_DESC)),
        ("feed-iocs.json",lambda p: _render_json_feed(p, ioc_items,
                              f"{_SITE_URL}/feed-iocs.json", "FalconEye PH IOC Stream", _IOC_DESC)),
        ("manifest.json", lambda p: _render_manifest(p, stats, now, mv)),
        ("healthz.json",  lambda p: _render_healthz(p, stats, now, mv)),
    ]:
        try:
            renderer(output / fn)
        except Exception as exc:
            log.error("SSG: failed to write %s: %s", fn, exc)
            errors += 1

    try:
        _render_asn_index(output, asns, asn_map, now)
        _render_asn_pages(output, conn, asn_map, now)
    except Exception as exc:
        log.error("SSG: failed to write ASN pages: %s", exc)
        errors += 1

    try:
        _render_campaign_index(output, campaigns, now)
        _render_campaign_pages(output, conn, campaigns, action_templates, now)
    except Exception as exc:
        log.error("SSG: failed to write campaign pages: %s", exc)
        errors += 1

    try:
        _render_taxii(output, iocs, cves, campaigns, conn, now)
    except Exception as exc:
        log.error("SSG: failed to write TAXII files: %s", exc)
        errors += 1

    try:
        _render_robots(output / "robots.txt")
        _render_sitemap(output / "sitemap.xml", campaigns, asns, now)
    except Exception as exc:
        log.error("SSG: failed to write robots.txt/sitemap.xml: %s", exc)
        errors += 1

    conn.close()
    total = len(iocs) + len(cves)
    log.info("SSG: complete — %d PH items, %d errors", total, errors)
    return total, errors
