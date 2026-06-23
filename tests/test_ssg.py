from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from falconeye.db import get_connection, init_db
from falconeye.ssg import (
    _build_12_week_counts,
    _build_feed_items,
    _manifest_version,
    _match_action_templates,
    _parse_ts,
    _query_asns_with_ioc_counts,
    _query_campaigns,
    _query_ph_cves,
    _query_ph_iocs,
    _query_stats,
    _render_robots,
    _render_sitemap,
    _sparkline_svg,
    run_ssg,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def db(tmp_path) -> Path:
    """Minimal populated DB with 2 PH IOCs and 1 PH CVE."""
    p = tmp_path / "test.db"
    init_db(p)
    conn = get_connection(p)

    conn.execute(
        "INSERT INTO iocs (ioc_type, ioc_value, threat_type, tags, source, source_id, "
        "first_seen, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("url", "http://phishing.bdo.com.ph/login", "phishing",
         '["banking", "ph"]', "urlhaus", "u1",
         "2026-06-22T00:00:00Z", "2026-06-22T01:00:00Z"),
    )
    conn.execute(
        "INSERT INTO iocs (ioc_type, ioc_value, threat_type, tags, source, source_id, "
        "first_seen, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("url", "http://evil.com/payload", "malware",
         "[]", "urlhaus", "u2",
         "2026-06-22T00:00:00Z", "2026-06-22T01:00:00Z"),
    )
    conn.execute(
        "INSERT INTO cves (cve_id, description, cvss_v3_score, cvss_v3_severity, "
        "kev_date_added, kev_ransomware_use, source, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("CVE-2024-1001", "Cisco IOS vulnerability", 9.8, "CRITICAL",
         "2024-01-10", "Known", "kev", "2026-06-22T01:00:00Z"),
    )
    conn.execute(
        "INSERT INTO ph_asns (asn, fetched_at) VALUES (?, ?)",
        (9836, "2026-06-22T00:00:00Z"),
    )
    conn.execute(
        "INSERT INTO ph_prefixes (prefix, prefix_type, fetched_at) VALUES (?, ?, ?)",
        ("202.90.136.0/24", "ipv4", "2026-06-22T00:00:00Z"),
    )

    # Sieve matches
    conn.execute(
        "INSERT INTO sieve_matches (record_type, record_id, match_criterion, "
        "matched_value, matched_at) VALUES ('ioc', 1, 'tld', 'bdo.com.ph', '2026-06-22T01:00:00Z')"
    )
    conn.execute(
        "INSERT INTO sieve_matches (record_type, record_id, match_criterion, "
        "matched_value, matched_at) VALUES ('ioc', 1, 'brand', 'BDO', '2026-06-22T01:00:00Z')"
    )
    conn.execute(
        "INSERT INTO sieve_matches (record_type, record_id, match_criterion, "
        "matched_value, matched_at) VALUES ('cve', 1, 'cpe', 'cpe:2.3:o:cisco:ios', '2026-06-22T01:00:00Z')"
    )
    conn.commit()
    conn.close()
    return p


# ---------------------------------------------------------------------------
# Unit: helpers
# ---------------------------------------------------------------------------

def test_parse_ts_z_suffix():
    dt = _parse_ts("2026-06-22T01:00:00Z")
    assert dt.tzinfo is not None
    assert dt.year == 2026


def test_parse_ts_none_returns_now():
    now = _now()
    dt = _parse_ts(None)
    assert abs((dt - now).total_seconds()) < 5


def test_parse_ts_invalid_returns_now():
    now = _now()
    dt = _parse_ts("not-a-date")
    assert abs((dt - now).total_seconds()) < 5


def test_manifest_version_format():
    dt = datetime(2026, 6, 22, 14, 0, 0, tzinfo=timezone.utc)
    mv = _manifest_version(dt)
    assert mv == "2026.173.140000"


# ---------------------------------------------------------------------------
# Unit: DB queries
# ---------------------------------------------------------------------------

def test_query_ph_iocs_returns_matched_only(db):
    conn = get_connection(db)
    iocs = _query_ph_iocs(conn)
    conn.close()
    assert len(iocs) == 1
    assert iocs[0]["ioc_value"] == "http://phishing.bdo.com.ph/login"


def test_query_ph_iocs_why_field(db):
    conn = get_connection(db)
    iocs = _query_ph_iocs(conn)
    conn.close()
    assert "tld" in iocs[0]["why"]
    assert "brand" in iocs[0]["why"]


def test_query_ph_iocs_tags_list(db):
    conn = get_connection(db)
    iocs = _query_ph_iocs(conn)
    conn.close()
    assert isinstance(iocs[0]["tags_list"], list)
    assert "banking" in iocs[0]["tags_list"]


def test_query_ph_cves_returns_matched(db):
    conn = get_connection(db)
    cves = _query_ph_cves(conn)
    conn.close()
    assert len(cves) == 1
    assert cves[0]["cve_id"] == "CVE-2024-1001"


def test_query_ph_cves_why_field(db):
    conn = get_connection(db)
    cves = _query_ph_cves(conn)
    conn.close()
    assert "cpe" in cves[0]["why"]


def test_query_stats_counts(db):
    conn = get_connection(db)
    stats = _query_stats(conn)
    conn.close()
    assert stats["ph_iocs"] == 1
    assert stats["ph_cves"] == 1
    assert stats["total_iocs"] == 2
    assert stats["total_cves"] == 1
    assert stats["ph_asns"] == 1
    assert stats["ph_prefixes"] == 1


# ---------------------------------------------------------------------------
# Unit: feed item builder
# ---------------------------------------------------------------------------

def test_build_feed_items_within_24h(db):
    conn = get_connection(db)
    iocs = _query_ph_iocs(conn)
    cves = _query_ph_cves(conn)
    conn.close()

    # Force fetched_at to be recent so items pass the 24h cutoff
    now = _now()
    recent = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    for ioc in iocs:
        ioc["fetched_at"] = recent
    for cve in cves:
        cve["fetched_at"] = recent

    items = _build_feed_items(iocs, cves, now)
    assert len(items) == 2
    titles = [i["title"] for i in items]
    assert any("[IOC]" in t for t in titles)
    assert any("[CVE]" in t for t in titles)


def test_build_feed_items_excludes_stale(db):
    conn = get_connection(db)
    iocs = _query_ph_iocs(conn)
    cves = _query_ph_cves(conn)
    conn.close()

    now = _now()
    old = (now - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for ioc in iocs:
        ioc["fetched_at"] = old
    for cve in cves:
        cve["fetched_at"] = old

    items = _build_feed_items(iocs, cves, now)
    assert items == []


def test_build_feed_items_sorted_newest_first(db):
    conn = get_connection(db)
    iocs = _query_ph_iocs(conn)
    cves = _query_ph_cves(conn)
    conn.close()

    now = _now()
    iocs[0]["fetched_at"] = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cves[0]["fetched_at"] = (now - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

    items = _build_feed_items(iocs, cves, now)
    assert len(items) == 2
    assert items[0]["pub_date"] >= items[1]["pub_date"]


# ---------------------------------------------------------------------------
# Integration: run_ssg writes all five files
# ---------------------------------------------------------------------------

@pytest.fixture
def ssg_output(db, tmp_path) -> Path:
    out = tmp_path / "public"
    run_ssg(db, out)
    return out


def test_ssg_creates_index_html(ssg_output):
    assert (ssg_output / "index.html").exists()


def test_ssg_creates_feed_xml(ssg_output):
    assert (ssg_output / "feed.xml").exists()


def test_ssg_creates_feed_json(ssg_output):
    assert (ssg_output / "feed.json").exists()


def test_ssg_creates_manifest_json(ssg_output):
    assert (ssg_output / "manifest.json").exists()


def test_ssg_creates_healthz_json(ssg_output):
    assert (ssg_output / "healthz.json").exists()


def test_ssg_index_html_contains_cve(ssg_output):
    html = (ssg_output / "index.html").read_text()
    assert "CVE-2024-1001" in html


def test_ssg_index_html_contains_ioc_stats(ssg_output):
    # New dashboard shows PH IOC count in stats cards, not a flat table
    html = (ssg_output / "index.html").read_text()
    assert "PH IOCs" in html
    assert "feed-iocs.xml" in html  # secondary per-IOC feed linked in header


def test_ssg_manifest_json_valid(ssg_output):
    data = json.loads((ssg_output / "manifest.json").read_text())
    assert data["schema_version"] == "1"
    assert "ph_matches" in data
    assert data["ph_matches"]["total"] == 2


def test_ssg_healthz_json_valid(ssg_output):
    data = json.loads((ssg_output / "healthz.json").read_text())
    assert data["status"] == "ok"
    assert "urlhaus" in data["sources"]


def test_ssg_feed_json_valid(ssg_output):
    data = json.loads((ssg_output / "feed.json").read_text())
    assert data["version"] == "https://jsonfeed.org/version/1.1"
    assert "items" in data


def test_ssg_returns_counts(db, tmp_path):
    out = tmp_path / "public"
    total, errors = run_ssg(db, out)
    assert total == 2  # 1 PH IOC + 1 PH CVE
    assert errors == 0


def test_ssg_idempotent(db, tmp_path):
    out = tmp_path / "public"
    t1, e1 = run_ssg(db, out)
    t2, e2 = run_ssg(db, out)
    assert t1 == t2
    assert e1 == e2 == 0


# ---------------------------------------------------------------------------
# ASN rendering
# ---------------------------------------------------------------------------

def test_ssg_creates_secondary_ioc_feeds(ssg_output):
    # Adjustment 1: secondary per-IOC feeds alongside campaign primary feeds
    assert (ssg_output / "feed-iocs.xml").exists()
    assert (ssg_output / "feed-iocs.json").exists()


def test_ssg_creates_asn_index(ssg_output):
    assert (ssg_output / "asn" / "index.html").exists()


def test_ssg_creates_per_asn_page(ssg_output):
    # db fixture inserts asn=9836
    assert (ssg_output / "asn" / "AS9836" / "index.html").exists()


def test_ssg_asn_index_lists_asn(ssg_output):
    # With no active 'asn' sieve_matches in the fixture the index renders empty-data message
    html = (ssg_output / "asn" / "index.html").read_text()
    assert "PH ASN Intelligence" in html


def test_query_asns_with_ioc_counts_no_asn_map(db):
    """Without asn_map, CIDR attribution is impossible — returns empty list."""
    conn = get_connection(db)
    asns = _query_asns_with_ioc_counts(conn)
    conn.close()
    assert asns == []


def test_query_asns_with_ioc_counts_attributes_by_cidr(tmp_path):
    """Prefix in sieve_matches is attributed to an ASN via ip_ranges containment."""
    db = tmp_path / "asn_cidr.db"
    init_db(db)
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO iocs (ioc_type, ioc_value, threat_type, source, source_id, fetched_at) "
        "VALUES ('ip', '10.0.0.1', 'malware', 'urlhaus', 'x1', '2026-06-23T00:00:00Z')"
    )
    ioc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO sieve_matches (record_type, record_id, match_criterion, "
        "matched_value, matched_at) VALUES ('ioc', ?, 'asn', '10.0.0.0/24', '2026-06-23T00:00:00Z')",
        (ioc_id,),
    )
    conn.commit()

    asn_map = {9999: {"name": "Test ISP", "short": "TEST", "ip_ranges": ["10.0.0.0/16"], "cpe_prefixes": []}}
    asns = _query_asns_with_ioc_counts(conn, asn_map)
    conn.close()

    assert len(asns) == 1
    assert asns[0]["asn"] == 9999
    assert asns[0]["ioc_count"] == 1


def test_query_asns_with_ioc_counts_14d_cutoff(tmp_path):
    """Matches older than 14 days are excluded from the count."""
    db = tmp_path / "asn_cutoff.db"
    init_db(db)
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO iocs (ioc_type, ioc_value, threat_type, source, source_id, fetched_at) "
        "VALUES ('ip', '10.0.0.2', 'malware', 'urlhaus', 'x2', '2026-06-01T00:00:00Z')"
    )
    ioc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO sieve_matches (record_type, record_id, match_criterion, "
        "matched_value, matched_at) VALUES ('ioc', ?, 'asn', '10.0.0.0/24', '2026-06-08T00:00:00Z')",
        (ioc_id,),
    )
    conn.commit()

    asn_map = {9999: {"name": "Test ISP", "short": "TEST", "ip_ranges": ["10.0.0.0/16"], "cpe_prefixes": []}}
    asns = _query_asns_with_ioc_counts(conn, asn_map)
    conn.close()
    assert asns == []


def test_query_asns_with_ioc_counts_aggregates_prefixes(tmp_path):
    """Two prefixes within the same ASN ip_range are summed into one entry."""
    db = tmp_path / "asn_agg.db"
    init_db(db)
    conn = get_connection(db)
    for i, cidr in enumerate(["10.0.1.0/24", "10.0.2.0/24"]):
        conn.execute(
            "INSERT INTO iocs (ioc_type, ioc_value, threat_type, source, source_id, fetched_at) "
            "VALUES ('ip', ?, 'malware', 'urlhaus', ?, '2026-06-23T00:00:00Z')",
            (f"10.0.{i + 1}.1", f"x{i}"),
        )
        ioc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO sieve_matches (record_type, record_id, match_criterion, "
            "matched_value, matched_at) VALUES ('ioc', ?, 'asn', ?, '2026-06-23T00:00:00Z')",
            (ioc_id, cidr),
        )
    conn.commit()

    asn_map = {9999: {"name": "Test ISP", "short": "TEST", "ip_ranges": ["10.0.0.0/16"], "cpe_prefixes": []}}
    asns = _query_asns_with_ioc_counts(conn, asn_map)
    conn.close()

    assert len(asns) == 1
    assert asns[0]["ioc_count"] == 2


def test_query_asns_with_ioc_counts_unmatched_excluded(tmp_path):
    """A prefix not covered by any asn_map ip_range produces no result."""
    db = tmp_path / "asn_nomatch.db"
    init_db(db)
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO iocs (ioc_type, ioc_value, threat_type, source, source_id, fetched_at) "
        "VALUES ('ip', '172.16.0.1', 'malware', 'urlhaus', 'x3', '2026-06-23T00:00:00Z')"
    )
    ioc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO sieve_matches (record_type, record_id, match_criterion, "
        "matched_value, matched_at) VALUES ('ioc', ?, 'asn', '172.16.0.0/24', '2026-06-23T00:00:00Z')",
        (ioc_id,),
    )
    conn.commit()

    asn_map = {9999: {"name": "Test ISP", "short": "TEST", "ip_ranges": ["10.0.0.0/16"], "cpe_prefixes": []}}
    asns = _query_asns_with_ioc_counts(conn, asn_map)
    conn.close()
    assert asns == []


def test_build_12_week_counts_fills_zeros():
    now = datetime(2026, 6, 23, 12, 0, tzinfo=timezone.utc)
    counts = _build_12_week_counts([], now)
    assert len(counts) == 12
    assert all(c == 0 for c in counts)


def test_build_12_week_counts_places_value():
    now = datetime(2026, 6, 23, 12, 0, tzinfo=timezone.utc)
    # Current week label
    this_week = now.strftime("%Y-%W")

    class FakeRow:
        def __getitem__(self, key):
            return {"week": this_week, "cnt": 42}[key]

    counts = _build_12_week_counts([FakeRow()], now)
    assert counts[-1] == 42  # most recent week is last


def test_sparkline_svg_empty_returns_empty():
    assert _sparkline_svg([]) == ""
    assert _sparkline_svg([0, 0, 0]) == ""


def test_sparkline_svg_returns_svg():
    svg = _sparkline_svg([1, 2, 3, 4, 5])
    assert svg.startswith("<svg")
    assert "polyline" in svg
    assert 'aria-hidden="true"' in svg


def test_sparkline_svg_single_point():
    svg = _sparkline_svg([5])
    assert "<svg" in svg


# ---------------------------------------------------------------------------
# Campaign rendering
# ---------------------------------------------------------------------------

@pytest.fixture
def db_with_campaign(db):
    """Add a campaign to the existing db fixture."""
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO campaigns (slug, name, summary, campaign_type, cluster_key, "
        "status, ioc_count, first_seen, last_seen, generated_at) "
        "VALUES ('dom-bdo-com-ph', 'phishing staging on bdo.com.ph', 'Test summary.', "
        "'domain', 'bdo.com.ph', 'active', 1, '2026-06-22T00:00:00Z', "
        "'2026-06-22T01:00:00Z', '2026-06-22T01:00:00Z')"
    )
    campaign_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO campaign_iocs (campaign_id, ioc_id) VALUES (?, 1)", (campaign_id,)
    )
    conn.commit()
    conn.close()
    return db


def test_ssg_creates_campaign_index(db_with_campaign, tmp_path):
    out = tmp_path / "public"
    run_ssg(db_with_campaign, out)
    assert (out / "campaign" / "index.html").exists()


def test_ssg_creates_per_campaign_page(db_with_campaign, tmp_path):
    out = tmp_path / "public"
    run_ssg(db_with_campaign, out)
    assert (out / "campaign" / "dom-bdo-com-ph" / "index.html").exists()


def test_ssg_campaign_index_lists_campaign(db_with_campaign, tmp_path):
    out = tmp_path / "public"
    run_ssg(db_with_campaign, out)
    html = (out / "campaign" / "index.html").read_text()
    assert "bdo.com.ph" in html


def test_ssg_campaign_page_shows_ioc(db_with_campaign, tmp_path):
    out = tmp_path / "public"
    run_ssg(db_with_campaign, out)
    html = (out / "campaign" / "dom-bdo-com-ph" / "index.html").read_text()
    assert "bdo.com.ph" in html


def test_query_campaigns_empty(db):
    conn = get_connection(db)
    camps = _query_campaigns(conn)
    conn.close()
    assert camps == []


def test_match_action_templates_hit():
    iocs = [{"tags": '["Mirai", "elf"]'}]
    templates = [{"match_tag": "Mirai", "title": "Block IoT", "guidance": "Do this."}]
    result = _match_action_templates(iocs, templates)
    assert len(result) == 1
    assert result[0]["title"] == "Block IoT"


def test_match_action_templates_case_insensitive():
    iocs = [{"tags": '["mirai"]'}]
    templates = [{"match_tag": "Mirai", "title": "Block IoT", "guidance": "Do this."}]
    result = _match_action_templates(iocs, templates)
    assert len(result) == 1


def test_match_action_templates_no_match():
    iocs = [{"tags": '["Emotet"]'}]
    templates = [{"match_tag": "Mirai", "title": "Block IoT", "guidance": "Do this."}]
    result = _match_action_templates(iocs, templates)
    assert result == []


def test_match_action_templates_deduplicates():
    iocs = [{"tags": '["Mirai"]'}, {"tags": '["Mirai"]'}]
    templates = [{"match_tag": "Mirai", "title": "Block IoT", "guidance": "Do this."}]
    result = _match_action_templates(iocs, templates)
    assert len(result) == 1


# ---------------------------------------------------------------------------
# robots.txt + sitemap.xml
# ---------------------------------------------------------------------------

def test_render_robots_creates_file(tmp_path):
    p = tmp_path / "robots.txt"
    _render_robots(p)
    assert p.exists()


def test_render_robots_allows_all(tmp_path):
    p = tmp_path / "robots.txt"
    _render_robots(p)
    content = p.read_text()
    assert "User-agent: *" in content
    assert "Allow: /" in content


def test_render_robots_references_sitemap(tmp_path):
    p = tmp_path / "robots.txt"
    _render_robots(p)
    assert "sitemap.xml" in p.read_text()


def test_render_sitemap_creates_file(tmp_path):
    p = tmp_path / "sitemap.xml"
    _render_sitemap(p, [], [], _now())
    assert p.exists()


def test_render_sitemap_contains_static_paths(tmp_path):
    p = tmp_path / "sitemap.xml"
    _render_sitemap(p, [], [], _now())
    content = p.read_text()
    for path in ["/", "/asn/", "/campaign/", "/api/v1/taxii/"]:
        assert path in content


def test_render_sitemap_includes_active_campaign(tmp_path):
    campaigns = [{"slug": "dom-evil-ph", "status": "active"}]
    p = tmp_path / "sitemap.xml"
    _render_sitemap(p, campaigns, [], _now())
    assert "/campaign/dom-evil-ph/" in p.read_text()


def test_render_sitemap_excludes_expired_campaign(tmp_path):
    campaigns = [{"slug": "dom-old", "status": "expired"}]
    p = tmp_path / "sitemap.xml"
    _render_sitemap(p, campaigns, [], _now())
    assert "dom-old" not in p.read_text()


def test_render_sitemap_includes_active_asn(tmp_path):
    asns = [{"asn": "AS9299", "ioc_count": 5}]
    p = tmp_path / "sitemap.xml"
    _render_sitemap(p, [], asns, _now())
    assert "/asn/AS9299/" in p.read_text()


def test_render_sitemap_excludes_zero_count_asn(tmp_path):
    asns = [{"asn": "AS9299", "ioc_count": 0}]
    p = tmp_path / "sitemap.xml"
    _render_sitemap(p, [], asns, _now())
    assert "AS9299" not in p.read_text()


def test_ssg_creates_robots_txt(ssg_output):
    assert (ssg_output / "robots.txt").exists()


def test_ssg_creates_sitemap_xml(ssg_output):
    assert (ssg_output / "sitemap.xml").exists()


# ---------------------------------------------------------------------------
# CVE 730-day date filter (v0.2.2)
# ---------------------------------------------------------------------------

def test_query_ph_cves_null_published_date_always_included(tmp_path):
    """CVEs with NULL published_date (KEV-only) survive the 730-day filter."""
    db = tmp_path / "null_pub.db"
    init_db(db)
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO cves (cve_id, description, source, fetched_at) "
        "VALUES ('CVE-2000-0001', 'Old KEV', 'kev', '2026-06-22T00:00:00Z')"
    )
    cve_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO sieve_matches (record_type, record_id, match_criterion, "
        "matched_value, matched_at) VALUES ('cve', ?, 'cpe', 'cpe:x', '2026-06-22T00:00:00Z')",
        (cve_id,),
    )
    conn.commit()
    now = datetime(2026, 6, 22, tzinfo=timezone.utc)
    cves = _query_ph_cves(conn, now)
    conn.close()
    assert len(cves) == 1


def test_query_ph_cves_filters_old_published_date(tmp_path):
    """CVEs published more than 730 days ago are excluded when published_date is set."""
    db = tmp_path / "old_pub.db"
    init_db(db)
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO cves (cve_id, description, source, fetched_at, published_date) "
        "VALUES ('CVE-2001-0001', 'Ancient CVE', 'nvd', '2026-06-22T00:00:00Z', '2001-01-01T00:00:00Z')"
    )
    cve_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO sieve_matches (record_type, record_id, match_criterion, "
        "matched_value, matched_at) VALUES ('cve', ?, 'cpe', 'cpe:x', '2026-06-22T00:00:00Z')",
        (cve_id,),
    )
    conn.commit()
    now = datetime(2026, 6, 22, tzinfo=timezone.utc)
    cves = _query_ph_cves(conn, now)
    conn.close()
    assert cves == []


def test_query_ph_cves_includes_cvss_version(tmp_path):
    """cvss_version is returned in the CVE dict."""
    db = tmp_path / "cvss_ver.db"
    init_db(db)
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO cves (cve_id, description, cvss_v3_score, cvss_v3_severity, "
        "cvss_version, source, fetched_at, published_date) "
        "VALUES ('CVE-2024-9999', 'Test', 9.8, 'CRITICAL', 'v3.1', 'nvd', "
        "'2026-06-22T00:00:00Z', '2025-01-01T00:00:00Z')"
    )
    cve_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO sieve_matches (record_type, record_id, match_criterion, "
        "matched_value, matched_at) VALUES ('cve', ?, 'cpe', 'cpe:x', '2026-06-22T00:00:00Z')",
        (cve_id,),
    )
    conn.commit()
    now = datetime(2026, 6, 22, tzinfo=timezone.utc)
    cves = _query_ph_cves(conn, now)
    conn.close()
    assert len(cves) == 1
    assert cves[0]["cvss_version"] == "v3.1"
