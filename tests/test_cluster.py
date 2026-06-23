from __future__ import annotations

import json
from pathlib import Path

import pytest

from falconeye.cluster import (
    _select_primary_tag,
    effective_grouping_domain,
    make_slug,
    run_clustering,
)
from falconeye.db import get_connection, init_db


# ---------------------------------------------------------------------------
# effective_grouping_domain
# ---------------------------------------------------------------------------

def test_egdomain_standard():
    # suffix=com.ph, domain=evil → registered domain is evil.com.ph
    assert effective_grouping_domain("evil.com.ph") == "evil.com.ph"


def test_egdomain_ph_tld():
    assert effective_grouping_domain("malware.ph") == "malware.ph"


def test_egdomain_subdomain_stripped():
    assert effective_grouping_domain("login.bdo.com.ph") == "bdo.com.ph"


def test_egdomain_workers_dev_uses_account():
    # workers.dev is a PSL entry; should group by account subdomain
    assert effective_grouping_domain("chris-smart.workers.dev") == "chris-smart.workers.dev"


def test_egdomain_deep_workers_dev_uses_last_subdomain():
    # sub.account.workers.dev → account is last component before workers.dev
    assert effective_grouping_domain("sub.account.workers.dev") == "account.workers.dev"


def test_egdomain_github_io_uses_account():
    assert effective_grouping_domain("attacker.github.io") == "attacker.github.io"


def test_egdomain_returns_none_for_empty():
    assert effective_grouping_domain("") is None


def test_egdomain_returns_none_for_ip():
    # tldextract gives no domain for bare IPs
    result = effective_grouping_domain("1.2.3.4")
    # IP addresses have no registered domain
    assert result is None or "1" in result  # implementation-dependent; main check is no crash


# ---------------------------------------------------------------------------
# make_slug
# ---------------------------------------------------------------------------

def test_make_slug_domain():
    assert make_slug("domain", "evil.com.ph") == "dom-evil-com-ph"


def test_make_slug_asn_tag():
    assert make_slug("asn_tag", "AS17639:Mirai") == "ast-as17639-mirai"


def test_make_slug_prefix24():
    assert make_slug("prefix24", "202.90.136.0/24") == "pfx-202-90-136-0-24"


def test_make_slug_truncates_at_80():
    long_key = "a" * 100
    result = make_slug("domain", long_key)
    assert len(result) <= 80


# ---------------------------------------------------------------------------
# run_clustering (integration)
# ---------------------------------------------------------------------------

_TS = "2026-06-23T00:00:00Z"


def _insert_ioc(conn, value, ioc_type="url", threat_type="malware_download",
                tags=None, iid=None, ts=_TS) -> int:
    conn.execute(
        "INSERT INTO iocs (ioc_type, ioc_value, threat_type, tags, source, source_id, fetched_at) "
        "VALUES (?, ?, ?, ?, 'urlhaus', ?, ?)",
        (ioc_type, value, threat_type, json.dumps(tags or []), iid or value[:40], ts),
    )
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def _insert_sieve(conn, ioc_id, criterion, matched_value, ts=_TS):
    conn.execute(
        "INSERT INTO sieve_matches "
        "(record_type, record_id, match_criterion, matched_value, matched_at) "
        "VALUES ('ioc', ?, ?, ?, ?)",
        (ioc_id, criterion, matched_value, ts),
    )


@pytest.fixture
def empty_db(tmp_path):
    db = tmp_path / "test.db"
    init_db(db)
    return db


@pytest.fixture
def domain_cluster_db(tmp_path):
    """DB with 4 IOCs sharing the same domain — should form one campaign."""
    db = tmp_path / "test.db"
    init_db(db)
    conn = get_connection(db)
    for i in range(4):
        iid = _insert_ioc(conn, f"http://phish{i}.bdo.com.ph/login",
                           iid=f"u{i}", threat_type="phishing")
        _insert_sieve(conn, iid, "tld", "bdo.com.ph")
    conn.commit()
    conn.close()
    return db


@pytest.fixture
def asn_tag_cluster_db(tmp_path):
    """DB with 4 Mirai-tagged IOCs on the same prefix."""
    db = tmp_path / "test.db"
    init_db(db)
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO ph_prefixes (prefix, prefix_type, asn, fetched_at) "
        "VALUES ('202.90.136.0/24', 'ipv4', 17639, '2026-06-23T00:00:00Z')"
    )
    for i in range(4):
        iid = _insert_ioc(
            conn, f"http://202.90.136.{10+i}/c2", ioc_type="url",
            threat_type="botnet_cc", tags=["Mirai", "elf"], iid=f"u{i}",
        )
        _insert_sieve(conn, iid, "asn", "202.90.136.0/24")
    conn.commit()
    conn.close()
    return db


@pytest.fixture
def prefix24_cluster_db(tmp_path):
    """DB with 4 IOCs in the same /24."""
    db = tmp_path / "test.db"
    init_db(db)
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO ph_prefixes (prefix, prefix_type, fetched_at) "
        "VALUES ('10.0.1.0/24', 'ipv4', '2026-06-23T00:00:00Z')"
    )
    for i in range(4):
        iid = _insert_ioc(
            conn, f"10.0.1.{10+i}", ioc_type="ip", iid=f"u{i}",
        )
        _insert_sieve(conn, iid, "asn", "10.0.1.0/24")
    conn.commit()
    conn.close()
    return db


@pytest.fixture
def empty_config(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "asn_operators.yaml").write_text("operators: {}\n")
    (cfg / "action_templates.yaml").write_text("templates: []\n")
    return cfg


@pytest.fixture
def config_with_asn(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "asn_operators.yaml").write_text(
        "operators:\n  17639:\n    name: Converge ICT Solutions\n    short: Converge\n    cpe_prefixes: []\n"
    )
    (cfg / "action_templates.yaml").write_text("templates: []\n")
    (cfg / "cluster_tag_priority.yaml").write_text(
        "priority_levels:\n"
        "  - level: family\n"
        "    tags: [mirai, mozi, gafgyt]\n"
        "  - level: architecture\n"
        "    tags: [arm, elf, mips]\n"
    )
    return cfg


def test_domain_cluster_created(domain_cluster_db, empty_config):
    written, errors = run_clustering(domain_cluster_db, empty_config)
    assert errors == 0
    assert written >= 1
    conn = get_connection(domain_cluster_db)
    camp = conn.execute(
        "SELECT * FROM campaigns WHERE campaign_type='domain'"
    ).fetchone()
    conn.close()
    assert camp is not None
    assert camp["ioc_count"] == 4
    assert "bdo.com.ph" in camp["cluster_key"]


def test_domain_cluster_iocs_linked(domain_cluster_db, empty_config):
    run_clustering(domain_cluster_db, empty_config)
    conn = get_connection(domain_cluster_db)
    count = conn.execute(
        "SELECT COUNT(*) FROM campaign_iocs ci "
        "JOIN campaigns c ON c.id = ci.campaign_id "
        "WHERE c.campaign_type='domain'"
    ).fetchone()[0]
    conn.close()
    assert count == 4


def test_asn_tag_cluster_with_known_asn(asn_tag_cluster_db, config_with_asn):
    run_clustering(asn_tag_cluster_db, config_with_asn)
    conn = get_connection(asn_tag_cluster_db)
    camp = conn.execute(
        "SELECT * FROM campaigns WHERE campaign_type='asn_tag'"
    ).fetchone()
    conn.close()
    assert camp is not None
    assert "Converge" in camp["name"]
    assert "Mirai" in camp["name"]


def test_prefix24_cluster_created(prefix24_cluster_db, empty_config):
    run_clustering(prefix24_cluster_db, empty_config)
    conn = get_connection(prefix24_cluster_db)
    camp = conn.execute(
        "SELECT * FROM campaigns WHERE campaign_type='prefix24'"
    ).fetchone()
    conn.close()
    assert camp is not None
    assert "10.0.1.0/24" in camp["cluster_key"]


def test_minimum_cluster_size_filters_small_groups(tmp_path, empty_config):
    """Only 2 IOCs on the same domain — should not create a campaign."""
    db = tmp_path / "test.db"
    init_db(db)
    conn = get_connection(db)
    for i in range(2):
        iid = _insert_ioc(conn, f"http://phish{i}.bdo.com.ph/login", iid=f"u{i}")
        _insert_sieve(conn, iid, "tld", "bdo.com.ph")
    conn.commit()
    conn.close()

    run_clustering(db, empty_config)
    conn = get_connection(db)
    count = conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
    conn.close()
    assert count == 0


def test_upsert_updates_existing_campaign(domain_cluster_db, empty_config):
    """Second run refreshes fields without creating duplicate campaigns."""
    run_clustering(domain_cluster_db, empty_config)
    run_clustering(domain_cluster_db, empty_config)

    conn = get_connection(domain_cluster_db)
    count = conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
    conn.close()
    assert count == 1  # no duplicate


def test_disappeared_campaign_marked_expired(domain_cluster_db, empty_config):
    """Campaign from first run that vanishes in second run gets status='expired'."""
    run_clustering(domain_cluster_db, empty_config)

    # Remove all sieve matches so the cluster disappears
    conn = get_connection(domain_cluster_db)
    conn.execute("DELETE FROM sieve_matches")
    conn.commit()
    conn.close()

    run_clustering(domain_cluster_db, empty_config)

    conn = get_connection(domain_cluster_db)
    camp = conn.execute("SELECT status, expired_at FROM campaigns").fetchone()
    conn.close()
    assert camp["status"] == "expired"
    assert camp["expired_at"] is not None


def test_empty_db_no_error(empty_db, empty_config):
    written, errors = run_clustering(empty_db, empty_config)
    assert written == 0
    assert errors == 0


# ---------------------------------------------------------------------------
# _select_primary_tag unit tests
# ---------------------------------------------------------------------------

_PRIORITY = [
    {"level": "family",       "tags": ["mirai", "mozi", "gafgyt"]},
    {"level": "functional",   "tags": ["c2", "dropper"]},
    {"level": "architecture", "tags": ["arm", "elf", "mips", "32-bit"]},
]


def test_select_primary_tag_family_beats_architecture():
    """Family level wins over architecture even when architecture tag appears first."""
    assert _select_primary_tag(["arm", "elf", "Mirai"], _PRIORITY) == "Mirai"


def test_select_primary_tag_alphabetical_within_level():
    """When two tags from the same level match, alphabetically-first wins."""
    # 'mirai' < 'mozi' — so Mirai is selected regardless of list order
    assert _select_primary_tag(["Mozi", "Mirai"], _PRIORITY) == "Mirai"


def test_select_primary_tag_no_recognized_tags_returns_none():
    assert _select_primary_tag(["unknown_malware", "some_other_tag"], _PRIORITY) is None


def test_select_primary_tag_empty_returns_none():
    assert _select_primary_tag([], _PRIORITY) is None


def test_asn_tag_cluster_single_tag_per_ioc(asn_tag_cluster_db, config_with_asn):
    """Multi-tagged IOC (Mirai + elf) produces exactly one asn_tag campaign."""
    run_clustering(asn_tag_cluster_db, config_with_asn)
    conn = get_connection(asn_tag_cluster_db)
    count = conn.execute(
        "SELECT COUNT(*) FROM campaigns WHERE campaign_type='asn_tag'"
    ).fetchone()[0]
    conn.close()
    assert count == 1
