from __future__ import annotations

import json
import uuid

import pytest

from falconeye.stix import (
    FALCONEYE_NS,
    campaign_to_stix,
    campaign_uses_indicator,
    cve_to_vulnerability,
    ioc_to_indicator,
    make_bundle,
    stix_id,
)


# ---------------------------------------------------------------------------
# stix_id — stable deterministic IDs
# ---------------------------------------------------------------------------

def test_stix_id_stable():
    a = stix_id("indicator", "urlhaus:abc123")
    b = stix_id("indicator", "urlhaus:abc123")
    assert a == b


def test_stix_id_different_keys():
    a = stix_id("indicator", "urlhaus:abc")
    b = stix_id("indicator", "urlhaus:xyz")
    assert a != b


def test_stix_id_format():
    sid = stix_id("indicator", "urlhaus:abc123")
    assert sid.startswith("indicator--")
    # The UUID part must be a valid UUID
    parts = sid.split("--", 1)
    uuid.UUID(parts[1])  # raises if invalid


def test_stix_id_different_types():
    a = stix_id("indicator", "x")
    b = stix_id("vulnerability", "x")
    assert a != b


# ---------------------------------------------------------------------------
# ioc_to_indicator
# ---------------------------------------------------------------------------

_URL_IOC = {
    "id": 1, "ioc_type": "url", "ioc_value": "http://evil.ph/malware",
    "threat_type": "malware_download", "source": "urlhaus", "source_id": "u1",
    "first_seen": "2026-06-23T00:00:00Z", "fetched_at": "2026-06-23T01:00:00Z",
    "source_url": "https://urlhaus.abuse.ch/url/u1/",
}

_IP_IOC = {
    "id": 2, "ioc_type": "ip", "ioc_value": "202.90.136.5",
    "threat_type": "botnet_cc", "source": "urlhaus", "source_id": "u2",
    "first_seen": "2026-06-23T00:00:00Z", "fetched_at": "2026-06-23T01:00:00Z",
    "source_url": None,
}

_DOMAIN_IOC = {
    "id": 3, "ioc_type": "domain", "ioc_value": "malware.ph",
    "threat_type": "phishing", "source": "urlhaus", "source_id": "u3",
    "first_seen": "2026-06-23T00:00:00Z", "fetched_at": "2026-06-23T01:00:00Z",
    "source_url": None,
}

_UNKNOWN_TYPE_IOC = {
    "id": 4, "ioc_type": "hash", "ioc_value": "abc123",
    "threat_type": "malware", "source": "urlhaus", "source_id": "u4",
    "first_seen": "2026-06-23T00:00:00Z", "fetched_at": "2026-06-23T01:00:00Z",
    "source_url": None,
}


def test_ioc_indicator_url_pattern():
    obj = ioc_to_indicator(_URL_IOC)
    assert obj is not None
    assert "[url:value = 'http://evil.ph/malware']" == obj["pattern"]


def test_ioc_indicator_ip_pattern():
    obj = ioc_to_indicator(_IP_IOC)
    assert obj is not None
    assert "[ipv4-addr:value = '202.90.136.5']" == obj["pattern"]


def test_ioc_indicator_domain_pattern():
    obj = ioc_to_indicator(_DOMAIN_IOC)
    assert obj is not None
    assert "[domain-name:value = 'malware.ph']" == obj["pattern"]


def test_ioc_indicator_unknown_type_returns_none():
    obj = ioc_to_indicator(_UNKNOWN_TYPE_IOC)
    assert obj is None


def test_ioc_indicator_label_malware_download():
    obj = ioc_to_indicator(_URL_IOC)
    assert "malicious-activity" in obj["labels"]


def test_ioc_indicator_label_botnet_cc():
    obj = ioc_to_indicator(_IP_IOC)
    assert "command-and-control" in obj["labels"]


def test_ioc_indicator_label_phishing():
    obj = ioc_to_indicator(_DOMAIN_IOC)
    assert "phishing" in obj["labels"]


def test_ioc_indicator_unknown_threat_type_defaults(caplog):
    ioc = {**_URL_IOC, "threat_type": "totally_unknown_type"}
    import logging
    with caplog.at_level(logging.WARNING, logger="falconeye.stix"):
        obj = ioc_to_indicator(ioc)
    assert obj is not None
    assert "malicious-activity" in obj["labels"]
    assert "malicious-activity" in obj["labels"]
    assert any("totally_unknown_type" in r.message for r in caplog.records)


def test_ioc_indicator_threat_types_from_adjustment4():
    for tt, expected_label in [
        ("malware_distribution", "malicious-activity"),
        ("c2",                   "command-and-control"),
        ("dropper",              "malicious-activity"),
        ("phishing_kit",         "phishing"),
        ("exploit",              "malicious-activity"),
    ]:
        ioc = {**_URL_IOC, "threat_type": tt}
        obj = ioc_to_indicator(ioc)
        assert obj is not None, f"None for threat_type={tt}"
        assert expected_label in obj["labels"], f"{tt} → expected {expected_label}, got {obj['labels']}"


def test_ioc_indicator_has_external_ref():
    obj = ioc_to_indicator(_URL_IOC)
    assert "external_references" in obj
    assert obj["external_references"][0]["source_name"] == "urlhaus"


def test_ioc_indicator_no_external_ref_when_no_source_url():
    obj = ioc_to_indicator(_IP_IOC)
    assert "external_references" not in obj


def test_ioc_indicator_id_stable():
    a = ioc_to_indicator(_URL_IOC)
    b = ioc_to_indicator(_URL_IOC)
    assert a["id"] == b["id"]


def test_ioc_indicator_spec_version():
    obj = ioc_to_indicator(_URL_IOC)
    assert obj["spec_version"] == "2.1"


def test_ioc_indicator_single_quote_escaped():
    ioc = {**_URL_IOC, "ioc_value": "http://evil.ph/it's-malware"}
    obj = ioc_to_indicator(ioc)
    assert "\\'" in obj["pattern"]


# ---------------------------------------------------------------------------
# cve_to_vulnerability
# ---------------------------------------------------------------------------

_CVE = {
    "cve_id": "CVE-2024-1234",
    "description": "Critical vulnerability in Example Corp Widget",
    "published_date": "2024-01-10T00:00:00Z",
    "last_modified": "2024-01-15T00:00:00Z",
    "fetched_at": "2026-06-23T00:00:00Z",
}


def test_cve_vulnerability_name():
    obj = cve_to_vulnerability(_CVE)
    assert obj["name"] == "CVE-2024-1234"


def test_cve_vulnerability_type():
    obj = cve_to_vulnerability(_CVE)
    assert obj["type"] == "vulnerability"


def test_cve_vulnerability_external_ref():
    obj = cve_to_vulnerability(_CVE)
    assert any(
        r["source_name"] == "cve" and r["external_id"] == "CVE-2024-1234"
        for r in obj["external_references"]
    )


def test_cve_vulnerability_description():
    obj = cve_to_vulnerability(_CVE)
    assert "Critical vulnerability" in obj["description"]


def test_cve_vulnerability_id_stable():
    a = cve_to_vulnerability(_CVE)
    b = cve_to_vulnerability(_CVE)
    assert a["id"] == b["id"]


# ---------------------------------------------------------------------------
# campaign_to_stix
# ---------------------------------------------------------------------------

_CAMPAIGN = {
    "slug": "ast-as17639-mirai",
    "name": "Mirai on Converge (AS17639)",
    "summary": "15 Mirai-tagged IOCs on Converge.",
    "cluster_key": "AS17639:Mirai",
    "first_seen": "2026-06-10T00:00:00Z",
    "last_seen": "2026-06-23T00:00:00Z",
    "generated_at": "2026-06-23T01:00:00Z",
}


def test_campaign_type():
    obj = campaign_to_stix(_CAMPAIGN)
    assert obj["type"] == "campaign"


def test_campaign_name():
    obj = campaign_to_stix(_CAMPAIGN)
    assert obj["name"] == "Mirai on Converge (AS17639)"


def test_campaign_id_stable():
    a = campaign_to_stix(_CAMPAIGN)
    b = campaign_to_stix(_CAMPAIGN)
    assert a["id"] == b["id"]


def test_campaign_aliases():
    obj = campaign_to_stix(_CAMPAIGN)
    assert "AS17639:Mirai" in obj["aliases"]


# ---------------------------------------------------------------------------
# campaign_uses_indicator
# ---------------------------------------------------------------------------

def test_relationship_type():
    rel = campaign_uses_indicator("campaign--abc", "indicator--def", "2026-06-23T00:00:00Z")
    assert rel["type"] == "relationship"
    assert rel["relationship_type"] == "uses"
    assert rel["source_ref"] == "campaign--abc"
    assert rel["target_ref"] == "indicator--def"


def test_relationship_id_stable():
    a = campaign_uses_indicator("campaign--abc", "indicator--def", "2026-06-23T00:00:00Z")
    b = campaign_uses_indicator("campaign--abc", "indicator--def", "2026-06-23T00:00:00Z")
    assert a["id"] == b["id"]


# ---------------------------------------------------------------------------
# make_bundle
# ---------------------------------------------------------------------------

def test_bundle_type():
    bundle = make_bundle([])
    assert bundle["type"] == "bundle"


def test_bundle_contains_objects():
    obj = ioc_to_indicator(_URL_IOC)
    bundle = make_bundle([obj])
    assert bundle["objects"] == [obj]


def test_bundle_id_is_uuid():
    bundle = make_bundle([])
    parts = bundle["id"].split("--", 1)
    assert parts[0] == "bundle"
    uuid.UUID(parts[1])
