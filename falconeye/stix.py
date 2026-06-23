"""STIX 2.1 object emitter for FalconEye IOCs, CVEs, and campaigns.

Hand-written JSON — no stix2 library dependency.
Stable UUIDv5 IDs derived from a fixed FalconEye namespace and a
per-record key, so the same object always gets the same STIX ID across runs.
"""
from __future__ import annotations

import logging
import uuid

log = logging.getLogger(__name__)

# Fixed UUID namespace for FalconEye STIX IDs.
# Generated once; must never change — changing this invalidates all existing IDs.
FALCONEYE_NS = uuid.UUID("c40e7b5b-eac2-471d-a05f-2bb8e2be4b39")

STIX_SPEC_VERSION = "2.1"

# Maps URLhaus threat_type values to STIX labels.
# Unknown values default to "malicious-activity" (Adjustment 4).
_THREAT_LABEL_MAP: dict[str, str] = {
    "malware_download":    "malicious-activity",
    "malware_distribution":"malicious-activity",
    "malware":             "malicious-activity",
    "dropper":             "malicious-activity",
    "exploit":             "malicious-activity",
    "c2":                  "command-and-control",
    "botnet_cc":           "command-and-control",
    "phishing":            "phishing",
    "phishing_kit":        "phishing",
}

_IOC_PATTERN_MAP: dict[str, str] = {
    "url":    "url:value",
    "ip":     "ipv4-addr:value",
    "domain": "domain-name:value",
}


def stix_id(object_type: str, key: str) -> str:
    """Return a stable STIX ID for the given type and deduplication key."""
    uid = uuid.uuid5(FALCONEYE_NS, f"{object_type}:{key}")
    return f"{object_type}--{uid}"


def ioc_to_indicator(ioc: dict) -> dict | None:
    """
    Convert a sieve-matched IOC dict to a STIX 2.1 indicator object.

    Returns None if the IOC type is not mappable to a STIX pattern.
    """
    ioc_type = ioc.get("ioc_type") or ""
    ioc_value = ioc.get("ioc_value") or ""
    if not ioc_value:
        return None

    stix_prop = _IOC_PATTERN_MAP.get(ioc_type)
    if not stix_prop:
        log.debug("STIX: no pattern mapping for ioc_type=%s, skipping %s", ioc_type, ioc_value)
        return None

    safe_value = ioc_value.replace("'", "\\'")
    pattern = f"[{stix_prop} = '{safe_value}']"

    threat_type = (ioc.get("threat_type") or "").lower()
    label = _THREAT_LABEL_MAP.get(threat_type)
    if not label:
        if threat_type:
            log.warning(
                "STIX: unknown threat_type %r for IOC %s, defaulting to malicious-activity",
                threat_type, ioc_value,
            )
        label = "malicious-activity"

    source = ioc.get("source") or "unknown"
    source_id = ioc.get("source_id") or ioc_value
    created = ioc.get("fetched_at") or ioc.get("first_seen") or "1970-01-01T00:00:00Z"
    valid_from = ioc.get("first_seen") or created

    obj: dict = {
        "type":           "indicator",
        "spec_version":   STIX_SPEC_VERSION,
        "id":             stix_id("indicator", f"{source}:{source_id}"),
        "created":        created,
        "modified":       ioc.get("fetched_at") or created,
        "name":           f"{threat_type or 'malware'} indicator: {ioc_value[:120]}",
        "pattern":        pattern,
        "pattern_type":   "stix",
        "valid_from":     valid_from,
        "labels":         [label],
    }
    if ioc.get("source_url"):
        obj["external_references"] = [
            {"source_name": source, "url": ioc["source_url"]}
        ]
    return obj


def cve_to_vulnerability(cve: dict) -> dict:
    """Convert a sieve-matched CVE dict to a STIX 2.1 vulnerability object."""
    cve_id = cve.get("cve_id") or "CVE-UNKNOWN"
    created = cve.get("published_date") or cve.get("fetched_at") or "1970-01-01T00:00:00Z"
    modified = cve.get("last_modified") or cve.get("fetched_at") or created

    obj: dict = {
        "type":         "vulnerability",
        "spec_version": STIX_SPEC_VERSION,
        "id":           stix_id("vulnerability", cve_id),
        "created":      created,
        "modified":     modified,
        "name":         cve_id,
        "external_references": [
            {
                "source_name": "cve",
                "external_id": cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        ],
    }
    if cve.get("description"):
        obj["description"] = cve["description"]
    return obj


def campaign_to_stix(campaign: dict) -> dict:
    """Convert a campaign dict to a STIX 2.1 campaign object."""
    slug = campaign.get("slug") or campaign.get("cluster_key") or "unknown"
    created = campaign.get("first_seen") or campaign.get("generated_at") or "1970-01-01T00:00:00Z"
    modified = campaign.get("last_seen") or campaign.get("generated_at") or created

    obj: dict = {
        "type":         "campaign",
        "spec_version": STIX_SPEC_VERSION,
        "id":           stix_id("campaign", slug),
        "created":      created,
        "modified":     modified,
        "name":         campaign.get("name") or slug,
        "aliases":      [campaign.get("cluster_key") or slug],
    }
    if campaign.get("summary"):
        obj["description"] = campaign["summary"]
    if campaign.get("first_seen"):
        obj["first_seen"] = campaign["first_seen"]
    if campaign.get("last_seen"):
        obj["last_seen"] = campaign["last_seen"]
    return obj


def campaign_uses_indicator(campaign_stix_id: str, indicator_stix_id: str,
                             now_iso: str) -> dict:
    """Return a STIX 2.1 relationship: campaign uses indicator."""
    key = f"{campaign_stix_id}:uses:{indicator_stix_id}"
    return {
        "type":              "relationship",
        "spec_version":      STIX_SPEC_VERSION,
        "id":                stix_id("relationship", key),
        "created":           now_iso,
        "modified":          now_iso,
        "relationship_type": "uses",
        "source_ref":        campaign_stix_id,
        "target_ref":        indicator_stix_id,
    }


def make_bundle(objects: list[dict]) -> dict:
    """Wrap a list of STIX objects in a STIX 2.1 bundle."""
    return {
        "type":    "bundle",
        "id":      f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
