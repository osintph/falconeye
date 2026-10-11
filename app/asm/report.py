"""Summary, API payload, exports, and monitoring snapshots for a scan.

The summary is stored on the scan row; the API payload is what the tab renders;
the JSON and CSV exports and the jsPDF path (built client-side) all read the
stored hosts and findings. A snapshot is the comparable shape monitoring diffs
from run to run. Empty cells are "n/a", never an em dash. No em dashes anywhere
in this module.
"""
from __future__ import annotations

import csv
import io
import json
import time

from app.asm import fingerprints
from app.asm.findings import SEVERITY_ORDER

RIPESTAT_ATTRIBUTION = "Source: RIPEstat (RIPE NCC)."
SOURCE_ATTRIBUTION = [
    "Certificate transparency: crt.sh and Cert Spotter.",
    "Passive DNS: Mnemonic.",
    "Historic hostnames: Internet Archive Wayback Machine.",
    RIPESTAT_ATTRIBUTION,
    fingerprints.ATTRIBUTION,
]


def _utc_iso(ts=None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts or time.time()))


def summarize(domain: str, records: list, found: list, disc: dict, posture: dict) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in found:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    kinds = [r.get("kind") for r in records]
    return {
        "domain": domain,
        "generated": _utc_iso(),
        "discovered": len(disc.get("hosts") or []),
        "hosts_probed": len(records),
        "in_scope": sum(1 for k in kinds if k in ("own", "cdn")),
        "own": sum(1 for k in kinds if k == "own"),
        "behind_cdn": sum(1 for k in kinds if k == "cdn"),
        "references": sum(1 for k in kinds if k == "reference"),
        "severity_counts": counts,
        "findings_total": len(found),
        "sources": disc.get("sources") or {},
        "asn": _asn_brief(disc.get("asn") or {}),
        "mail_posture": _posture_brief(posture or {}),
        "attribution": SOURCE_ATTRIBUTION,
    }


def _asn_brief(asn: dict) -> dict:
    if not asn.get("available"):
        return {"available": False}
    return {"available": True, "asn": asn.get("asn"),
            "name": asn.get("description") or asn.get("name"),
            "prefix": asn.get("covering_prefix")}


def _posture_brief(posture: dict) -> dict:
    spf = posture.get("spf") or {}
    dmarc = posture.get("dmarc") or {}
    return {
        "spf": bool(spf.get("found")),
        "dmarc": bool(dmarc.get("found")),
        "dmarc_policy": dmarc.get("policy") or "n/a",
        "mta_sts": bool(posture.get("mta_sts")),
        "tls_rpt": bool(posture.get("tls_rpt")),
    }


def _host_view(h: dict) -> dict:
    """One host row for the API, without the internal body sample."""
    ports = h.get("open_ports") or []
    kind = _infer_kind(h)
    return {
        "host": h.get("host"),
        "kind": kind,
        "resolved_ips": h.get("resolved_ips") or [],
        "cname": h.get("cname") or "",
        "cdn": h.get("cdn") or "",
        "is_reference": bool(h.get("is_reference")),
        "ports": [p.get("port") for p in ports],
        "server": (h.get("http") or {}).get("server", ""),
        "status": (h.get("http") or {}).get("status"),
        "title": (h.get("http") or {}).get("title", ""),
        "tls": h.get("tls"),
        "tech": (h.get("fingerprint") or {}).get("tech", []) if isinstance(h.get("fingerprint"), dict) else [],
    }


def _infer_kind(h: dict) -> str:
    if h.get("is_reference"):
        return "reference"
    if h.get("cdn"):
        return "cdn"
    return "own"


def api_payload(scan: dict, hosts: list, found: list) -> dict:
    """What GET /api/asm/scan/{id} returns."""
    return {
        "scan_id": scan["scan_id"],
        "domain": scan["domain"],
        "mode": scan["mode"],
        "state": scan["state"],
        "operator": bool(scan.get("operator")),
        "engagement": scan.get("engagement") or "",
        "error": scan.get("error"),
        "summary": scan.get("summary"),
        "hosts": [_host_view(h) for h in hosts],
        "findings": sorted(found, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 9)),
    }


def export_json(scan: dict, hosts: list, found: list) -> str:
    return json.dumps(api_payload(scan, hosts, found), indent=2)


def export_csv(scan: dict, hosts: list, found: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([f"FalconEye attack surface report for {scan['domain']}"])
    w.writerow([f"Generated {_utc_iso()}"])
    if scan.get("operator") and scan.get("engagement"):
        w.writerow([f"Engagement: {scan['engagement']}"])
    w.writerow([])
    w.writerow(["Findings"])
    w.writerow(["severity", "kind", "host", "title", "detail"])
    for f in sorted(found, key=lambda x: SEVERITY_ORDER.get(x.get("severity"), 9)):
        w.writerow([f.get("severity"), f.get("kind"), f.get("host") or "n/a",
                    f.get("title"), f.get("detail") or "n/a"])
    w.writerow([])
    w.writerow(["Hosts"])
    w.writerow(["host", "kind", "resolved_ips", "cname", "cdn", "open_ports", "server", "status"])
    for h in hosts:
        v = _host_view(h)
        w.writerow([
            v["host"], v["kind"], "|".join(v["resolved_ips"]) or "n/a",
            v["cname"] or "n/a", v["cdn"] or "n/a",
            "|".join(str(p) for p in v["ports"]) or ("not scanned" if v["kind"] != "own" else "none"),
            v["server"] or "n/a", v["status"] if v["status"] is not None else "n/a",
        ])
    return buf.getvalue()


# ----------------------------------------------------------- monitoring diff ----

def snapshot(hosts: list, found: list) -> dict:
    """The comparable shape monitoring diffs on."""
    host_map = {}
    for h in hosts:
        v = _host_view(h)
        host_map[v["host"]] = {
            "ports": sorted(v["ports"]),
            "cname": v["cname"],
            "cert_to": (v["tls"] or {}).get("valid_to") if v.get("tls") else None,
        }
    finding_keys = sorted({f"{f.get('kind')}|{f.get('host') or ''}|{f.get('title')}" for f in found})
    return {"hosts": host_map, "findings": finding_keys, "taken": _utc_iso()}


def diff(old: dict, new: dict) -> dict:
    """Human-readable differences between two snapshots. {changed, lines}."""
    if not old:
        return {"changed": False, "lines": []}
    lines = []
    old_hosts, new_hosts = set(old.get("hosts", {})), set(new.get("hosts", {}))
    for h in sorted(new_hosts - old_hosts):
        lines.append(f"New host: {h}")
    for h in sorted(old_hosts - new_hosts):
        lines.append(f"Removed host: {h}")
    for h in sorted(new_hosts & old_hosts):
        o, n = old["hosts"][h], new["hosts"][h]
        gained = sorted(set(n["ports"]) - set(o["ports"]))
        lost = sorted(set(o["ports"]) - set(n["ports"]))
        if gained:
            lines.append(f"{h}: new open ports {', '.join(str(p) for p in gained)}")
        if lost:
            lines.append(f"{h}: closed ports {', '.join(str(p) for p in lost)}")
        if o.get("cname") != n.get("cname"):
            lines.append(f"{h}: CNAME changed from {o.get('cname') or 'n/a'} to {n.get('cname') or 'n/a'}")
        if o.get("cert_to") != n.get("cert_to"):
            lines.append(f"{h}: certificate changed")
    new_findings = sorted(set(new.get("findings", [])) - set(old.get("findings", [])))
    for key in new_findings:
        kind, host, title = (key.split("|", 2) + ["", "", ""])[:3]
        lines.append(f"New finding on {host or 'apex'}: {title}")
    return {"changed": bool(lines), "lines": lines}
