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
    """What GET /api/asm/scan/{id} returns (legacy, from stored hosts/findings)."""
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


# ---------------------------------------------- one-time payload (v3.38.0) ----

def asm_source_status(disc: dict) -> tuple:
    """Return (status_list, incomplete). CT, passive DNS and Wayback are
    discovery sources: if any failed, the run is INCOMPLETE and a zero result is
    not a clean result. RIPEstat is ASN context and does not make a run
    incomplete on its own."""
    sources = disc.get("sources") or {}
    out = []
    incomplete = False
    for key, role in (("ct", "CT discovery (crt.sh, Cert Spotter)"),
                      ("passive_dns", "passive DNS (Mnemonic)"),
                      ("wayback", "historic hostnames (Wayback)")):
        info = sources.get(key) or {}
        answered = bool(info.get("ok"))
        if not answered:
            incomplete = True
        out.append({"source": _SRC_LABEL[key], "role": role,
                    "status": "answered" if answered else "failed"})
    asn_ok = bool((disc.get("asn") or {}).get("available"))
    out.append({"source": "RIPEstat", "role": "ASN and routing context",
                "status": "answered" if asn_ok else "skipped"})
    return out, incomplete


_SRC_LABEL = {"ct": "crt.sh / Cert Spotter", "passive_dns": "Mnemonic", "wayback": "Wayback Machine"}


def host_view_from_record(r: dict) -> dict:
    """A host row from a probe record (the one-time path does not store hosts)."""
    kind = "reference" if r.get("is_reference") else ("cdn" if r.get("cdn_provider") else "own")
    http = r.get("http") or {}
    return {
        "host": r.get("host"), "kind": kind,
        "resolved_ips": r.get("resolved_ips") or [],
        "cname": r.get("cname_target") or r.get("cname") or "",
        "cdn": r.get("cdn_provider") or "",
        "ports": [p.get("port") for p in (r.get("open_ports") or [])],
        "server": http.get("server", ""), "status": http.get("status"),
        "title": http.get("title", ""), "tls": r.get("tls"),
        "tech": r.get("fingerprint") or [],
    }


def build_asm_payload(scan: dict, records: list, found: list, disc: dict, posture: dict,
                      generated_ts) -> dict:
    """The one-time payload: rendered on screen once and into the PDF, then
    purged. Same structure for both so they cannot disagree."""
    from app import config
    status_list, incomplete = asm_source_status(disc)
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in found:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    hosts = [host_view_from_record(r) for r in records]
    kinds = [h["kind"] for h in hosts]
    in_scope = sum(1 for k in kinds if k in ("own", "cdn"))
    behind = sum(1 for k in kinds if k == "cdn")
    refs = sum(1 for k in kinds if k == "reference")
    refhosts = [h["host"] for h in hosts if h["kind"] in ("cdn", "reference")]
    refnote = ("CDN-fronted and third-party-CNAME hosts were not port scanned: "
               + ", ".join(refhosts[:12]) + ".") if refhosts else ""
    methodology = (
        "Passive discovery (crt.sh, Cert Spotter, Mnemonic passive DNS, the Wayback "
        "Machine) and RIPEstat ASN context, then a light active probe (DNS, HTTP and "
        "TLS through the SSRF-safe fetcher, header-based tech fingerprint) and a "
        "conservative TCP connect scan. Only the target's own hosts are probed; CDN "
        "edges and third-party CNAME targets are recorded as references and never port "
        f"scanned. Caps this run: {config.ASM_MAX_HOSTS_PER_RUN} hosts, about 25 ports "
        f"per host, {config.ASM_PORT_TIMEOUT_SECONDS}s per connect, "
        f"{config.ASM_RUN_TIMEOUT_SECONDS}s per run.")
    sline = (f"{len(disc.get('hosts') or [])} hosts discovered, {in_scope} in scope, "
             f"{behind} behind a CDN and not port scanned, {refs} third-party reference(s).")
    if incomplete:
        sline = "INCOMPLETE run. " + sline + " A discovery source did not answer."
    return {
        "kind": "asm", "title": scan["domain"], "generated_ts": generated_ts,
        "scan_id": scan["scan_id"], "state": "done",
        "mode": scan.get("mode", "On-demand"), "engagement": scan.get("engagement") or "",
        "operator": bool(scan.get("operator")), "incomplete": incomplete,
        "source_status": status_list, "severity_counts": counts, "summary_line": sline,
        "in_scope": in_scope, "behind_cdn": behind, "references": refs,
        "discovered": len(disc.get("hosts") or []), "hosts_probed": len(records),
        "findings": sorted(found, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 9)),
        "hosts": hosts, "posture": _posture_brief(posture or {}),
        "references_note": refnote, "methodology": methodology,
        "attribution": SOURCE_ATTRIBUTION,
    }


def export_json_payload(payload: dict) -> str:
    return json.dumps(payload, indent=2)


def export_csv_payload(payload: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([f"FalconEye {payload.get('kind', 'asm')} report for {payload.get('title')}"])
    w.writerow([f"Generated {_utc_iso(payload.get('generated_ts'))}"])
    if payload.get("incomplete"):
        w.writerow(["INCOMPLETE: a discovery source did not answer"])
    w.writerow([])
    w.writerow(["Source", "Status"])
    for s in payload.get("source_status", []):
        w.writerow([s.get("source"), s.get("status")])
    w.writerow([])
    if payload.get("kind") == "hunt":
        w.writerow(["Candidate", "Verdict", "Score", "Registered", "Evidence"])
        for c in payload.get("candidates", []):
            w.writerow([c.get("domain"), c.get("verdict"), c.get("score"),
                        c.get("registered") or "n/a", "; ".join(c.get("evidence") or [])])
        return buf.getvalue()
    w.writerow(["Findings"])
    w.writerow(["severity", "kind", "host", "title", "detail"])
    for f in payload.get("findings", []):
        w.writerow([f.get("severity"), f.get("kind"), f.get("host") or "n/a",
                    f.get("title"), f.get("detail") or "n/a"])
    w.writerow([])
    w.writerow(["Hosts"])
    w.writerow(["host", "kind", "ips", "ports", "server"])
    for h in payload.get("hosts", []):
        ports = ("|".join(str(p) for p in h.get("ports") or [])
                 if h["kind"] == "own" else "not scanned")
        w.writerow([h["host"], h["kind"], "|".join(h.get("resolved_ips") or []) or "n/a",
                    ports or "none", h.get("server") or "n/a"])
    return buf.getvalue()


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
