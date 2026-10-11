"""Turn probed hosts and the apex mail posture into findings, by severity.

Finding kinds:
  takeover         a dangling CNAME or a matched takeover fingerprint
  cert             an expired or soon-to-expire TLS certificate
  private_ip       a host whose published A/AAAA points into private space
  admin_surface    an exposed admin or login panel
  open_service     an unexpected open service (database, RDP, SMB, telnet)
  headers          missing security headers on a live host
  mail_posture     SPF/DMARC/MTA-STS/TLS-RPT gaps on the apex

Each finding is {host, severity, kind, title, detail}. Severity is one of
critical, high, medium, low, info. No em dashes in this module.
"""
from __future__ import annotations

import logging
import ssl
import time

from app.asm import fingerprints
from app.utils.safe_fetch import is_private_ip

log = logging.getLogger("falconeye.asm.findings")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_RISKY_PORTS = {
    23: "Telnet", 445: "SMB", 1433: "Microsoft SQL Server", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    9200: "Elasticsearch", 27017: "MongoDB",
}
_ADMIN_HIGH = {
    "phpmyadmin": "phpMyAdmin", "adminer": "Adminer", "grafana": "Grafana",
    "kibana": "Kibana", "jenkins": "Jenkins", "gitlab": "GitLab",
    "portainer": "Portainer",
}
_ADMIN_MED = ("login", "sign in", "admin", "dashboard", "control panel")


def _cert_days_left(valid_to: str):
    if not valid_to:
        return None
    try:
        expires = ssl.cert_time_to_seconds(valid_to)
    except Exception:  # noqa: BLE001
        return None
    return int((expires - time.time()) // 86400)


def _host_findings(host: dict) -> list:
    out = []
    name = host.get("host", "")
    cname = host.get("cname", "")
    http = host.get("http") or {}
    body = host.get("_body", "") or ""

    # Takeover: dangling CNAME, or a matched service fingerprint.
    if cname:
        match = fingerprints.match(cname, body, cname_nxdomain=host.get("nxdomain", False))
        if match:
            sev = "critical" if match.get("vulnerable") else "high"
            out.append({
                "host": name, "severity": sev, "kind": "takeover",
                "title": "Subdomain takeover candidate",
                "detail": (f"{name} CNAME to {cname} ({match['service']}, "
                           f"{match['status']}): {match['reason']}"),
            })
        elif host.get("nxdomain"):
            out.append({
                "host": name, "severity": "high", "kind": "takeover",
                "title": "Dangling CNAME",
                "detail": f"{name} has a CNAME to {cname} that does not resolve (NXDOMAIN).",
            })

    # Certificate expiry.
    tls = host.get("tls") or {}
    days = _cert_days_left(tls.get("valid_to", ""))
    if days is not None:
        if days < 0:
            out.append({"host": name, "severity": "high", "kind": "cert",
                        "title": "Certificate expired",
                        "detail": f"{name} TLS certificate expired {abs(days)} days ago "
                                  f"(issuer {tls.get('issuer') or 'n/a'})."})
        elif days <= 7:
            out.append({"host": name, "severity": "high", "kind": "cert",
                        "title": "Certificate expires within 7 days",
                        "detail": f"{name} TLS certificate expires in {days} days "
                                  f"(issuer {tls.get('issuer') or 'n/a'})."})
        elif days <= 30:
            out.append({"host": name, "severity": "medium", "kind": "cert",
                        "title": "Certificate expires within 30 days",
                        "detail": f"{name} TLS certificate expires in {days} days "
                                  f"(issuer {tls.get('issuer') or 'n/a'})."})

    # Private or reserved A/AAAA records (resolve_and_check already refuses to
    # connect to these, but a published private record is itself a finding).
    dns = host.get("dns") or {}
    private_addrs = [ip for ip in (dns.get("a", []) + dns.get("aaaa", [])) if is_private_ip(ip)]
    if private_addrs:
        out.append({"host": name, "severity": "medium", "kind": "private_ip",
                    "title": "Host resolves to a private or reserved address",
                    "detail": f"{name} publishes {', '.join(private_addrs[:5])}, which is "
                              f"private or reserved space and should not be in public DNS."})

    # Exposed admin / login surface.
    title = (http.get("title") or "").lower()
    status = http.get("status")
    if status and status < 500:
        for needle, label in _ADMIN_HIGH.items():
            if needle in title or needle in body.lower():
                out.append({"host": name, "severity": "high", "kind": "admin_surface",
                            "title": "Exposed admin surface",
                            "detail": f"{name} serves {label} "
                                      f"(HTTP {status}, title {http.get('title') or 'n/a'})."})
                break
        else:
            if any(k in title for k in _ADMIN_MED):
                out.append({"host": name, "severity": "medium", "kind": "admin_surface",
                            "title": "Exposed login or admin page",
                            "detail": f"{name} serves a login or admin page "
                                      f"(HTTP {status}, title {http.get('title') or 'n/a'})."})

    # Unexpected open services.
    for p in host.get("open_ports") or []:
        port = p.get("port")
        if port in _RISKY_PORTS:
            banner = p.get("banner")
            detail = f"{name} has {_RISKY_PORTS[port]} open on port {port}."
            if banner:
                detail += f" Banner: {banner}"
            out.append({"host": name, "severity": "medium", "kind": "open_service",
                        "title": f"{_RISKY_PORTS[port]} exposed to the internet",
                        "detail": detail})

    # Missing security headers on a live host.
    sec = http.get("sec") or {}
    if status and status < 400 and sec:
        missing = [h for h, present in sec.items() if not present]
        if missing:
            out.append({"host": name, "severity": "low", "kind": "headers",
                        "title": "Missing security headers",
                        "detail": f"{name} is missing: {', '.join(sorted(missing))}."})
    return out


def _apex_findings(domain: str, posture: dict) -> list:
    out = []
    spf = posture.get("spf") or {}
    dmarc = posture.get("dmarc") or {}
    if not spf.get("found"):
        out.append({"host": domain, "severity": "medium", "kind": "mail_posture",
                    "title": "No SPF record", "detail": f"{domain} publishes no SPF record."})
    if not dmarc.get("found"):
        out.append({"host": domain, "severity": "medium", "kind": "mail_posture",
                    "title": "No DMARC policy",
                    "detail": f"{domain} publishes no DMARC record, so receivers cannot tell "
                              f"spoofed mail from genuine mail."})
    elif (dmarc.get("policy") or "none") == "none":
        out.append({"host": domain, "severity": "low", "kind": "mail_posture",
                    "title": "DMARC policy is p=none",
                    "detail": f"{domain} has DMARC with p=none, which only monitors and does "
                              f"not reject spoofed mail."})
    if not posture.get("mta_sts"):
        out.append({"host": domain, "severity": "low", "kind": "mail_posture",
                    "title": "No MTA-STS policy",
                    "detail": f"{domain} publishes no MTA-STS policy."})
    if not posture.get("tls_rpt"):
        out.append({"host": domain, "severity": "info", "kind": "mail_posture",
                    "title": "No TLS-RPT record",
                    "detail": f"{domain} publishes no SMTP TLS reporting (TLS-RPT) record."})
    return out


def build(domain: str, hosts: list, posture: dict) -> list:
    """All findings, most severe first."""
    out = []
    for host in hosts:
        try:
            out.extend(_host_findings(host))
        except Exception as exc:  # noqa: BLE001 - one bad host must not sink the run
            log.warning("asm findings: host analysis failed: %s", exc)
    out.extend(_apex_findings(domain, posture or {}))
    out.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    return out
