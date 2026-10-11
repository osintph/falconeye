"""Campaign clustering for the Phishing Domain Hunt.

A real phishing operation registers many lookalikes that share a brand theme (the
MMDA LTO/NCAP fine-lure run: mmda-ltoncap.net, mmdancap-ncr.icu, ncapmmdar.com,
all Aug to Oct 2026 on cheap TLDs). Candidates that share a theme term form a
campaign; a cluster of three or more boosts every member and is reported as a
named section. The registration window, registrars, hosting ASNs and TLDs are
carried as corroborating evidence. No em dashes in this module.
"""
from __future__ import annotations

from app.scanner.scope import registrable

MIN_CLUSTER = 3


def _tld(domain: str) -> str:
    reg = registrable(domain) or domain
    return reg.split(".", 1)[1] if "." in reg else ""


def build(candidates: list) -> tuple:
    """Group candidates sharing a brand theme term into campaigns. Returns
    (campaigns, domain_to_campaign_id). Each candidate dict is expected to carry
    domain, themes, and (when known) reg_date, registrar and asn."""
    themed = [c for c in candidates if c.get("themes")]
    # Union-find over candidates that share any theme term.
    parent = {c["domain"]: c["domain"] for c in themed}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    by_term: dict = {}
    for c in themed:
        for t in c["themes"]:
            by_term.setdefault(t, []).append(c["domain"])
    for members in by_term.values():
        for d in members[1:]:
            union(members[0], d)

    comps: dict = {}
    for c in themed:
        comps.setdefault(find(c["domain"]), []).append(c)

    campaigns = []
    dom_to_cid = {}
    cid = 0
    for root, members in comps.items():
        if len(members) < MIN_CLUSTER:
            continue
        cid += 1
        theme_terms = sorted({t for m in members for t in m["themes"]})
        dates = sorted(m["reg_date"] for m in members if m.get("reg_date"))
        registrars = sorted({m["registrar"] for m in members if m.get("registrar")})
        asns = sorted({str(m["asn"]) for m in members if m.get("asn")})
        tlds = sorted({_tld(m["domain"]) for m in members})
        doms = [m["domain"] for m in members]
        for d in doms:
            dom_to_cid[d] = cid
        campaigns.append({
            "id": cid,
            "theme": ", ".join(theme_terms) or "brand lookalikes",
            "members": sorted(doms),
            "count": len(doms),
            "window": {"first": dates[0] if dates else None,
                       "last": dates[-1] if dates else None},
            "registrars": registrars, "asns": asns, "tlds": tlds,
        })
    campaigns.sort(key=lambda c: -c["count"])
    return campaigns, dom_to_cid
