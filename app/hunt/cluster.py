"""Campaign clustering for the Phishing Domain Hunt.

A theme term groups candidates, but a group is only a CAMPAIGN (and only then
boosts its members to Likely Phishing) when it is corroborated: its registrations
fall inside a window (default 60 days) AND it shares at least one registrar,
nameserver, hosting ASN or cheap-TLD family. A theme-only group with no
corroboration is reported as "related brand-themed domains" and gives no boost, so
a loose run of name matches over many months is not called a campaign. No em
dashes in this module.
"""
from __future__ import annotations

from collections import Counter

from app import config
from app.scanner.scope import registrable

MIN_CLUSTER = 3


def _tld(domain: str) -> str:
    reg = registrable(domain) or domain
    return reg.split(".", 1)[1] if "." in reg else ""


def _corroboration(members: list) -> tuple:
    """Return (corroborated, reasons). Needs a tight registration window AND at
    least one shared registrar, nameserver, ASN or cheap-TLD family."""
    ages = [m["reg_age_days"] for m in members
            if isinstance(m.get("reg_age_days"), int) and m["reg_age_days"] >= 0]
    window_ok = len(ages) >= 2 and (max(ages) - min(ages)) <= config.HUNT_CAMPAIGN_WINDOW_DAYS
    reasons = []
    if window_ok:
        reasons.append(f"registered within {max(ages) - min(ages)} days")

    def _shared(key):
        vals = [str(m.get(key)) for m in members if m.get(key)]
        c = Counter(vals)
        return c.most_common(1)[0][0] if c and c.most_common(1)[0][1] >= 2 else None

    shared = []
    reg = _shared("registrar")
    if reg:
        shared.append(f"shared registrar {reg}")
    asn = _shared("asn")
    if asn:
        shared.append(f"shared hosting {asn}")
    ns_counter = Counter(n for m in members for n in (m.get("ns") or []))
    ns_hit = [n for n, k in ns_counter.items() if k >= 2]
    if ns_hit:
        shared.append(f"shared nameserver {ns_hit[0]}")
    if sum(1 for m in members if m.get("cheap")) >= 2:
        shared.append("cheap-TLD family")

    corroborated = bool(window_ok and shared)
    return corroborated, (reasons + shared)


def build(candidates: list) -> tuple:
    """Group candidates by shared theme term, then split into corroborated
    campaigns (which boost members) and uncorroborated related groups (which do
    not). Returns (campaigns, related_groups, domain_to_campaign_id)."""
    themed = [c for c in candidates if c.get("themes")]
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

    campaigns, related = [], []
    dom_to_cid = {}
    cid = 0
    for members in comps.values():
        if len(members) < MIN_CLUSTER:
            continue
        theme_terms = sorted({t for m in members for t in m["themes"]})
        dates = sorted(m["reg_date"] for m in members if m.get("reg_date"))
        registrars = sorted({m["registrar"] for m in members if m.get("registrar")})
        asns = sorted({str(m["asn"]) for m in members if m.get("asn")})
        tlds = sorted({_tld(m["domain"]) for m in members})
        doms = sorted(m["domain"] for m in members)
        corroborated, reasons = _corroboration(members)
        entry = {
            "theme": ", ".join(theme_terms) or "brand lookalikes",
            "members": doms, "count": len(doms),
            "window": {"first": dates[0] if dates else None,
                       "last": dates[-1] if dates else None},
            "registrars": registrars, "asns": asns, "tlds": tlds,
            "corroboration": reasons,
        }
        if corroborated:
            cid += 1
            entry["id"] = cid
            for d in doms:
                dom_to_cid[d] = cid
            campaigns.append(entry)
        else:
            related.append(entry)
    campaigns.sort(key=lambda c: -c["count"])
    related.sort(key=lambda c: -c["count"])
    return campaigns, related, dom_to_cid
