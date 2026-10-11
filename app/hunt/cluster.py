"""Campaign clustering for the Phishing Domain Hunt.

A theme term groups candidates, but a group is only a CAMPAIGN (and only then
boosts its members to Likely Phishing) when it is corroborated: its registrations
fall inside a window (default 60 days) AND it shares at least one registrar,
nameserver, hosting ASN or cheap-TLD family. A theme-only group with no
corroboration is reported as "related brand-themed domains" with no boost. Once a
campaign exists, a brand candidate that shares its registrar, nameserver or ASN
inside the window is merged in even without a theme term (scrambles like nocpmmda).
The campaign carries the shared registrar, nameservers, ASN, window and the
registrar abuse contact so a report can be filed from it. No em dashes here.
"""
from __future__ import annotations

from collections import Counter

from app import config
from app.scanner.scope import registrable

MIN_CLUSTER = 3


def _tld(domain: str) -> str:
    reg = registrable(domain) or domain
    return reg.split(".", 1)[1] if "." in reg else ""


def _ages(members: list) -> list:
    return [m["reg_age_days"] for m in members
            if isinstance(m.get("reg_age_days"), int) and m["reg_age_days"] >= 0]


def _shared_most(members: list, key: str):
    vals = [str(m.get(key)) for m in members if m.get(key)]
    c = Counter(vals)
    return c.most_common(1)[0][0] if c and c.most_common(1)[0][1] >= 2 else None


def _corroboration(members: list) -> tuple:
    ages = _ages(members)
    window_ok = len(ages) >= 2 and (max(ages) - min(ages)) <= config.HUNT_CAMPAIGN_WINDOW_DAYS
    reasons = []
    if window_ok:
        reasons.append(f"registered within {max(ages) - min(ages)} days")
    shared = []
    reg = _shared_most(members, "registrar")
    if reg:
        shared.append(f"shared registrar {reg}")
    asn = _shared_most(members, "asn")
    if asn:
        shared.append(f"shared hosting {asn}")
    ns_counter = Counter(n for m in members for n in (m.get("ns") or []))
    ns_hit = [n for n, k in ns_counter.items() if k >= 2]
    if ns_hit:
        shared.append(f"shared nameserver {ns_hit[0]}")
    if sum(1 for m in members if m.get("cheap")) >= 2:
        shared.append("cheap-TLD family")
    return bool(window_ok and shared), (reasons + shared)


def _entry(members: list) -> dict:
    dates = sorted(m["reg_date"] for m in members if m.get("reg_date"))
    theme_terms = sorted({t for m in members for t in m.get("themes", [])})
    abuse = next((m.get("abuse_contact") for m in members if m.get("abuse_contact")), None)
    ns_counter = Counter(n for m in members for n in (m.get("ns") or []))
    return {
        "theme": ", ".join(theme_terms) or "brand lookalikes",
        "members": sorted(m["domain"] for m in members), "count": len(members),
        "window": {"first": dates[0] if dates else None, "last": dates[-1] if dates else None},
        "registrars": sorted({m["registrar"] for m in members if m.get("registrar")}),
        "asns": sorted({str(m["asn"]) for m in members if m.get("asn")}),
        "nameservers": sorted({n for n, k in ns_counter.items() if k >= 2}),
        "tlds": sorted({_tld(m["domain"]) for m in members}),
        "abuse": abuse,
    }


def build(candidates: list) -> tuple:
    """Returns (campaigns, related_groups, domain_to_campaign_id)."""
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

    campaigns, related, dom_to_cid = [], [], {}
    camp_state = []  # (campaign dict, registrar set, asn set, ns set, age min, age max)
    cid = 0
    for members in comps.values():
        if len(members) < MIN_CLUSTER:
            continue
        corroborated, reasons = _corroboration(members)
        entry = _entry(members)
        entry["corroboration"] = reasons
        if corroborated:
            cid += 1
            entry["id"] = cid
            for m in members:
                dom_to_cid[m["domain"]] = cid
                m["campaign_join"] = "shared brand theme"
            campaigns.append(entry)
            ages = _ages(members)
            camp_state.append((entry, set(entry["registrars"]), set(entry["asns"]),
                               set(entry["nameservers"]) or {n for m in members
                                                             for n in (m.get("ns") or [])},
                               min(ages) if ages else None, max(ages) if ages else None))
        else:
            related.append(entry)

    # Infrastructure merge: a brand candidate sharing a campaign's registrar, ASN
    # or nameserver inside its window joins it, even without a theme term.
    W = config.HUNT_CAMPAIGN_WINDOW_DAYS
    for rec in candidates:
        d = rec["domain"]
        if d in dom_to_cid:
            continue
        age = rec.get("reg_age_days")
        for entry, regs, asns, nss, amin, amax in camp_state:
            share = None
            if rec.get("registrar") and str(rec["registrar"]) in regs:
                share = f"shared registrar {rec['registrar']}"
            elif rec.get("asn") and str(rec["asn"]) in asns:
                share = f"shared hosting {rec['asn']}"
            elif set(rec.get("ns") or []) & nss:
                share = f"shared nameserver {next(iter(set(rec.get('ns') or []) & nss))}"
            if not share:
                continue
            in_window = (not isinstance(age, int) or amin is None
                         or (amin - W) <= age <= (amax + W))
            if not in_window:
                continue
            dom_to_cid[d] = entry["id"]
            rec["campaign_join"] = share + " (infra match)"
            if d not in entry["members"]:
                entry["members"].append(d)
                entry["members"].sort()
                entry["count"] += 1
            break

    campaigns.sort(key=lambda c: -c["count"])
    related.sort(key=lambda c: -c["count"])
    return campaigns, related, dom_to_cid
