"""Campaign clustering for the Phishing Domain Hunt.

A theme term groups candidates, but a group is a CAMPAIGN (and only then boosts
its members to Likely Phishing) only when it is corroborated: its registrations
fall inside a window (default 60 days) AND it shares a DISTINCTIVE attribute. An
attribute that millions of unrelated domains share is not distinctive: a CDN or
large-cloud hosting ASN, a registrar default or parking nameserver, and a very
large registrar on its own do not corroborate. A very large registrar counts only
together with a second distinctive attribute. Once a campaign exists, a brand
candidate that shares a DISTINCTIVE attribute (a non-generic nameserver, a
non-cloud ASN, or a small registrar) inside the window is merged in; a domain that
would only share generic infrastructure is left out and scored on its own.

The campaign carries per-domain registrar data from RDAP, not a single inferred
value, plus the shared nameservers, ASN, window and the registrar abuse contact.
No em dashes in this module.
"""
from __future__ import annotations

from collections import Counter

from app import config
from app.scanner.scope import registrable

MIN_CLUSTER = 3

# CDN, large-cloud and large consumer-hosting ASNs: millions of unrelated domains
# sit on these, so sharing one is not distinctive. Numeric, matched after stripping
# any AS prefix. Maintained list.
_CDN_ASNS = {
    "13335",   # Cloudflare
    "16509", "14618",   # AWS
    "15169", "396982",  # Google
    "8075",    # Microsoft
    "20940", "16625", "35994", "12222",  # Akamai
    "54113",   # Fastly
    "132203", "45090", "133478", "137876",  # Tencent
    "45102", "37963", "24429", "134963",    # Alibaba
    "14061",   # DigitalOcean
    "20473",   # Vultr / Choopa
    "63949",   # Linode / Akamai
    "24940",   # Hetzner
    "16276",   # OVH
    "9009",    # M247
    "19551",   # Incapsula
    # Large consumer hosting (same class as the above for our purposes).
    "22612", "394695",          # Namecheap (and Spaceship)
    "47583",                    # Hostinger
    "26496", "398101", "30148", # GoDaddy / Secureserver
    "46606", "19871", "29873", "25847",  # Newfold (Bluehost, HostGator, Network Solutions)
    "8560",                     # IONOS
}

# Tokens that mark a registrar default, parking, CDN or large consumer-hosting
# nameserver (not operator specific). Matched as a substring of the nameserver
# host. Maintained list.
_GENERIC_NS_TOKENS = (
    "domainnamens", "domaincontrol", "registrar-servers", "cloudflare", "awsdns",
    "azure-dns", "googledomains", "google.com", "dns-parking", "sedoparking",
    "parkingcrew", "bodis", "dan.com", "hugedomains", "cashparking", "above.com",
    "dnsowl", "nsone", "digitalocean", "hostinger", "wixdns", "squarespacedns",
    "shopifydns", "name-services", "hichina", "dnspod", "ztomy", "parklogic",
    # Large consumer hosting default nameservers.
    "namecheaphosting", "spaceship", "secureserver", "bluehost", "hostgator",
    "websitewelcome", "siteground", "sgvps", "ionos", "ui-dns", "dreamhost",
    "newfold", "name.com", "web.com", "register.com",
)

# Very large registrars and consumer hosts acting as registrar: a shared registrar
# here needs a second distinctive attribute to corroborate. Substring match.
_LARGE_REGISTRARS = (
    "namesilo", "namemart", "godaddy", "namecheap", "spaceship", "public domain registry",
    "pdr ltd", "tucows", "network solutions", "dynadot", "porkbun", "hostinger",
    "key-systems", "google", "cloudflare", "gname", "alibaba", "tencent", "ename",
    "dnspod", "namebright", "realtime register", "openprovider", "west263",
    "squarespace", "wild west", "enom", "hosting concepts", "newfold", "web.com",
    "ionos", "register.com", "bluehost", "hostgator", "siteground",
)


def _asn_num(asn) -> str:
    return "".join(ch for ch in str(asn or "") if ch.isdigit())


def _is_cdn_asn(asn) -> bool:
    return _asn_num(asn) in _CDN_ASNS


def _ns_base(ns: str) -> str:
    reg = registrable((ns or "").lower()) or (ns or "").lower()
    return reg


def _is_generic_ns(ns: str) -> bool:
    low = (ns or "").lower()
    return any(tok in low for tok in _GENERIC_NS_TOKENS)


def _is_large_registrar(name) -> bool:
    low = str(name or "").lower()
    # A platform placeholder (platform: pages.dev) is shared hosting, never a
    # distinctive registrar: treat it as non-distinctive like the large registrars.
    if low.startswith("platform:"):
        return True
    return any(tok in low for tok in _LARGE_REGISTRARS)


def _tld(domain: str) -> str:
    reg = registrable(domain, private=True) or domain
    return reg.split(".", 1)[1] if "." in reg else ""


def _ages(members: list) -> list:
    return [m["reg_age_days"] for m in members
            if isinstance(m.get("reg_age_days"), int) and m["reg_age_days"] >= 0]


def _distinctive_ns(members: list):
    c = Counter(_ns_base(n) for m in members for n in (m.get("ns") or [])
                if n and not _is_generic_ns(n))
    hit = [n for n, k in c.items() if k >= 2]
    return hit[0] if hit else None


def _distinctive_asn(members: list):
    c = Counter(_asn_num(m.get("asn")) for m in members
                if m.get("asn") and not _is_cdn_asn(m.get("asn")))
    hit = [a for a, k in c.items() if k >= 2 and a]
    return hit[0] if hit else None


def _distinctive_registrar(members: list):
    c = Counter(str(m.get("registrar")) for m in members
                if m.get("registrar") and not _is_large_registrar(m.get("registrar")))
    hit = [r for r, k in c.items() if k >= 2]
    return hit[0] if hit else None


def _large_registrar_shared(members: list):
    c = Counter(str(m.get("registrar")) for m in members
                if m.get("registrar") and _is_large_registrar(m.get("registrar")))
    return c.most_common(1)[0][0] if c and c.most_common(1)[0][1] >= 2 else None


def _burst(ages: list) -> tuple:
    """Find the densest registration burst. Clustering on a lure family builds a
    larger, realistic campaign set whose full span can exceed the window because
    operators register lookalikes over time, so the gate asks whether the MAJORITY
    of dated members fall inside one window, not whether every one does. Returns
    (ok, count_in_burst, span_of_burst, lo_age, hi_age) where lo/hi bound the
    densest window (ages inside it are burst members, dated ages outside are
    outliers)."""
    a = sorted(ages)
    if len(a) < 2:
        return (False, len(a), 0, None, None)
    w = config.HUNT_CAMPAIGN_WINDOW_DAYS
    best_n, best_span, lo, hi = 1, 0, a[0], a[0]
    for i in range(len(a)):
        j = i
        while j < len(a) and (a[j] - a[i]) <= w:
            j += 1
        if (j - i) > best_n:
            best_n, best_span, lo, hi = j - i, a[j - 1] - a[i], a[i], a[j - 1]
    ok = best_n >= max(2, (len(a) + 1) // 2)
    return (ok, best_n, best_span, lo, hi)


def _distinctive_overlap(m: dict, burst: list):
    """Why outlier *m* shares a distinctive attribute with some burst member, or
    None. Generic infrastructure (a registrar default nameserver, a CDN or large
    cloud ASN) does not count; a large registrar counts only paired with a shared
    non-generic nameserver."""
    m_ns = {_ns_base(n) for n in (m.get("ns") or []) if n and not _is_generic_ns(n)}
    m_reg = str(m["registrar"]) if m.get("registrar") else None
    m_asn = _asn_num(m["asn"]) if (m.get("asn") and not _is_cdn_asn(m["asn"])) else None
    m_ip = m.get("ip")
    m_fav = m.get("favicon_hash")
    m_title = (m.get("title") or "").strip().lower()
    for b in burst:
        b_ns = {_ns_base(n) for n in (b.get("ns") or []) if n and not _is_generic_ns(n)}
        if m_reg and str(b.get("registrar")) == m_reg and (m_ns & b_ns):
            return f"same registrar and nameserver as the burst ({m_reg})"
        if m_asn and b.get("asn") and not _is_cdn_asn(b["asn"]) and _asn_num(b["asn"]) == m_asn:
            return f"same non-cloud ASN as the burst ({m_asn})"
        if m_ip and b.get("ip") and b["ip"] == m_ip:
            return f"same hosting IP as the burst ({m_ip})"
        if m_fav and b.get("favicon_hash") and b["favicon_hash"] == m_fav:
            return "same favicon as the burst"
        if m_title and len(m_title) >= 6 and (b.get("title") or "").strip().lower() == m_title:
            return "same page content as the burst"
    return None


def _corroboration(members: list) -> tuple:
    ages = _ages(members)
    window_ok, burst_n, burst_span, _lo, _hi = _burst(ages)
    reasons = []
    if window_ok:
        reasons.append(f"a burst of {burst_n} registered within {burst_span} days")
    distinctive = []
    ns = _distinctive_ns(members)
    if ns:
        distinctive.append(f"shared nameserver {ns}")
    asn = _distinctive_asn(members)
    if asn:
        distinctive.append(f"shared non-cloud ASN {asn}")
    small_reg = _distinctive_registrar(members)
    if small_reg:
        distinctive.append(f"shared registrar {small_reg}")
    if sum(1 for m in members if m.get("cheap")) >= 2:
        distinctive.append("cheap-TLD family")
    # A very large registrar counts only alongside a distinctive attribute.
    big = _large_registrar_shared(members)
    if big and distinctive:
        reasons.append(f"large registrar {big} (with a distinctive attribute)")
    corroborated = bool(window_ok and distinctive)
    return corroborated, (reasons + distinctive)


def _member_rows(members: list) -> list:
    rows = []
    for m in sorted(members, key=lambda x: x["domain"]):
        ns = sorted({_ns_base(n) for n in (m.get("ns") or []) if n})
        rows.append({"domain": m["domain"], "registrar": m.get("registrar") or "unknown",
                     "reg_date": m.get("reg_date"), "ns": ", ".join(ns),
                     "abuse": m.get("abuse_contact")})
    return rows


def _registrar_groups(member_rows: list) -> list:
    """Members grouped by registrar with that registrar's abuse email from RDAP, so
    one abuse report per registrar can list all of its domains in the campaign."""
    groups: dict = {}
    for r in member_rows:
        g = groups.setdefault(r.get("registrar") or "unknown",
                              {"registrar": r.get("registrar") or "unknown",
                               "abuse": None, "domains": []})
        g["domains"].append(r["domain"])
        if not g["abuse"] and r.get("abuse"):
            g["abuse"] = r["abuse"]
    out = []
    for g in groups.values():
        g["domains"] = sorted(g["domains"])
        g["count"] = len(g["domains"])
        out.append(g)
    out.sort(key=lambda g: (-g["count"], g["registrar"]))
    return out


def _entry(members: list) -> dict:
    dates = sorted(m["reg_date"] for m in members if m.get("reg_date"))
    theme_terms = sorted({t for m in members for t in m.get("themes", [])})
    abuse = next((m.get("abuse_contact") for m in members if m.get("abuse_contact")), None)
    return {
        "theme": ", ".join(theme_terms) or "brand lookalikes",
        "members": sorted(m["domain"] for m in members), "count": len(members),
        "member_rows": _member_rows(members),
        "window": {"first": dates[0] if dates else None, "last": dates[-1] if dates else None},
        "registrars": sorted({str(m["registrar"]) for m in members if m.get("registrar")}),
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

    # Group on the lure FAMILY (traffic fines, benefits, ...), not the single term,
    # so terms that advance the same lure (ncap and huli, member and miyembro)
    # cluster together. Fall back to the raw term when no family is attached.
    by_key: dict = {}
    for c in themed:
        for k in (c.get("families") or c.get("themes") or []):
            by_key.setdefault(k, []).append(c["domain"])
    for members in by_key.values():
        for d in members[1:]:
            union(members[0], d)

    comps: dict = {}
    for c in themed:
        comps.setdefault(find(c["domain"]), []).append(c)

    campaigns, related, dom_to_cid = [], [], {}
    camp_state = []
    cid = 0
    for members in comps.values():
        if len(members) < MIN_CLUSTER:
            continue
        ages = _ages(members)
        corroborated, reasons = _corroboration(members)
        if not corroborated:
            entry = _entry(members)
            entry["corroboration"] = reasons
            related.append(entry)
            continue
        # Split the corroborated component into the burst, the outliers that still
        # share a distinctive attribute with it (they join), and the outliers that
        # do not (listed under the campaign as "related, outside burst", scored on
        # their own, not boosted).
        _ok, _n, _sp, lo, hi = _burst(ages)
        burst, outliers = [], []
        for m in members:
            a = m.get("reg_age_days")
            if isinstance(a, int) and lo is not None and (a < lo or a > hi):
                outliers.append(m)
            else:
                burst.append(m)  # in-burst, or undated (date unknown)
        joined, outside = [], []
        for m in outliers:
            why = _distinctive_overlap(m, burst)
            if why:
                m["outlier_join"] = why
                joined.append(m)
            else:
                outside.append(m)
        campaign_members = burst + joined
        if len(campaign_members) < MIN_CLUSTER:
            # Too little left to call a campaign once outliers are removed.
            entry = _entry(members)
            entry["corroboration"] = reasons
            related.append(entry)
            continue
        cid += 1
        entry = _entry(campaign_members)
        entry["corroboration"] = reasons
        entry["id"] = cid
        entry["outliers_related"] = [
            {"domain": m["domain"], "reg_date": m.get("reg_date"),
             "registrar": m.get("registrar") or "unknown"} for m in sorted(
                 outside, key=lambda x: x["domain"])]
        for m in campaign_members:
            dom_to_cid[m["domain"]] = cid
            m.setdefault("campaign_join", m.get("outlier_join") or "shared brand theme")
        campaigns.append(entry)
        camp_state.append((
            entry,
            {_ns_base(n) for m in campaign_members for n in (m.get("ns") or [])
             if n and not _is_generic_ns(n)},
            {_asn_num(m.get("asn")) for m in campaign_members
             if m.get("asn") and not _is_cdn_asn(m.get("asn"))},
            {str(m["registrar"]) for m in campaign_members
             if m.get("registrar") and not _is_large_registrar(m.get("registrar"))},
            lo, hi))

    # Infrastructure merge, DISTINCTIVE attributes only.
    W = config.HUNT_CAMPAIGN_WINDOW_DAYS
    for rec in candidates:
        d = rec["domain"]
        if d in dom_to_cid:
            continue
        age = rec.get("reg_age_days")
        for entry, nss, asns, regs, amin, amax in camp_state:
            share = None
            rec_ns = {_ns_base(n) for n in (rec.get("ns") or []) if n and not _is_generic_ns(n)}
            if rec_ns & nss:
                share = f"shared nameserver {next(iter(rec_ns & nss))}"
            elif rec.get("asn") and not _is_cdn_asn(rec["asn"]) and _asn_num(rec["asn"]) in asns:
                share = f"shared non-cloud ASN {_asn_num(rec['asn'])}"
            elif (rec.get("registrar") and not _is_large_registrar(rec["registrar"])
                  and str(rec["registrar"]) in regs):
                share = f"shared registrar {rec['registrar']}"
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
                entry["member_rows"].append({
                    "domain": d, "registrar": rec.get("registrar") or "unknown",
                    "reg_date": rec.get("reg_date"),
                    "ns": ", ".join(sorted({_ns_base(n) for n in (rec.get("ns") or []) if n})),
                    "abuse": rec.get("abuse_contact")})
            break

    # Per-registrar abuse grouping (built after merges so it covers every member).
    for entry in campaigns + related:
        entry["member_rows"].sort(key=lambda r: r["domain"])
        entry["registrar_groups"] = _registrar_groups(entry["member_rows"])

    campaigns.sort(key=lambda c: -c["count"])
    related.sort(key=lambda c: -c["count"])
    return campaigns, related, dom_to_cid
