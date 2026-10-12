"""Run one Phishing Hunt and build its one-time payload.

execute(scan) is called by the shared background job runner. For a hunt row the
keyword is in scan["domain"] and the optional legitimate domain in
scan["engagement"].

Pipeline. Discovery (sources.discover) collapses hits to registrable domains,
attaches urlscan evidence and brand theme terms, and drops irrelevant keyword
matches. Stage one resolves cheap DNS for every candidate and drops registry
wildcards. The fetch budget probes the resolving candidates; a domain urlscan saw
recently that no longer resolves is kept as "possibly taken down" with its urlscan
evidence. Candidates sharing a brand theme term are clustered into campaigns, a
cluster of three or more is reported at the top and boosts its members, and
scoring recognises themes, campaigns, urlscan verdicts and cheap TLDs. No em
dashes in this module.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx

from app import config
from app.hunt import candidate as candidate_mod
from app.hunt import cluster as cluster_mod
from app.hunt import rdap as rdap_mod
from app.hunt import score as score_mod
from app.hunt import sources
from app.hunt import themes as themes_mod
from app.hunt import wildcard
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.hunt.engine")

_GSB = "https://safebrowsing.google.com/safebrowsing/report_phish/?url="
_ATTRIBUTION = [
    "Keyword search: urlscan.io (primary).",
    "Permutations: dnstwist (Apache-2.0).",
    "Certificate transparency keyword search: crt.sh (best effort).",
    "Known-bad enrichment: URLhaus (abuse.ch).",
    "Registration and routing: RDAP, system whois and RIPEstat (RIPE NCC).",
]


def _reg_date(registered) -> str | None:
    """The registration date from RDAP or whois (the real date), or None. It is
    NEVER derived from an age; the age is computed from this date, not the reverse,
    and it is never urlscan first-seen."""
    return str(registered)[:10] if registered else None


def _age_from(date_str) -> int | None:
    try:
        dt = datetime.fromisoformat(str(date_str)[:10])
        return int((datetime.now(timezone.utc).date() - dt.date()).days)
    except Exception:  # noqa: BLE001
        return None


async def _backfill_registrars(records: list) -> None:
    """For themed candidates the concurrent probe left without a registrar, look
    RDAP up again on its own (no competing CT/HTTP/ASN budget, cache-aware) so a
    campaign member is "unknown" only when the registry truly publishes none."""
    targets = [r for r in records if r.get("themes") and not r.get("registrar")]
    if not targets:
        return
    async with httpx.AsyncClient(follow_redirects=True) as client:
        sem = asyncio.Semaphore(4)

        async def one(r):
            async with sem:
                try:
                    parsed = await rdap_mod.lookup(client, r["domain"])
                except Exception:  # noqa: BLE001
                    parsed = None
                if not parsed:
                    return
                if not r.get("registrar"):
                    r["registrar"] = (parsed.get("registrar") or {}).get("name")
                if not r.get("abuse_contact"):
                    r["abuse_contact"] = (parsed.get("abuse_contact") or {}).get("email")
                reg = (parsed.get("events") or {}).get("registration")
                if reg and not r.get("registered"):
                    r["registered"] = reg
                    r["reg_date"] = _reg_date(reg)
                    if r["reg_date"]:
                        r["reg_age_days"] = _age_from(r["reg_date"])

        await asyncio.gather(*[one(r) for r in targets])


async def execute(scan: dict) -> dict:
    keyword = (scan.get("domain") or "").strip().lower()
    legit = (scan.get("engagement") or "").strip().lower()
    op = bool(scan.get("operator"))
    engagement = (scan.get("grant_id") or "").strip() if op else ""
    max_cand = config.HUNT_OPERATOR_MAX_CANDIDATES if op else config.HUNT_MAX_CANDIDATES
    max_fetch = config.HUNT_OPERATOR_MAX_FETCHES if op else config.HUNT_MAX_FETCHES

    disc = await sources.discover(keyword, legit, max_candidates=max_cand)
    cands = disc["candidates"]
    by_domain = {c["domain"]: c for c in cands}

    async with httpx.AsyncClient(follow_redirects=True) as client:
        legit_sig = await candidate_mod.legit_signature(client, legit)
        rsem = asyncio.Semaphore(config.HUNT_RESOLVE_CONCURRENCY)

        async def _resolve(dom):
            async with rsem:
                try:
                    return await asyncio.wait_for(candidate_mod.resolve(dom), timeout=8)
                except Exception:  # noqa: BLE001
                    return {"domain": dom, "dns": {"A": [], "AAAA": [], "MX": [], "NS": [],
                            "CNAME": []}, "ips": [], "cname": "", "resolves": False,
                            "has_mx": False, "has_ns": False}

        resolved = await asyncio.gather(*[_resolve(c["domain"]) for c in cands])
        res_map = {r["domain"]: r for r in resolved}

        # Wildcard control per TLD.
        suffixes = sorted({wildcard.suffix_of(c["domain"]) for c in cands})

        async def _control(sfx):
            async with rsem:
                answers = []
                for _ in range(config.HUNT_WILDCARD_CONTROLS):
                    try:
                        answers.append(await asyncio.wait_for(
                            candidate_mod.resolve(f"{wildcard.random_label()}.{sfx}"), timeout=8))
                    except Exception:  # noqa: BLE001
                        answers.append({"ips": [], "cname": ""})
                return sfx, wildcard.signature_from(answers)

        controls = dict(await asyncio.gather(*[_control(s) for s in suffixes]))

        def _is_wildcard(dom):
            r = res_map[dom]
            return r["resolves"] and wildcard.is_control_answer(
                r["ips"], r["cname"], controls.get(wildcard.suffix_of(dom)))

        wildcard_hits = {c["domain"] for c in cands if _is_wildcard(c["domain"])}

        resolving = [c for c in cands
                     if res_map[c["domain"]]["resolves"] and c["domain"] not in wildcard_hits]
        # urlscan saw these recently but they no longer resolve: possibly taken down.
        taken_down = [c for c in cands
                      if c["domain"] not in wildcard_hits
                      and not res_map[c["domain"]]["resolves"] and c.get("urlscan")]
        wildcard_count = len(wildcard_hits)
        not_registered = len(cands) - len(resolving) - len(taken_down) - wildcard_count

        # Fetch budget: resolving candidates, themed and keyword hits first.
        resolving.sort(key=lambda c: (0 if c.get("themes") else 1,
                                      0 if c["keyword_hit"] else 1, len(c["domain"])))
        to_fetch = resolving[:max_fetch]
        dns_only = resolving[max_fetch:]
        not_fetched = len(dns_only)

        fsem = asyncio.Semaphore(8)

        async def _probe(c):
            async with fsem:
                dom = c["domain"]
                try:
                    return await asyncio.wait_for(
                        candidate_mod.probe(client, dom, keyword, legit, legit_sig,
                                            dns_data=res_map[dom]["dns"]),
                        timeout=config.HUNT_CANDIDATE_TIMEOUT + 6)
                except Exception as exc:  # noqa: BLE001
                    log.info("hunt candidate gave up %s: %s", tag(dom), type(exc).__name__)
                    return {"domain": dom, "resolves": True, "fetched": False, "evidence": []}

        probed = {p["domain"]: p for p in await asyncio.gather(*[_probe(c) for c in to_fetch])}

    # Assemble unified records (probe data + discovery evidence) for every row.
    records = []
    for c in resolving + taken_down:
        dom = c["domain"]
        p = probed.get(dom, {})
        urls = c.get("urlscan") or {}
        rec = dict(p)
        rec["domain"] = dom
        rec.setdefault("resolves", res_map[dom]["resolves"])
        rec.setdefault("fetched", False)
        rec["urlscan"] = urls
        rec["themes"] = c.get("themes") or []
        rec["families"] = themes_mod.families_of(keyword, rec["themes"])
        rec["observed_hosts"] = c.get("observed") or []
        rec["keyword_hit"] = c.get("keyword_hit")
        rec["origins"] = c.get("origins") or []
        # The shown registration date comes from RDAP or whois (the real date); the
        # age is computed from that date. urlscan first-seen is never the shown
        # date (shown separately, labelled). When there is no registration date,
        # the first CT certificate is the labelled "first live" fallback.
        rec["reg_date"] = _reg_date(rec.get("registered"))
        if rec.get("reg_date"):
            rec["reg_age_days"] = _age_from(rec["reg_date"])
        elif rec.get("reg_age_days") is None and isinstance(rec.get("ct_first_seen_age"), int):
            rec["reg_age_days"] = rec["ct_first_seen_age"]
        elif rec.get("reg_age_days") is None and isinstance(urls.get("age_days"), int):
            rec["reg_age_days"] = urls["age_days"]  # young determination only, no shown date
        if not rec.get("asn") and urls.get("asn"):
            rec["asn"] = urls["asn"]
        rec["ns"] = list((res_map[dom]["dns"] or {}).get("NS") or [])
        rec["cheap"] = themes_mod.cheap_tld(dom)
        records.append(rec)

    # The concurrent probe shares one short budget across DNS, RDAP, CT, ASN and
    # the HTTP fetch, so RDAP for a slow registry can be cut off, leaving a themed
    # candidate with no registrar. Backfill those (serial-ish, cache-aware) before
    # clustering so campaign members are not left "unknown" when the registry does
    # publish one.
    await _backfill_registrars(records)

    # Theme clustering, split into corroborated campaigns (which boost) and
    # uncorroborated related groups (which do not), then score.
    campaigns, related_groups, dom_to_cid = cluster_mod.build(records)
    for rec in records:
        rec["campaign_member"] = rec["domain"] in dom_to_cid
        rec["campaign_id"] = dom_to_cid.get(rec["domain"])

    scored = [score_mod.score_candidate(rec, keyword, legit) for rec in records]

    counts = {v: 0 for v in ("likely phishing", "suspicious", "brand-referencing",
                             "parked", "unknown", "unrelated")}
    rows = []
    noise_dropped = 0
    for c in scored:
        if c.get("drop_noise"):
            noise_dropped += 1
            continue
        counts[c["verdict"]] = counts.get(c["verdict"], 0) + 1
        urls = c.get("urlscan") or {}
        rows.append({
            "domain": c["domain"], "verdict": c["verdict"], "score": c.get("score", 0),
            "registered": c.get("reg_date"), "reg_note": c.get("reg_note"),
            "age_days": c.get("reg_age_days"), "registrar": c.get("registrar"),
            "asn": c.get("asn"), "source": ", ".join(c.get("origins") or []) or "dnstwist",
            "keyword_hit": bool(c.get("keyword_hit")), "themes": c.get("themes") or [],
            "campaign_id": c.get("campaign_id"), "observed": c.get("observed_hosts") or [],
            "ct_first_seen": c.get("ct_first_seen"),
            "urlscan_first_seen": (urls.get("first_seen") or "")[:10],
            "urlscan_title": urls.get("title") or "", "urlscan_labels": urls.get("labels") or [],
            "urlscan_result": urls.get("result_url") or "",
            "evidence": c.get("evidence") or [], "gsb_url": _GSB + f"http://{c['domain']}/",
        })
    rows.sort(key=lambda r: (0 if r["campaign_id"] else 1, -r["score"]))

    pipeline = {"discovered": disc.get("generated_count", len(cands)),
                "considered": len(cands), "resolved": len(resolving),
                "fetched": len(to_fetch), "not_fetched": not_fetched,
                "taken_down": len(taken_down), "wildcard": wildcard_count,
                "not_registered": not_registered,
                "irrelevant": disc.get("irrelevant_count", 0) + noise_dropped,
                "keyword_hits": disc.get("keyword_hit_count", 0)}

    methodology = (
        "Discovery: urlscan.io keyword search (the primary keyword source, with "
        "first-seen, title, classification labels and the public result link kept "
        "as evidence), permutations of the legitimate domain (dnstwist), a best "
        "effort certificate transparency keyword lookup (crt.sh, non-gating), and "
        "an optional newly-registered-domain feed. Hits are collapsed to the "
        "registrable domain. A keyword match whose brand letters are buried in an "
        "unrelated word, with no brand theme term and no urlscan flag, is dropped "
        "as irrelevant. Registry wildcards are detected with random control labels "
        "and dropped. The legitimate domain, its subdomains and restricted "
        "namespaces are excluded. Candidates sharing a brand theme term are "
        "clustered into campaigns; a cluster of three or more is boosted and "
        "reported. Scoring weighs theme terms, campaign membership, urlscan "
        "verdicts, recent registration, cheap abuse-heavy TLDs and page content "
        "imitating the brand. A domain urlscan saw recently that no longer resolves "
        "is kept as possibly taken down. No port scans, no crawling. Caps this run: "
        f"{max_cand} candidates, {max_fetch} fetched.")

    sline = (f"{pipeline['discovered']} discovered, {pipeline['considered']} considered: "
             f"{pipeline['resolved']} registered, {pipeline['taken_down']} possibly taken down, "
             f"{pipeline['wildcard']} registry-wildcard and {pipeline['irrelevant']} irrelevant "
             f"keyword matches dropped, {pipeline['not_registered']} not registered. "
             f"{len(campaigns)} corroborated campaign(s), {len(related_groups)} related "
             f"brand-themed group(s). {pipeline['keyword_hits']} urlscan or certificate "
             f"keyword hits.")
    if disc["incomplete"]:
        sline = "INCOMPLETE run. " + sline + " The primary keyword source did not answer."

    return {
        "kind": "hunt", "title": keyword, "legit_domain": legit, "generated_ts": time.time(),
        "scan_id": scan["scan_id"], "state": "done",
        "mode": "Operator" if op else "Public", "engagement": engagement,
        "operator": False, "incomplete": disc["incomplete"], "nrd_off": disc["nrd_off"],
        "source_status": disc["source_status"], "severity_counts": counts,
        "pipeline": pipeline, "campaigns": campaigns, "related_groups": related_groups,
        "summary_line": sline, "candidates": rows, "hosts_probed": len(to_fetch),
        "methodology": methodology, "attribution": _ATTRIBUTION,
    }
