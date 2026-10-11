"""Run one Phishing Hunt and build its one-time payload.

execute(scan) is called by the shared background job runner. For a hunt row the
keyword is stored in scan["domain"] and the optional legitimate domain in
scan["engagement"] (the hunt reuses the generic job row).

Two stages, per the v3.38.1 brief. Stage one resolves cheap DNS for every
generated candidate (concurrency capped). Stage two spends the fetch budget only
on candidates that resolve or were observed in certificate transparency or
urlscan, keyword hits first. Non-resolving permutations are counted as "not
registered", not shown as rows. The counts (generated, resolved, fetched, not
fetched, not registered) are reported honestly. No em dashes in this module.
"""
from __future__ import annotations

import asyncio
import logging
import time

import httpx

from app import config
from app.hunt import candidate as candidate_mod
from app.hunt import score as score_mod
from app.hunt import sources
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.hunt.engine")

_GSB = "https://safebrowsing.google.com/safebrowsing/report_phish/?url="
_ATTRIBUTION = [
    "Certificate transparency keyword search: crt.sh.",
    "Permutations: dnstwist (Apache-2.0).",
    "Keyword search: urlscan.io.",
    "Known-bad enrichment: URLhaus (abuse.ch).",
    "Registration and routing: RDAP, system whois and RIPEstat (RIPE NCC).",
]


def _registered_or_observed(dom: str, res: dict, keyword_hit: bool) -> bool:
    """A candidate worth the fetch budget: it resolves, has name or mail servers,
    or was actually observed in CT or urlscan (so it exists even if DNS is quiet)."""
    if keyword_hit:
        return True
    return bool(res.get("resolves") or res.get("has_ns") or res.get("has_mx"))


async def execute(scan: dict) -> dict:
    keyword = (scan.get("domain") or "").strip().lower()
    legit = (scan.get("engagement") or "").strip().lower()

    disc = await sources.discover(keyword, legit)
    cands = disc["candidates"]
    by_domain = {c["domain"]: c for c in cands}

    async with httpx.AsyncClient(follow_redirects=True) as client:
        legit_fav = await candidate_mod.legit_favicon_hash(client, legit)

        # Stage one: cheap DNS for every candidate, concurrency capped.
        rsem = asyncio.Semaphore(config.HUNT_RESOLVE_CONCURRENCY)

        async def _resolve(dom):
            async with rsem:
                try:
                    return await asyncio.wait_for(candidate_mod.resolve(dom), timeout=8)
                except Exception:  # noqa: BLE001
                    return {"domain": dom, "dns": {"A": [], "AAAA": [], "MX": [], "NS": []},
                            "resolves": False, "has_mx": False, "has_ns": False}

        resolved = await asyncio.gather(*[_resolve(c["domain"]) for c in cands])
        res_map = {r["domain"]: r for r in resolved}

        resolved_count = sum(1 for r in resolved if r["resolves"])
        worth = [c for c in cands
                 if _registered_or_observed(c["domain"], res_map[c["domain"]], c["keyword_hit"])]
        not_registered = len(cands) - len(worth)

        # Keyword hits are always shown; the fetch budget is spent in priority
        # order (discover already ordered keyword hits first).
        to_fetch = worth[:config.HUNT_MAX_FETCHES]
        fetch_set = {c["domain"] for c in to_fetch}
        # Keyword hits beyond the fetch cap still get a DNS-only row.
        extra_rows = [c for c in worth[config.HUNT_MAX_FETCHES:] if c["keyword_hit"]]
        not_fetched = len(worth) - len(to_fetch)

        # Stage two: full probe only for the fetch targets, reusing stage-one DNS.
        fsem = asyncio.Semaphore(8)

        async def _probe(c):
            async with fsem:
                dom = c["domain"]
                try:
                    r = await asyncio.wait_for(
                        candidate_mod.probe(client, dom, keyword, legit, legit_fav,
                                            dns_data=res_map[dom]["dns"]),
                        timeout=config.HUNT_CANDIDATE_TIMEOUT + 6)
                except Exception as exc:  # noqa: BLE001 - one candidate must not sink the run
                    log.info("hunt candidate gave up %s: %s", tag(dom), type(exc).__name__)
                    r = {"domain": dom, "resolves": res_map[dom]["resolves"],
                         "has_mx": res_map[dom]["has_mx"], "has_ns": res_map[dom]["has_ns"],
                         "fetched": False, "evidence": ["probe failed"]}
                return r

        probed = await asyncio.gather(*[_probe(c) for c in to_fetch])

    # DNS-only records for keyword hits beyond the fetch cap.
    for c in extra_rows:
        r = res_map[c["domain"]]
        probed.append({"domain": c["domain"], "resolves": r["resolves"], "has_mx": r["has_mx"],
                       "has_ns": r["has_ns"], "fetched": False,
                       "evidence": ["not fetched: fetch cap reached"]})

    scored = [score_mod.score_candidate(c, keyword, legit) for c in probed]

    counts = {v: 0 for v in ("likely phishing", "suspicious", "parked", "unknown", "unrelated")}
    rows = []
    for c in scored:
        counts[c["verdict"]] = counts.get(c["verdict"], 0) + 1
        meta = by_domain.get(c["domain"], {})
        rows.append({
            "domain": c["domain"], "verdict": c["verdict"], "score": c.get("score", 0),
            "registered": c.get("registered"), "registrar": c.get("registrar"),
            "age_days": c.get("reg_age_days"), "asn": c.get("asn"),
            "source": ", ".join(meta.get("origins") or []) or "dnstwist",
            "keyword_hit": bool(meta.get("keyword_hit")),
            "evidence": c.get("evidence") or [], "gsb_url": _GSB + f"http://{c['domain']}/",
        })
    # Keyword hits first, then by score.
    rows.sort(key=lambda r: (0 if r["keyword_hit"] else 1, -r["score"]))

    pipeline = {"generated": disc.get("generated_count", len(cands)),
                "resolved": resolved_count, "fetched": len(to_fetch),
                "not_fetched": not_fetched, "not_registered": not_registered,
                "keyword_hits": disc.get("keyword_hit_count", 0)}

    methodology = (
        "Discovery: certificate transparency keyword search (crt.sh, retried with "
        "backoff and serialised across concurrent hunts), permutations of the "
        "legitimate domain (dnstwist: homoglyph, IDN and punycode, bitsquatting, "
        "TLD swap to open registrable TLDs, hyphenation, phishing-word combos), "
        "urlscan.io keyword search, and an optional newly-registered-domain feed. "
        "Restricted namespaces an attacker cannot register (.gov.ph and the like) "
        "and the legitimate domain and its subdomains are excluded. Every generated "
        "candidate is DNS resolved first; the fetch budget is then spent only on "
        "candidates that resolve or were observed, keyword hits first. Per fetched "
        "candidate: RDAP and whois registration, hosting ASN, cert freshness, and "
        "one homepage GET through the SSRF-safe fetcher plus a favicon fetch. No "
        "port scans, no crawling. Caps this run: "
        f"{config.HUNT_MAX_CANDIDATES} candidates, {config.HUNT_MAX_FETCHES} fetched.")

    sline = (f"{pipeline['generated']} candidates generated, {pipeline['resolved']} resolve, "
             f"{pipeline['fetched']} fetched and assessed, {pipeline['not_fetched']} not fetched "
             f"(fetch cap), {pipeline['not_registered']} not registered. "
             f"{pipeline['keyword_hits']} certificate or urlscan keyword hits.")
    if disc["incomplete"]:
        sline = "INCOMPLETE run. " + sline + " A discovery source did not answer."

    return {
        "kind": "hunt", "title": keyword, "legit_domain": legit, "generated_ts": time.time(),
        "scan_id": scan["scan_id"], "state": "done", "mode": "Public", "engagement": "",
        "operator": False, "incomplete": disc["incomplete"], "nrd_off": disc["nrd_off"],
        "source_status": disc["source_status"], "severity_counts": counts,
        "pipeline": pipeline, "summary_line": sline, "candidates": rows,
        "hosts_probed": len(to_fetch), "methodology": methodology, "attribution": _ATTRIBUTION,
    }
