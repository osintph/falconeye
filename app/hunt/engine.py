"""Run one Phishing Hunt and build its one-time payload.

execute(scan) is called by the shared background job runner. For a hunt row the
keyword is stored in scan["domain"] and the optional legitimate domain in
scan["engagement"] (the hunt reuses the generic job row).

Pipeline, per the v3.38.1 and v3.38.2 briefs. Stage one resolves cheap DNS for
every generated candidate (concurrency capped) and resolves random control labels
per TLD to detect registry wildcards (dot.ph answers every .ph label with one
address). Candidates matching the wildcard control are not registered and are
dropped. Stage two spends the fetch budget only on candidates that actually
resolve, keyword hits first. Non-resolving and wildcard candidates never become
rows. The counts are reported honestly and stay consistent (fetched never exceeds
resolved). No em dashes in this module.
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
from app.hunt import wildcard
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


async def execute(scan: dict) -> dict:
    keyword = (scan.get("domain") or "").strip().lower()
    legit = (scan.get("engagement") or "").strip().lower()

    disc = await sources.discover(keyword, legit)
    cands = disc["candidates"]
    by_domain = {c["domain"]: c for c in cands}

    async with httpx.AsyncClient(follow_redirects=True) as client:
        legit_sig = await candidate_mod.legit_signature(client, legit)

        # Stage one: cheap DNS for every candidate, concurrency capped.
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

        # Wildcard control: resolve random control labels per TLD present, so a
        # candidate whose answer equals the registry catch-all is dropped.
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
            return wildcard.is_control_answer(r["ips"], r["cname"],
                                              controls.get(wildcard.suffix_of(dom)))

        wildcard_hits = {c["domain"] for c in cands if res_map[c["domain"]]["resolves"]
                         and _is_wildcard(c["domain"])}

        # Worth fetching: resolves for real (not a wildcard answer). Non-resolving
        # and wildcard candidates are never rows. Keyword hits lead the order.
        worth = [c for c in cands
                 if res_map[c["domain"]]["resolves"] and c["domain"] not in wildcard_hits]
        resolved_count = len(worth)
        wildcard_count = len(wildcard_hits)
        not_registered = len(cands) - resolved_count - wildcard_count

        to_fetch = worth[:config.HUNT_MAX_FETCHES]
        not_fetched = resolved_count - len(to_fetch)

        fsem = asyncio.Semaphore(8)

        async def _probe(c):
            async with fsem:
                dom = c["domain"]
                try:
                    r = await asyncio.wait_for(
                        candidate_mod.probe(client, dom, keyword, legit, legit_sig,
                                            dns_data=res_map[dom]["dns"]),
                        timeout=config.HUNT_CANDIDATE_TIMEOUT + 6)
                except Exception as exc:  # noqa: BLE001 - one candidate must not sink the run
                    log.info("hunt candidate gave up %s: %s", tag(dom), type(exc).__name__)
                    r = {"domain": dom, "resolves": True, "fetched": False,
                         "has_mx": res_map[dom]["has_mx"], "evidence": ["probe failed"]}
                return r

        probed = await asyncio.gather(*[_probe(c) for c in to_fetch])

    scored = [score_mod.score_candidate(c, keyword, legit) for c in probed]

    counts = {v: 0 for v in ("likely phishing", "suspicious", "parked", "unknown", "unrelated")}
    rows = []
    for c in scored:
        counts[c["verdict"]] = counts.get(c["verdict"], 0) + 1
        meta = by_domain.get(c["domain"], {})
        rows.append({
            "domain": c["domain"], "verdict": c["verdict"], "score": c.get("score", 0),
            "registered": c.get("registered"), "reg_note": c.get("reg_note"),
            "registrar": c.get("registrar"), "age_days": c.get("reg_age_days"),
            "asn": c.get("asn"),
            "source": ", ".join(meta.get("origins") or []) or "dnstwist",
            "keyword_hit": bool(meta.get("keyword_hit")),
            "evidence": c.get("evidence") or [], "gsb_url": _GSB + f"http://{c['domain']}/",
        })
    rows.sort(key=lambda r: (0 if r["keyword_hit"] else 1, -r["score"]))

    # "considered" is the capped set actually processed, so considered ==
    # resolved + wildcard + not_registered. "discovered" is the raw count before
    # the HUNT_MAX_CANDIDATES cap, reported separately so the figures add up.
    pipeline = {"discovered": disc.get("generated_count", len(cands)),
                "considered": len(cands), "resolved": resolved_count,
                "fetched": len(to_fetch), "not_fetched": not_fetched,
                "wildcard": wildcard_count, "not_registered": not_registered,
                "keyword_hits": disc.get("keyword_hit_count", 0)}

    methodology = (
        "Discovery: certificate transparency keyword search (crt.sh, retried with "
        "backoff and serialised across concurrent hunts; routable through a proxy "
        "when its own IP is throttled), permutations of the legitimate domain "
        "(dnstwist: homoglyph, IDN and punycode, bitsquatting, TLD swap to open "
        "registrable TLDs, hyphenation, phishing-word combos), urlscan.io keyword "
        "search, and an optional newly-registered-domain feed. Restricted "
        "namespaces an attacker cannot register (.gov.ph and the like) and the "
        "legitimate domain and its subdomains are excluded. Every candidate is DNS "
        "resolved, and random control labels per TLD detect registry wildcards (a "
        "candidate matching the wildcard answer is not a real registration and is "
        "dropped). The fetch budget is spent only on candidates that resolve, "
        "keyword hits first. Per fetched candidate: RDAP and whois registration, "
        "hosting ASN, cert freshness, a URLhaus known-bad check, and one homepage "
        "GET through the SSRF-safe fetcher plus a favicon fetch; parking and "
        "marketplace landing pages are classified and their payment-logo markers "
        "ignored. No port scans, no crawling. Caps this run: "
        f"{config.HUNT_MAX_CANDIDATES} candidates, {config.HUNT_MAX_FETCHES} fetched.")

    sline = (f"{pipeline['discovered']} candidates discovered, {pipeline['considered']} considered "
             f"after the cap: {pipeline['resolved']} registered and resolving, "
             f"{pipeline['wildcard']} registry-wildcard answers dropped, "
             f"{pipeline['not_registered']} not registered. {pipeline['fetched']} fetched and "
             f"assessed, {pipeline['not_fetched']} not fetched (fetch cap). "
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
