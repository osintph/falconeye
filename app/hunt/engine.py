"""Run one Phishing Hunt and build its one-time payload.

execute(scan) is called by the shared background job runner. For a hunt row the
keyword is stored in scan["domain"] and the optional legitimate domain in
scan["engagement"] (the hunt reuses the generic job row). No em dashes here.
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
    "Registration and routing: RDAP and RIPEstat (RIPE NCC).",
]


async def execute(scan: dict) -> dict:
    keyword = (scan.get("domain") or "").strip().lower()
    legit = (scan.get("engagement") or "").strip().lower()

    disc = await sources.discover(keyword, legit)
    candidates = disc["candidates"]
    to_fetch = candidates[:config.HUNT_MAX_FETCHES]

    probed = []
    async with httpx.AsyncClient(follow_redirects=True) as client:
        legit_fav = await candidate_mod.legit_favicon_hash(client, legit)
        sem = asyncio.Semaphore(8)

        async def _one(dom):
            async with sem:
                try:
                    return await asyncio.wait_for(
                        candidate_mod.probe(client, dom, keyword, legit, legit_fav),
                        timeout=config.HUNT_CANDIDATE_TIMEOUT + 6)
                except Exception as exc:  # noqa: BLE001 - one candidate must not sink the run
                    log.info("hunt candidate gave up %s: %s", tag(dom), type(exc).__name__)
                    return {"domain": dom, "resolves": False, "evidence": ["probe failed"]}

        probed = await asyncio.gather(*[_one(d) for d in to_fetch])

    scored = [score_mod.score_candidate(c, keyword, legit) for c in probed]
    scored.sort(key=lambda c: -c.get("score", 0))

    counts = {v: 0 for v in ("likely phishing", "suspicious", "parked", "unrelated")}
    for c in scored:
        counts[c["verdict"]] = counts.get(c["verdict"], 0) + 1

    rows = []
    for c in scored:
        rows.append({
            "domain": c["domain"], "verdict": c["verdict"], "score": c.get("score", 0),
            "registered": c.get("registered"), "registrar": c.get("registrar"),
            "asn": c.get("asn"), "evidence": c.get("evidence") or [],
            "gsb_url": _GSB + f"http://{c['domain']}/",
        })

    methodology = (
        "Discovery: certificate transparency keyword search (crt.sh), permutations "
        "of the legitimate domain (dnstwist: homoglyph, IDN and punycode, "
        "bitsquatting, TLD swap, hyphenation, keyword combos), urlscan.io keyword "
        "search, and an optional newly-registered-domain feed. Per candidate: DNS, "
        "RDAP registration and registrar, hosting ASN, cert freshness, and one "
        "homepage GET through the SSRF-safe fetcher plus a favicon fetch. No port "
        "scans, no crawling. Caps this run: "
        f"{config.HUNT_MAX_CANDIDATES} candidates, {config.HUNT_MAX_FETCHES} fetched.")
    gen = disc.get("generated_count", len(candidates))
    sline = f"{gen} candidates generated, {len(to_fetch)} fetched and assessed."
    if disc["incomplete"]:
        sline = "INCOMPLETE run. " + sline + " A discovery source did not answer."

    return {
        "kind": "hunt", "title": keyword, "legit_domain": legit, "generated_ts": time.time(),
        "scan_id": scan["scan_id"], "state": "done", "mode": "Public", "engagement": "",
        "operator": False, "incomplete": disc["incomplete"], "nrd_off": disc["nrd_off"],
        "source_status": disc["source_status"], "severity_counts": counts,
        "summary_line": sline, "candidates": rows, "hosts_probed": len(to_fetch),
        "methodology": methodology, "attribution": _ATTRIBUTION,
    }
