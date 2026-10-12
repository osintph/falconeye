"""Candidate discovery for the Phishing Domain Hunt, with per-source status.

discover(keyword, legit) returns the candidate domains with the source that found
each one, a per-source status list, and honest counts. urlscan is the PRIMARY
keyword source: the run is INCOMPLETE only when urlscan fails, so a zero from a
source that actually answered is not treated as a clean result, while a degraded
crt.sh does not turn every run into a false INCOMPLETE.

Rules:
  - The legitimate domain and all its subdomains are never candidates.
  - Permutations are not generated under restricted namespaces an attacker cannot
    register (.gov.ph, .edu.ph, .mil.ph and equivalents); TLD swaps go to open,
    cheap TLDs instead.
  - urlscan and crt.sh keyword hits carry a source label so the report lists them
    first.
  - crt.sh keyword search is best effort and Hunt-scoped (crt.sh has no cheap
    substring search): it uses the plain keyword query, is cached and backed off
    on 502, never gates the run, and never affects the Domain Intel or ASM crt.sh
    paths.

Permutations run offline (dnstwist); the newly registered domain feed is optional.
No em dashes in this module.
"""
from __future__ import annotations

import asyncio
import io
import logging
import re
import zipfile

import httpx

from app import config
from app.asm import store
from app.hunt import themes
from app.scanner.scope import registrable
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.hunt.sources")

_UA = f"FalconEye-Hunt/3.38.15 (+{config.OPERATOR_SITE_ORIGIN})"
_URLSCAN = "https://urlscan.io/api/v1/search/"
_TIMEOUT = 20.0

# Phishing words combined with the brand label, and the open, cheap TLDs an
# attacker can actually register. Restricted namespaces below are never generated.
_COMBO_WORDS = ("login", "verify", "refund", "payment", "update", "portal", "claim",
                "secure", "account", "online", "ph")
_OPEN_TLDS = ("ph", "com.ph", "net.ph", "org.ph", "com", "net", "org", "online",
              "site", "info", "xyz", "top", "shop", "click", "link", "live", "app", "icu")

# Namespaces an attacker cannot register (government, education, military and the
# like). A permutation landing in one of these is a real institutional domain, not
# a lookalike, so it is dropped before it becomes a candidate. Small by design.
_RESTRICTED_SUFFIXES = (
    ".gov.ph", ".edu.ph", ".mil.ph", ".sss.gov.ph",
    ".gov", ".mil", ".edu", ".int",
    ".gov.uk", ".ac.uk", ".mod.uk",
    ".gob.es", ".gouv.fr", ".go.id", ".go.th", ".go.kr",
    ".gov.au", ".edu.au", ".govt.nz", ".gc.ca",
)

_HOST_OK = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def _clean_host(v: str) -> str:
    v = (v or "").strip().lower().lstrip("*.").rstrip(".")
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0].split(":", 1)[0]
    return v if _HOST_OK.match(v) else ""


def _is_legit_or_sub(host: str, legit: str) -> bool:
    """True if *host* is the legitimate domain or any subdomain of it. The legit
    domain and its own subdomains are the site being protected, never candidates."""
    if not legit:
        return False
    return host == legit or host.endswith("." + legit)


def _is_restricted(host: str) -> bool:
    return any(host == s.lstrip(".") or host.endswith(s) for s in _RESTRICTED_SUFFIXES)


def _allowed(host: str, legit: str) -> bool:
    return bool(host) and not _is_legit_or_sub(host, legit)


# The Hunt uses its own gate name so a crt.sh failure here can never affect the
# Domain Intel or ASM crt.sh paths (which do not consult this gate at all).
_HUNT_CRTSH_GATE = "hunt_crtsh"
_CRTSH_URL = "https://crt.sh/"


async def _crtsh(client: httpx.AsyncClient, keyword: str) -> tuple:
    """Best-effort crt.sh keyword lookup for the Hunt. crt.sh has no cheap substring
    search, so this uses the plain keyword query (not %keyword%) and treats crt.sh
    as optional: urlscan and the NRD feed are the primary keyword sources, so a
    crt.sh failure here never gates the run. A 24h per-keyword cache serves repeat
    hunts, each hunt makes at most ONE request, and a 502 backs the Hunt crt.sh
    call off for a window (a later hunt retries). Returns (hosts, status, note).
    The note never claims the IP is blocked, because it is not."""
    # 1. Fresh cache: no network at all.
    cached = store.ct_cache_get(keyword, config.HUNT_CT_CACHE_TTL)
    if cached is not None:
        return {h for h in cached if keyword in h}, "answered", "served from the 24h cache"

    # 2. A backoff from a recent crt.sh 502 is in effect: skip the request.
    if store.gate_wait(_HUNT_CRTSH_GATE) > config.HUNT_CRTSH_MIN_INTERVAL + 2:
        return set(), "failed", "crt.sh keyword search backing off after a recent 502, will retry later"

    # 3. One request, spaced across concurrent hunts. Plain keyword, no wildcards.
    wait = store.reserve_gate_slot(_HUNT_CRTSH_GATE, config.HUNT_CRTSH_MIN_INTERVAL)
    if wait > 0:
        await asyncio.sleep(min(wait, 30.0))
    try:
        r = await client.get(_CRTSH_URL, params={"q": keyword, "output": "json"},
                             timeout=_TIMEOUT, headers={"User-Agent": _UA})
        if r.status_code in (429, 500, 502, 503, 504):
            store.gate_set_backoff(_HUNT_CRTSH_GATE, config.HUNT_CRTSH_BACKOFF)
            return set(), "failed", f"crt.sh keyword search returned {r.status_code} (crt.sh side)"
        if r.status_code != 200 or "json" not in r.headers.get("content-type", "").lower():
            return set(), "failed", "crt.sh keyword search did not return JSON"
        hosts = set()
        for row in r.json():
            for name in str(row.get("name_value", "")).split("\n"):
                h = _clean_host(name)
                if h and keyword in h:
                    hosts.add(h)
        store.ct_cache_put(keyword, sorted(hosts))
        return hosts, "answered", ""
    except Exception as exc:  # noqa: BLE001
        log.info("hunt crt.sh failed for %s: %s", tag(keyword), type(exc).__name__)
        store.gate_set_backoff(_HUNT_CRTSH_GATE, config.HUNT_CRTSH_BACKOFF)
        return set(), "failed", "crt.sh keyword search errored (crt.sh side)"


def _public_result(api_url: str) -> str:
    return (api_url or "").replace("/api/v1/result/", "/result/")


async def _urlscan(client: httpx.AsyncClient, keyword: str) -> tuple:
    """urlscan keyword search (the primary keyword source). Returns (meta, status)
    where meta maps a registrable domain to its urlscan evidence: first seen, page
    title, classification labels, hosting ASN, urlscan-reported age, and the public
    result link. urlscan gives the apex domain directly, so hits collapse cleanly."""
    meta: dict = {}
    headers = {"User-Agent": _UA}
    key = config.URLSCAN_API_KEY
    if key:
        headers["API-Key"] = key
    try:
        r = await client.get(_URLSCAN, params={"q": f"page.domain:*{keyword}*", "size": 100},
                             timeout=_TIMEOUT, headers=headers)
        if r.status_code != 200:
            return meta, "failed"
        for res in (r.json().get("results") or []):
            page = res.get("page") or {}
            task = res.get("task") or {}
            apex = _clean_host(page.get("apexDomain") or task.get("apexDomain")
                               or page.get("domain") or "")
            observed = _clean_host(page.get("domain") or task.get("domain") or "")
            if not apex:
                continue
            labels = [str(x).lower() for x in (res.get("labels") or [])]
            age = page.get("apexDomainAgeDays")
            if age is None:
                age = page.get("domainAgeDays")
            m = meta.setdefault(apex, {
                "first_seen": task.get("time"), "title": page.get("title") or "",
                "labels": [], "asn": page.get("asnname") or page.get("asn"),
                "age_days": age, "server": page.get("server"),
                "result_url": _public_result(res.get("result")), "observed": set(),
            })
            m["labels"] = sorted(set(m["labels"]) | set(labels))
            if observed:
                m["observed"].add(observed)
            # Keep the earliest first-seen and a non-empty title if one appears.
            if task.get("time") and (not m["first_seen"] or task["time"] < m["first_seen"]):
                m["first_seen"] = task["time"]
            if not m["title"] and page.get("title"):
                m["title"] = page["title"]
    except Exception as exc:  # noqa: BLE001
        log.info("hunt urlscan failed for %s: %s", tag(keyword), type(exc).__name__)
        return meta, "failed"
    return meta, "answered"


def _brand_label(legit_domain: str, keyword: str) -> str:
    base = registrable(legit_domain).split(".", 1)[0] if legit_domain else keyword
    return base or keyword


def _permutations(legit_domain: str, keyword: str) -> set:
    """dnstwist permutations of the legit domain (offline), plus phishing-word
    combos on open TLDs. Homoglyph output is huge, so it is sampled. Restricted
    namespaces and the legit domain and its subdomains are excluded."""
    out = set()
    try:
        import dnstwist
        fuzz = dnstwist.Fuzzer(legit_domain)
        fuzz.generate()
        homo = 0
        for p in fuzz.permutations():
            dom = _clean_host(p.get("domain", ""))
            if not dom or _is_legit_or_sub(dom, legit_domain) or _is_restricted(dom):
                continue
            if p.get("fuzzer") in ("homoglyph", "cyrillic"):
                homo += 1
                if homo > 200:  # cap the homoglyph flood
                    continue
            out.add(dom)
    except Exception as exc:  # noqa: BLE001
        log.info("hunt permutations failed: %s", type(exc).__name__)
    # Phishing-word combos and plain TLD swaps on open, registrable TLDs only.
    base = _brand_label(legit_domain, keyword)
    for tld in _OPEN_TLDS:
        out.add(_clean_host(f"{base}.{tld}"))
        for w in _COMBO_WORDS:
            out.add(_clean_host(f"{base}-{w}.{tld}"))
            out.add(_clean_host(f"{base}{w}.{tld}"))
    return {h for h in out if h and not _is_restricted(h) and not _is_legit_or_sub(h, legit_domain)}


async def _nrd(client: httpx.AsyncClient, keyword: str) -> tuple:
    """Optional newly-registered-domain feed (WHOISDS). Off unless HUNT_NRD_URL is
    set. Accepts a zipped or plain text list of one domain per line."""
    url = config.HUNT_NRD_URL
    if not url:
        return set(), "skipped"
    hosts = set()
    try:
        r = await client.get(url, timeout=_TIMEOUT, headers={"User-Agent": _UA})
        if r.status_code != 200:
            return hosts, "failed"
        body = r.content
        text = ""
        if body[:2] == b"PK":  # a zip
            with zipfile.ZipFile(io.BytesIO(body)) as z:
                for name in z.namelist():
                    text += z.read(name).decode("utf-8", "replace")
        else:
            text = body.decode("utf-8", "replace")
        for line in text.splitlines():
            h = _clean_host(line)
            if h and keyword in h:
                hosts.add(h)
    except Exception as exc:  # noqa: BLE001
        log.info("hunt NRD feed failed: %s", type(exc).__name__)
        return hosts, "failed"
    return hosts, "answered"


def _has_phish_word(host: str) -> bool:
    return any(w in host for w in _COMBO_WORDS if len(w) > 2)


def _priority(host: str, origins: set) -> int:
    """Lower sorts first. Keyword hits (CT, urlscan) first, then NRD, then combos
    with a phishing word, then plain permutations."""
    if origins & {"crt.sh", "urlscan.io"}:
        return 0
    if "WHOISDS" in origins:
        return 1
    return 2 if _has_phish_word(host) else 3


def _is_malicious(labels) -> bool:
    return any(x in ("phishing", "malicious", "suspicious") for x in (labels or []))


async def discover(keyword: str, legit_domain: str, max_candidates: int = None) -> dict:
    """Gather, dedupe and cap candidates, collapsed to registrable domains, each
    with its source labels, observed hostnames, urlscan evidence and brand theme
    terms. urlscan and CT keyword hits whose brand letters are buried in an
    unrelated word (and that urlscan did not flag) are dropped as irrelevant and
    counted. urlscan is the primary keyword source and the only one that gates the
    run. Returns candidates, source_status, incomplete, nrd_off and counts."""
    status = []
    incomplete = False
    origins: dict = {}        # registrable -> set(source labels)
    observed: dict = {}       # registrable -> set(observed hostnames)
    us_meta: dict = {}        # registrable -> urlscan evidence

    def _add_hosts(hosts, label):
        for h in hosts:
            reg = registrable(h) or h
            if not _allowed(reg, legit_domain) or _is_restricted(reg):
                continue
            origins.setdefault(reg, set()).add(label)
            observed.setdefault(reg, set())
            if h != reg:
                observed[reg].add(h)

    async with httpx.AsyncClient(follow_redirects=True) as client:
        ct_hosts, ct_status, ct_note = await _crtsh(client, keyword)
        _add_hosts(ct_hosts, "crt.sh")
        ct_entry = {"source": "crt.sh", "role": "CT keyword search (best effort)",
                    "status": ct_status}
        if ct_note:
            ct_entry["note"] = ct_note
        status.append(ct_entry)

        us_result, us_status = await _urlscan(client, keyword)
        for apex, m in us_result.items():
            if not _allowed(apex, legit_domain) or _is_restricted(apex):
                continue
            origins.setdefault(apex, set()).add("urlscan.io")
            observed.setdefault(apex, set()).update(m.get("observed") or set())
            us_meta[apex] = {k: v for k, v in m.items() if k != "observed"}
        status.append({"source": "urlscan.io", "role": "keyword search (primary)",
                       "status": us_status})
        if us_status == "failed":
            incomplete = True

        if legit_domain:
            perms = _permutations(legit_domain, keyword)
            _add_hosts(perms, "dnstwist")
            status.append({"source": "dnstwist", "role": "permutations of the legit domain",
                           "status": "answered" if perms else "failed"})
        else:
            perms = _permutations("", keyword)
            _add_hosts(perms, "dnstwist")
            status.append({"source": "dnstwist", "role": "keyword permutations",
                           "status": "answered" if perms else "skipped"})

        nrd_hosts, nrd_status = await _nrd(client, keyword)
        _add_hosts(nrd_hosts, "WHOISDS")
        status.append({"source": "WHOISDS NRD", "role": "newly registered domains",
                       "status": nrd_status})

    ranked = sorted(origins.items(), key=lambda kv: (_priority(kv[0], kv[1]), len(kv[0]), kv[0]))
    cap = max_candidates if isinstance(max_candidates, int) and max_candidates > 0 \
        else config.HUNT_MAX_CANDIDATES
    candidates = []
    keyword_hits = 0
    irrelevant = 0
    for host, orig in ranked:
        is_hit = bool(orig & {"crt.sh", "urlscan.io"})
        meta = us_meta.get(host)
        title = (meta or {}).get("title") or ""
        cls = themes.classify(host, keyword, title)
        # A keyword hit that is not relevant (brand buried in an unrelated word, or
        # only in a shared-host registrable), with no urlscan malicious label, is
        # noise: drop and count it. A permutation is a targeted lookalike by
        # construction, so it is always kept.
        if is_hit and not cls["relevant"] and not _is_malicious((meta or {}).get("labels")):
            irrelevant += 1
            continue
        if len(candidates) >= cap:
            continue
        if is_hit:
            keyword_hits += 1
        candidates.append({
            "domain": host, "origins": sorted(orig), "keyword_hit": is_hit,
            "observed": sorted(observed.get(host) or []), "urlscan": meta,
            "themes": cls["themes"], "relevant": cls["relevant"],
        })

    return {"candidates": candidates, "source_status": status, "incomplete": incomplete,
            "nrd_off": not config.HUNT_NRD_URL, "generated_count": len(origins),
            "keyword_hit_count": keyword_hits, "irrelevant_count": irrelevant}
