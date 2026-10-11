"""Candidate discovery for the Phishing Domain Hunt, with per-source status.

discover(keyword, legit) returns the candidate domains with the source that found
each one, a per-source status list, and honest counts. Each source reports
answered, failed or skipped; if crt.sh or urlscan (the network discovery sources)
fails, the run is INCOMPLETE and a zero result is not a clean result.

Rules, from the v3.38.1 brief:
  - The legitimate domain and all its subdomains are never candidates.
  - Permutations are not generated under restricted namespaces an attacker cannot
    register (.gov.ph, .edu.ph, .mil.ph and equivalents); TLD swaps go to open,
    cheap TLDs instead.
  - Certificate transparency keyword hits (crt.sh) and urlscan hits carry a source
    label so the report can show them first.
  - crt.sh is retried with backoff and serialised through a global gate so
    concurrent hunts respect its rate limit.

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
from app.scanner.scope import registrable
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.hunt.sources")

_UA = f"FalconEye-Hunt/3.38.3 (+{config.OPERATOR_SITE_ORIGIN})"
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


async def _crtsh_get(client: httpx.AsyncClient, params: dict):
    """One crt.sh GET, through HUNT_CRTSH_PROXY and HUNT_CRTSH_BASE when set. crt.sh
    returns a fast 502 to some egress IPs (the production VPS among them); a proxy
    on a host whose IP it serves restores access."""
    base = config.HUNT_CRTSH_BASE
    proxy = config.HUNT_CRTSH_PROXY
    headers = {"User-Agent": _UA}
    if proxy:
        async with httpx.AsyncClient(proxy=proxy, follow_redirects=True) as pc:
            return await pc.get(base, params=params, timeout=_TIMEOUT, headers=headers)
    return await client.get(base, params=params, timeout=_TIMEOUT, headers=headers)


async def _crtsh(client: httpx.AsyncClient, keyword: str) -> tuple:
    """CT keyword search. crt.sh only (Cert Spotter has no keyword search).

    crt.sh is rate limited and shared across concurrent hunts, so each call first
    reserves a spaced slot from a global gate, then retries with backoff. A clean
    empty answer is 'answered'; exhausting the retries is 'failed' (which makes the
    run INCOMPLETE)."""
    hosts = set()
    attempts = 3
    for i in range(attempts):
        wait = store.reserve_gate_slot("crtsh", config.HUNT_CRTSH_MIN_INTERVAL)
        if wait > 0:
            await asyncio.sleep(min(wait, 30.0))
        try:
            r = await _crtsh_get(client, {"q": f"%{keyword}%", "output": "json"})
            if r.status_code in (429, 500, 502, 503, 504):
                raise httpx.HTTPError(f"crt.sh {r.status_code}")
            if r.status_code != 200 or "json" not in r.headers.get("content-type", "").lower():
                return hosts, "failed"
            for row in r.json():
                for name in str(row.get("name_value", "")).split("\n"):
                    h = _clean_host(name)
                    if h and keyword in h:
                        hosts.add(h)
            return hosts, "answered"
        except Exception as exc:  # noqa: BLE001
            log.info("hunt crt.sh attempt %d/%d for %s: %s", i + 1, attempts,
                     tag(keyword), type(exc).__name__)
            if i < attempts - 1:
                await asyncio.sleep(2.0 * (i + 1))
    return hosts, "failed"


async def _urlscan(client: httpx.AsyncClient, keyword: str) -> tuple:
    hosts = set()
    headers = {"User-Agent": _UA}
    key = config.URLSCAN_API_KEY
    if key:
        headers["API-Key"] = key
    try:
        r = await client.get(_URLSCAN, params={"q": f"page.domain:*{keyword}*", "size": 100},
                             timeout=_TIMEOUT, headers=headers)
        if r.status_code != 200:
            return hosts, "failed"
        for res in (r.json().get("results") or []):
            h = _clean_host(((res.get("page") or {}).get("domain")) or "")
            if h and keyword in h:
                hosts.add(h)
    except Exception as exc:  # noqa: BLE001
        log.info("hunt urlscan failed for %s: %s", tag(keyword), type(exc).__name__)
        return hosts, "failed"
    return hosts, "answered"


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


async def discover(keyword: str, legit_domain: str) -> dict:
    """Gather, dedupe and cap candidate domains, tracking which source found each.
    Returns candidates (each with its source labels and a keyword_hit flag),
    source_status, incomplete and nrd_off."""
    status = []
    incomplete = False
    origins: dict = {}

    def _add(found, label):
        for h in found:
            if _allowed(h, legit_domain):
                origins.setdefault(h, set()).add(label)

    async with httpx.AsyncClient(follow_redirects=True) as client:
        ct_hosts, ct_status = await _crtsh(client, keyword)
        _add(ct_hosts, "crt.sh")
        status.append({"source": "crt.sh", "role": "CT keyword search", "status": ct_status})
        if ct_status == "failed":
            incomplete = True

        us_hosts, us_status = await _urlscan(client, keyword)
        _add(us_hosts, "urlscan.io")
        status.append({"source": "urlscan.io", "role": "keyword search", "status": us_status})
        if us_status == "failed":
            incomplete = True

        if legit_domain:
            perms = _permutations(legit_domain, keyword)
            _add(perms, "dnstwist")
            status.append({"source": "dnstwist", "role": "permutations of the legit domain",
                           "status": "answered" if perms else "failed"})
        else:
            perms = _permutations("", keyword)
            _add(perms, "dnstwist")
            status.append({"source": "dnstwist", "role": "keyword permutations",
                           "status": "answered" if perms else "skipped"})

        nrd_hosts, nrd_status = await _nrd(client, keyword)
        _add(nrd_hosts, "WHOISDS")
        status.append({"source": "WHOISDS NRD", "role": "newly registered domains",
                       "status": nrd_status})

    generated = len(origins)
    ranked = sorted(origins.items(), key=lambda kv: (_priority(kv[0], kv[1]), len(kv[0]), kv[0]))
    candidates = []
    keyword_hits = 0
    for host, orig in ranked[:config.HUNT_MAX_CANDIDATES]:
        is_hit = bool(orig & {"crt.sh", "urlscan.io"})
        if is_hit:
            keyword_hits += 1
        candidates.append({"domain": host, "origins": sorted(orig), "keyword_hit": is_hit})

    return {"candidates": candidates, "source_status": status, "incomplete": incomplete,
            "nrd_off": not config.HUNT_NRD_URL, "generated_count": generated,
            "keyword_hit_count": keyword_hits}
