"""Candidate discovery for the Phishing Domain Hunt, with per-source status.

Returns (candidates, status_list, incomplete). Each source reports answered,
failed or skipped; if crt.sh or urlscan (the network discovery sources) fails,
the run is INCOMPLETE and a zero result is not a clean result. Permutations run
offline (dnstwist) and the newly-registered-domain feed is optional. No em
dashes in this module.
"""
from __future__ import annotations

import io
import logging
import zipfile

import httpx

from app import config
from app.scanner.scope import registrable
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.hunt.sources")

_UA = f"FalconEye-Hunt/3.38.0 (+{config.OPERATOR_SITE_ORIGIN})"
_CRTSH = "https://crt.sh/"
_URLSCAN = "https://urlscan.io/api/v1/search/"
_TIMEOUT = 20.0

# Keyword combinations and PH TLDs appended to permutations of a legit domain.
_COMBO_WORDS = ("login", "verify", "refund", "payment", "update", "portal", "online", "ph", "secure")
_PH_TLDS = ("ph", "com.ph", "net.ph", "org.ph", "gov.ph")

_HOST_OK = __import__("re").compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def _clean_host(v: str) -> str:
    v = (v or "").strip().lower().lstrip("*.").rstrip(".")
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0].split(":", 1)[0]
    return v if _HOST_OK.match(v) else ""


async def _crtsh(client: httpx.AsyncClient, keyword: str) -> tuple:
    """CT keyword search. crt.sh only: Cert Spotter has no keyword search."""
    hosts = set()
    try:
        r = await client.get(_CRTSH, params={"q": f"%{keyword}%", "output": "json"},
                             timeout=_TIMEOUT, headers={"User-Agent": _UA})
        if r.status_code != 200 or "json" not in r.headers.get("content-type", "").lower():
            return hosts, "failed"
        for row in r.json():
            for name in str(row.get("name_value", "")).split("\n"):
                h = _clean_host(name)
                if h and keyword in h:
                    hosts.add(h)
    except Exception as exc:  # noqa: BLE001
        log.info("hunt crt.sh failed for %s: %s", tag(keyword), type(exc).__name__)
        return hosts, "failed"
    return hosts, "answered"


async def _urlscan(client: httpx.AsyncClient, keyword: str) -> tuple:
    hosts = set()
    headers = {"User-Agent": _UA}
    key = config.URLSCAN_API_KEY
    if key:
        headers["API-Key"] = key
    try:
        r = await client.get(_URLSCAN, params={"q": f"page.domain:*{keyword}*", "size": 100},
                             timeout=_TIMEOUT, headers=headers)
        if r.status_code == 429:
            return hosts, "failed"
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


def _permutations(legit_domain: str, keyword: str) -> set:
    """dnstwist permutations of the legit domain, offline, plus keyword combos and
    PH TLD swaps. Homoglyph output is huge, so it is sampled."""
    out = set()
    try:
        import dnstwist
        fuzz = dnstwist.Fuzzer(legit_domain)
        fuzz.generate()
        homo = 0
        for p in fuzz.permutations():
            dom = _clean_host(p.get("domain", ""))
            if not dom or dom == legit_domain:
                continue
            if p.get("fuzzer") in ("homoglyph", "cyrillic"):
                homo += 1
                if homo > 200:  # cap the homoglyph flood
                    continue
            out.add(dom)
    except Exception as exc:  # noqa: BLE001
        log.info("hunt permutations failed: %s", type(exc).__name__)
    # Keyword combos and PH TLD variants of the base label.
    base = registrable(legit_domain).split(".", 1)[0] if legit_domain else keyword
    base = base or keyword
    for w in _COMBO_WORDS:
        for tld in _PH_TLDS:
            out.add(_clean_host(f"{base}-{w}.{tld}"))
            out.add(_clean_host(f"{base}{w}.{tld}"))
    for tld in _PH_TLDS:
        out.add(_clean_host(f"{base}.{tld}"))
    return {h for h in out if h}


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


async def discover(keyword: str, legit_domain: str) -> dict:
    """Gather, dedupe and cap candidate domains. Returns a dict with candidates,
    source_status, incomplete and nrd_off."""
    status = []
    incomplete = False
    all_hosts = set()

    async with httpx.AsyncClient(follow_redirects=True) as client:
        ct_hosts, ct_status = await _crtsh(client, keyword)
        all_hosts |= ct_hosts
        status.append({"source": "crt.sh", "role": "CT keyword search", "status": ct_status})
        if ct_status == "failed":
            incomplete = True

        us_hosts, us_status = await _urlscan(client, keyword)
        all_hosts |= us_hosts
        status.append({"source": "urlscan.io", "role": "keyword search", "status": us_status})
        if us_status == "failed":
            incomplete = True

        if legit_domain:
            perms = _permutations(legit_domain, keyword)
            all_hosts |= perms
            status.append({"source": "dnstwist", "role": "permutations of the legit domain",
                           "status": "answered" if perms else "failed"})
        else:
            status.append({"source": "dnstwist", "role": "permutations",
                           "status": "skipped"})

        nrd_hosts, nrd_status = await _nrd(client, keyword)
        all_hosts |= nrd_hosts
        status.append({"source": "WHOISDS NRD", "role": "newly registered domains",
                       "status": nrd_status})

    # Prioritise candidates that actually contain the keyword, then cap.
    ranked = sorted(all_hosts, key=lambda h: (keyword not in h, len(h)))
    candidates = ranked[:config.HUNT_MAX_CANDIDATES]
    return {"candidates": candidates, "source_status": status, "incomplete": incomplete,
            "nrd_off": not config.HUNT_NRD_URL, "generated_count": len(all_hosts)}
