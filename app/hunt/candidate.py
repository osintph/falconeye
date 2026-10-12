"""Probe one Hunt candidate and score it. Never raises; returns a partial result.

Per candidate: DNS (A, AAAA, MX, NS), RDAP registration date and registrar,
hosting ASN via RIPEstat, a cert freshness check via Cert Spotter, and exactly
one homepage GET through safe_fetch (title, final URL, PH brand and kit
indicators, Cloudflare challenge). One further small GET fetches the favicon for
its hash. No port scans, no crawling. No em dashes in this module.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import re
import time
from datetime import datetime, timezone

import dns.resolver
import httpx

from app.hunt import rdap as rdap_mod
from app.ip_sources import asn_intel
from app.routers import domain_intel
from app.scanner import cloudflare_detect
from app.scanner.ph_bank_indicators import detect_brand, match_ph_indicators
from app.utils import abusech
from app.utils import domain_age as domain_age_mod
from app.utils.logsafe import tag
from app.utils.safe_fetch import SafeFetchError, resolve_and_check, safe_fetch

try:
    from rapidfuzz import fuzz as _FUZZ
except Exception:  # noqa: BLE001 - optional; title similarity just does not contribute
    _FUZZ = None

log = logging.getLogger("falconeye.hunt.candidate")

_UA = "FalconEye-Hunt/3.38.14"
_HTTP_TIMEOUT = 8.0
_DNS_TIMEOUT = 4.0
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_ICON_RE = re.compile(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]+href=["\']([^"\']+)', re.IGNORECASE)


def _resolve_sync(host: str) -> dict:
    out = {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = _DNS_TIMEOUT
    resolver.timeout = _DNS_TIMEOUT
    for rt in out:
        try:
            for rd in resolver.resolve(host, rt):
                out[rt].append(str(rd).strip().rstrip("."))
        except Exception:
            continue
    return out


async def resolve(domain: str) -> dict:
    """Stage one: cheap DNS only. Returns the record sets, the resolved IPs and
    CNAME (for wildcard control matching), and resolves and has_mx/has_ns flags, so
    the fetch budget can be spent only on candidates that actually exist. No HTTP."""
    loop = asyncio.get_event_loop()
    dns_data = await loop.run_in_executor(None, _resolve_sync, domain)
    ips = sorted(set(dns_data["A"]) | set(dns_data["AAAA"]))
    cname = (dns_data.get("CNAME") or [""])[0] if dns_data.get("CNAME") else ""
    return {
        "domain": domain, "dns": dns_data, "ips": ips, "cname": cname,
        "resolves": bool(dns_data["A"] or dns_data["AAAA"]),
        "has_mx": bool(dns_data["MX"]), "has_ns": bool(dns_data["NS"]),
    }


# Parking, registrar, registry and marketplace landing pages. A candidate serving
# one of these is a benign landing, not an impersonation of the hunted brand.
_PARK_SIGNALS = ("this domain is for sale", "buy this domain", "domain for sale",
                 "the domain you are looking for", "parked", "domain parking",
                 "sedoparking", "sedo.com", "bodis", "dan.com", "afternic", "hugedomains",
                 "related searches", "domain is parked", "parkingcrew", "this web page is parked",
                 "get this domain", "inquire about this domain", "registry placeholder",
                 "future home of something")
_MARKETPLACE_SIGNALS = ("add to cart", "add to basket", "proceed to checkout", "shopping cart",
                        "place your order", "payment methods", "we accept", "pay with gcash",
                        "cash on delivery", "view cart")
_PH_SUFFIXES = ("ph", "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph", "mil.ph")
_PASSWORD_RE = re.compile(r'type\s*=\s*["\']?\s*password', re.IGNORECASE)
_PAYMENT_HINTS = ("card number", "cardnumber", "card-number", "cc-number", "cvv", "cvc",
                  "credit card", "card holder", "cardholder", "expiry", "expiration date")
# Positive evidence that a page is a real informational site, not a blank shell.
_INFO_HINTS = ("<article", "<nav", "blog", "read more", "posted on", "published",
               "comment", "newsletter", "privacy policy", "about us", "terms of",
               "copyright", "navigation", "related posts", "subscribe")


def assess_content(body: str, final_url: str, keyword: str, legit_domain: str,
                   legit_title: str) -> dict:
    """Classify a fetched homepage. Pure (no network), so it is unit tested.

    Parking, registrar and marketplace landing pages are flagged parked, and brand
    and PH-indicator checks are suppressed on them, so payment-method logos (GCash,
    Maya, bank marks) on a for-sale or checkout page do not read as impersonation.
    Brand impersonation is counted only when it relates to the hunted brand or the
    legitimate site, never an unrelated brand."""
    out = {"parked": False, "landing": "", "brand": None, "brand_markers": 0,
           "ph_indicators": 0, "legit_title_sim": 0, "title": "",
           "has_cred_form": False, "has_payment_form": False, "page_class": ""}
    low = (body or "").lower()

    m = _TITLE_RE.search(body or "")
    title = re.sub(r"\s+", " ", m.group(1)).strip()[:160] if m else ""
    out["title"] = title
    # Full-string ratio (not token_set_ratio, which over-matches short or generic
    # titles and flags unrelated sites) with a minimum legitimate-title length, so
    # only a page that genuinely copies the title reads as imitation.
    if legit_title and len(legit_title) >= 8 and title and _FUZZ:
        out["legit_title_sim"] = int(_FUZZ.ratio(title.lower(), legit_title.lower()))

    parked = any(s in low for s in _PARK_SIGNALS)
    marketplace = any(s in low for s in _MARKETPLACE_SIGNALS)
    # A marketplace or checkout page that is not imitating the legitimate site is a
    # benign landing, so treat it as parked and suppress the payment-logo markers.
    if marketplace and out["legit_title_sim"] < 70:
        parked = True
        if not out["landing"]:
            out["landing"] = "marketplace or checkout page"
    if parked and not out["landing"]:
        out["landing"] = next((s for s in _PARK_SIGNALS if s in low), "parking page")
    out["parked"] = parked

    if not parked:
        brand = detect_brand(body or "")
        bn = (brand.get("brand") or "")
        hunted = (keyword or "").lower()
        legit_label = legit_domain.split(".", 1)[0].lower() if legit_domain else ""
        bnl = bn.lower()
        related = bool(bn and ((hunted and (hunted in bnl or bnl in hunted))
                               or (legit_label and (legit_label in bnl or bnl in legit_label))))
        if related:
            out["brand"] = bn
            out["brand_markers"] = len(brand.get("matched_markers") or [])
        out["ph_indicators"] = len(match_ph_indicators(body or "", final_url or ""))

    # Credential and payment form detection, and the page class. A page that
    # collects a password or card, or imitates the legit title, is phishing
    # content; a fetched page with none of that is informational (brand
    # referencing), not phishing on its name alone.
    has_cred = bool(_PASSWORD_RE.search(body or "")) or (
        "<form" in low and "password" in low
        and any(s in low for s in ("login", "log in", "sign in", "signin")))
    has_pay = ("<form" in low or "<input" in low) and any(h in low for h in _PAYMENT_HINTS)
    out["has_cred_form"] = has_cred
    out["has_payment_form"] = has_pay

    # Positive informational-content test: a real article or site, not a shell.
    text = re.sub(r"<[^>]+>", " ", body or "")
    text = re.sub(r"\s+", " ", text).strip()
    info_markers = sum(1 for s in _INFO_HINTS if s in low) + (low.count("<a ") >= 5) \
        + (low.count("<p") >= 3)
    informational = len(text) >= 300 or info_markers >= 2

    if parked:
        out["page_class"] = "parked"
    elif out["legit_title_sim"] >= 80:
        out["page_class"] = "imitation"
    elif informational:
        out["page_class"] = "informational"
    elif body:
        out["page_class"] = "thin"  # fetched but near-empty: possible geofenced kit
    return out


def _favicon_hash(raw: bytes):
    try:
        import mmh3
        return mmh3.hash(base64.encodebytes(raw))
    except Exception:  # noqa: BLE001
        return None


def _reg_age_days(rdap_parsed) -> int | None:
    try:
        events = (rdap_parsed or {}).get("events") or {}
        reg = events.get("registration")
        if not reg:
            return None
        dt = datetime.fromisoformat(reg.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int((datetime.now(timezone.utc) - dt).days)
    except Exception:  # noqa: BLE001
        return None


async def probe(client: httpx.AsyncClient, domain: str, keyword: str, legit_domain: str,
                legit_sig, dns_data: dict | None = None) -> dict:
    legit_sig = legit_sig or {}
    legit_favicon = legit_sig.get("favicon")
    legit_title = legit_sig.get("title") or ""
    if dns_data is None:
        loop = asyncio.get_event_loop()
        dns_data = await loop.run_in_executor(None, _resolve_sync, domain)
    resolves = bool(dns_data["A"] or dns_data["AAAA"])

    out = {
        "domain": domain, "resolves": resolves, "has_mx": bool(dns_data["MX"]),
        "has_ns": bool(dns_data["NS"]),
        "registered": None, "registrar": None, "reg_age_days": None, "reg_note": None,
        "abuse_contact": None, "ct_first_seen": None, "ct_first_seen_age": None,
        "asn": None, "http_status": None, "title": "",
        "favicon_match": False, "brand_markers": 0, "brand": None, "cloudflare": False,
        "ph_indicators": 0, "legit_title_sim": 0, "known_bad": False, "landing": "",
        "parked": False, "fetched": False, "page_class": "", "has_cred_form": False,
        "has_payment_form": False, "evidence": [],
    }
    if not resolves:
        out["evidence"].append("does not resolve")
        return out

    # RDAP registration + registrar, via the domain's own authoritative RDAP
    # server (IANA bootstrap), capped per server, retried and cached, with a whois
    # registrar fallback. This is what fills the per-registrar campaign grouping.
    try:
        parsed = await rdap_mod.lookup(client, domain)
        if parsed:
            out["registrar"] = (parsed.get("registrar") or {}).get("name")
            out["reg_age_days"] = _reg_age_days(parsed)
            out["registered"] = (parsed.get("events") or {}).get("registration")
            out["abuse_contact"] = (parsed.get("abuse_contact") or {}).get("email")
    except Exception as exc:  # noqa: BLE001
        log.info("hunt rdap failed %s: %s", tag(domain), type(exc).__name__)

    # Registration date fallback via the shared helper (RDAP through rdap.org then
    # system whois). dot.ph does not publish a registration date in whois, so for
    # the PH registries we say so rather than show a bare n/a.
    if out["reg_age_days"] is None:
        try:
            info = await domain_age_mod.check_domain_age(domain)
            if info.get("found"):
                out["reg_age_days"] = info.get("age_days")
                out["registered"] = out["registered"] or (info.get("created_at") or "")[:10]
        except Exception as exc:  # noqa: BLE001
            log.info("hunt domain age fallback failed %s: %s", tag(domain), type(exc).__name__)
    if out["reg_age_days"] is None and not out["registered"] and \
            any(domain == s or domain.endswith("." + s) for s in _PH_SUFFIXES):
        out["reg_note"] = "registry does not publish registration date"

    # Hosting ASN of the first resolved public IP.
    try:
        ips = resolve_and_check(domain)
        if ips:
            out["ip"] = ips[0]
            asn, _ = await asn_intel.fetch_network_info(client, ips[0])
            out["asn"] = asn
    except SafeFetchError:
        pass
    except Exception:  # noqa: BLE001
        pass

    # First-live date from certificate transparency: the earliest certificate ever
    # logged for the domain (Cert Spotter). Used as the age basis when there is no
    # registration date, and to flag a dormant domain that was recently activated.
    # The current certificate is NOT a signal (short-lived, auto-renewed).
    try:
        cs = await domain_intel.fetch_ct_certspotter(client, domain)
        earliest = None
        for c in (cs or {}).get("raw_normalized", [])[:60]:
            nb = c.get("not_before")
            if not nb:
                continue
            try:
                dt = datetime.fromisoformat(nb.replace("Z", "+00:00"))
            except Exception:  # noqa: BLE001
                continue
            if earliest is None or dt < earliest:
                earliest = dt
        if earliest is not None:
            out["ct_first_seen"] = earliest.strftime("%Y-%m-%d")
            out["ct_first_seen_age"] = int((datetime.now(timezone.utc) - earliest).days)
    except Exception:  # noqa: BLE001
        pass

    # Known-bad listing (URLhaus), a strong signal. Only when a key is configured.
    try:
        if abusech.configured():
            uh = await abusech.urlhaus_host(client, domain)
            if uh and uh.get("query_status") == "ok" and (uh.get("urls") or uh.get("url_count")):
                out["known_bad"] = True
                out["evidence"].append("listed on URLhaus")
    except Exception:  # noqa: BLE001
        pass

    # Exactly one homepage GET, https then http.
    body = ""
    for scheme in ("https", "http"):
        try:
            res = await safe_fetch(f"{scheme}://{domain}/", method="GET",
                                   headers={"User-Agent": _UA}, timeout=_HTTP_TIMEOUT,
                                   max_redirects=4, max_bytes=300_000)
            out["http_status"] = res.get("status")
            body = res.get("body", "") or ""
            out["final_url"] = res.get("url_final")
            break
        except SafeFetchError:
            continue
        except Exception:  # noqa: BLE001
            continue

    if body:
        if cloudflare_detect.detect_cloudflare_challenge(body):
            out["cloudflare"] = True
        assess = assess_content(body, out.get("final_url") or f"https://{domain}/",
                                keyword, legit_domain, legit_title)
        out["title"] = assess["title"]
        out["parked"] = assess["parked"]
        out["landing"] = assess["landing"]
        out["brand"] = assess["brand"]
        out["brand_markers"] = assess["brand_markers"]
        out["ph_indicators"] = assess["ph_indicators"]
        out["legit_title_sim"] = assess["legit_title_sim"]
        out["page_class"] = assess["page_class"]
        out["has_cred_form"] = assess["has_cred_form"]
        out["has_payment_form"] = assess["has_payment_form"]
        if assess["parked"]:
            out["evidence"].append(f"parking or landing page ({assess['landing']})")
        if assess["has_cred_form"]:
            out["evidence"].append("collects a password (credential form)")
        if assess["has_payment_form"]:
            out["evidence"].append("collects card or payment details")
        if out["brand_markers"]:
            out["evidence"].append(f"brand impersonation content for {out['brand']}")
        if out["legit_title_sim"] >= 80:
            out["evidence"].append("page title closely imitates the legitimate site")
        elif assess["page_class"] == "informational":
            out["evidence"].append("informational or brand-referencing page, no credential or payment form")
        elif assess["page_class"] == "thin":
            out["evidence"].append("near-empty or blank page from our vantage")
        # Favicon hash: one small fetch, from the page's icon href or /favicon.ico.
        icon = _ICON_RE.search(body)
        icon_url = None
        if icon:
            href = icon.group(1).strip()
            if href.startswith("http"):
                icon_url = href
            elif href.startswith("/"):
                icon_url = f"https://{domain}{href}"
        icon_url = icon_url or f"https://{domain}/favicon.ico"
        try:
            fres = await safe_fetch(icon_url, method="GET", headers={"User-Agent": _UA},
                                    timeout=6.0, max_redirects=2, max_bytes=200_000)
            if fres.get("status") == 200:
                fh = _favicon_hash((fres.get("body") or "").encode("latin-1", "replace"))
                out["favicon_hash"] = fh
                if fh is not None and legit_favicon is not None and fh == legit_favicon:
                    out["favicon_match"] = True
                    out["page_class"] = "imitation"  # favicon match is imitation
                    out["evidence"].append("favicon matches the legitimate site")
        except Exception:  # noqa: BLE001
            pass

    # A real homepage was retrieved only if a body came back and it was not a
    # Cloudflare interstitial. A resolving domain we could not fetch is UNKNOWN,
    # never unrelated.
    out["fetched"] = bool(body) and not out["cloudflare"]
    return out


async def legit_signature(client: httpx.AsyncClient, legit_domain: str) -> dict:
    """The legitimate site's favicon hash and homepage title, so a candidate that
    imitates it (favicon match, title similarity) can be recognised."""
    sig = {"favicon": None, "title": ""}
    if not legit_domain:
        return sig
    try:
        res = await safe_fetch(f"https://{legit_domain}/", method="GET",
                               headers={"User-Agent": _UA}, timeout=_HTTP_TIMEOUT,
                               max_redirects=4, max_bytes=300_000)
        body = res.get("body") or ""
        m = _TITLE_RE.search(body)
        if m:
            sig["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:160]
    except Exception:  # noqa: BLE001
        pass
    try:
        res = await safe_fetch(f"https://{legit_domain}/favicon.ico", method="GET",
                               headers={"User-Agent": _UA}, timeout=6.0, max_redirects=2,
                               max_bytes=200_000)
        if res.get("status") == 200:
            sig["favicon"] = _favicon_hash((res.get("body") or "").encode("latin-1", "replace"))
    except Exception:  # noqa: BLE001
        pass
    return sig
