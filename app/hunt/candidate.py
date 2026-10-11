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

from app.ip_sources import asn_intel
from app.routers import domain_intel
from app.scanner import cloudflare_detect
from app.scanner.ph_bank_indicators import detect_brand, match_ph_indicators
from app.utils.logsafe import tag
from app.utils.safe_fetch import SafeFetchError, resolve_and_check, safe_fetch

log = logging.getLogger("falconeye.hunt.candidate")

_UA = "FalconEye-Hunt/3.38.0"
_HTTP_TIMEOUT = 8.0
_DNS_TIMEOUT = 4.0
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_ICON_RE = re.compile(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]+href=["\']([^"\']+)', re.IGNORECASE)
_PARK_SIGNALS = ("this domain is for sale", "buy this domain", "parked", "domain parking",
                 "sedoparking", "bodis", "related searches")


def _resolve_sync(host: str) -> dict:
    out = {"A": [], "AAAA": [], "MX": [], "NS": []}
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
                legit_favicon) -> dict:
    loop = asyncio.get_event_loop()
    dns_data = await loop.run_in_executor(None, _resolve_sync, domain)
    resolves = bool(dns_data["A"] or dns_data["AAAA"])

    out = {
        "domain": domain, "resolves": resolves, "has_mx": bool(dns_data["MX"]),
        "registered": None, "registrar": None, "reg_age_days": None, "asn": None,
        "fresh_cert": False, "http_status": None, "title": "", "favicon_match": False,
        "brand_markers": 0, "brand": None, "cloudflare": False, "ph_indicators": 0,
        "parked": False, "evidence": [],
    }
    if not resolves:
        out["evidence"].append("does not resolve")
        return out

    # RDAP registration + registrar.
    try:
        rdap_raw = await domain_intel.fetch_rdap(client, domain)
        parsed = domain_intel.parse_rdap(rdap_raw) if rdap_raw else None
        if parsed:
            out["registrar"] = (parsed.get("registrar") or {}).get("name")
            age = _reg_age_days(parsed)
            out["reg_age_days"] = age
            ev = (parsed.get("events") or {})
            out["registered"] = ev.get("registration")
    except Exception as exc:  # noqa: BLE001
        log.info("hunt rdap failed %s: %s", tag(domain), type(exc).__name__)

    # Hosting ASN of the first resolved public IP.
    try:
        ips = resolve_and_check(domain)
        if ips:
            asn, _ = await asn_intel.fetch_network_info(client, ips[0])
            out["asn"] = asn
    except SafeFetchError:
        pass
    except Exception:  # noqa: BLE001
        pass

    # Cert freshness via Cert Spotter (per-candidate, not keyword search).
    try:
        cs = await domain_intel.fetch_ct_certspotter(client, domain)
        for c in (cs or {}).get("raw_normalized", [])[:20]:
            nb = c.get("not_before")
            if nb:
                try:
                    dt = datetime.fromisoformat(nb.replace("Z", "+00:00"))
                    if (datetime.now(timezone.utc) - dt).days <= 30:
                        out["fresh_cert"] = True
                        break
                except Exception:  # noqa: BLE001
                    continue
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
        m = _TITLE_RE.search(body)
        out["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:160] if m else ""
        low = body.lower()
        if cloudflare_detect.detect_cloudflare_challenge(body):
            out["cloudflare"] = True
            out["evidence"].append("Cloudflare challenge")
        brand = detect_brand(body)
        if brand and brand.get("brand"):
            out["brand"] = brand["brand"]
            out["brand_markers"] = len(brand.get("matched_markers") or [])
        ph = match_ph_indicators(body, out.get("final_url") or f"https://{domain}/")
        out["ph_indicators"] = len(ph)
        if any(s in low for s in _PARK_SIGNALS):
            out["parked"] = True
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
                    out["evidence"].append("favicon matches the legitimate site")
        except Exception:  # noqa: BLE001
            pass

    return out


async def legit_favicon_hash(client: httpx.AsyncClient, legit_domain: str):
    """The favicon hash of the legitimate site, to compare candidates against."""
    if not legit_domain:
        return None
    try:
        res = await safe_fetch(f"https://{legit_domain}/favicon.ico", method="GET",
                               headers={"User-Agent": _UA}, timeout=6.0, max_redirects=2,
                               max_bytes=200_000)
        if res.get("status") == 200:
            return _favicon_hash((res.get("body") or "").encode("latin-1", "replace"))
    except Exception:  # noqa: BLE001
        return None
    return None
