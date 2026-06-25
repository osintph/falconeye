"""
Email Header Analyzer.

Takes a raw email header text, parses it, runs authentication checks,
traces the Received chain, attributes hops to ASNs, and surfaces BEC indicators.
"""
import asyncio
import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from email import message_from_string
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any
import logging

import dns.resolver
import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.config import DB_PATH

log = logging.getLogger(__name__)
router = APIRouter()

CACHE_TTL_HOURS = 24
HTTP_TIMEOUT = 6.0

FREE_WEBMAIL = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com",
    "yandex.com", "yandex.ru", "mail.com", "gmx.com", "gmx.net", "tutanota.com",
    "zoho.com", "fastmail.com", "hushmail.com", "yahoo.co.uk", "yahoo.co.jp",
}


class HeaderAnalyzeRequest(BaseModel):
    raw_header: str


def _init_cache():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS email_header_cache (
            id TEXT PRIMARY KEY,
            response_json TEXT NOT NULL,
            fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


_init_cache()


# ---------- header parsing helpers ----------

RECEIVED_FROM_IP = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
RECEIVED_FROM_HOST = re.compile(r"from\s+([\w.\-]+)", re.IGNORECASE)
RECEIVED_BY = re.compile(r"by\s+([\w.\-]+)", re.IGNORECASE)
RECEIVED_WITH = re.compile(r"with\s+([\w.\-/]+)", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"[a-zA-Z0-9._+-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
PRIVATE_RANGES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                  "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                  "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                  "127.")


def _is_public_ip(ip: str) -> bool:
    return not any(ip.startswith(prefix) for prefix in PRIVATE_RANGES)


def _hash_header(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _parse_received_chain(headers: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Parse all Received headers in order (newest first to oldest last)."""
    received_lines = [v for k, v in headers if k.lower() == "received"]
    hops = []
    for idx, line in enumerate(received_lines):
        clean = " ".join(line.split())
        from_host = RECEIVED_FROM_HOST.search(clean)
        by_host = RECEIVED_BY.search(clean)
        with_proto = RECEIVED_WITH.search(clean)
        ip_match = RECEIVED_FROM_IP.search(clean)

        date_str = clean.rsplit(";", 1)[-1].strip() if ";" in clean else None
        try:
            ts = parsedate_to_datetime(date_str) if date_str else None
        except (TypeError, ValueError):
            ts = None

        hops.append({
            "hop_index": idx,
            "from_host": from_host.group(1) if from_host else None,
            "by_host": by_host.group(1) if by_host else None,
            "with_protocol": with_proto.group(1) if with_proto else None,
            "ip": ip_match.group(1) if ip_match else None,
            "timestamp": ts.isoformat() if ts else None,
            "raw": clean[:500],
        })
    hops.reverse()
    return hops


def _compute_hop_delays(hops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add delay_seconds between hops."""
    prev_ts = None
    for hop in hops:
        if hop.get("timestamp"):
            try:
                ts = datetime.fromisoformat(hop["timestamp"])
                if prev_ts:
                    delta = (ts - prev_ts).total_seconds()
                    hop["delay_seconds"] = abs(delta)
                prev_ts = ts
            except (ValueError, TypeError):
                pass
    return hops


def _parse_addresses(value: str) -> list[dict[str, str]]:
    out = []
    for display, addr in getaddresses([value or ""]):
        if addr:
            domain = addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""
            out.append({"display": display, "email": addr, "domain": domain})
    return out


def _parse_auth_results(value: str) -> dict[str, str]:
    out = {"spf": "none", "dkim": "none", "dmarc": "none", "raw": value}
    if not value:
        return out
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=([\w]+)", value, re.IGNORECASE)
        if m:
            out[mech] = m.group(1).lower()
    return out


# ---------- live DNS lookups ----------

async def _resolve_txt(domain: str) -> list[str]:
    try:
        loop = asyncio.get_event_loop()
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4
        resolver.timeout = 4
        answers = await loop.run_in_executor(
            None, lambda: resolver.resolve(domain, "TXT")
        )
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
    except Exception:
        return []


async def _lookup_spf(domain: str) -> dict[str, Any]:
    txts = await _resolve_txt(domain)
    for t in txts:
        if t.lower().startswith("v=spf1"):
            return {"found": True, "record": t}
    return {"found": False, "record": None}


async def _lookup_dmarc(domain: str) -> dict[str, Any]:
    txts = await _resolve_txt(f"_dmarc.{domain}")
    for t in txts:
        if t.lower().startswith("v=dmarc1"):
            policy = re.search(r"\bp=([a-z]+)", t, re.IGNORECASE)
            return {
                "found": True,
                "record": t,
                "policy": policy.group(1).lower() if policy else "none",
            }
    return {"found": False, "record": None, "policy": None}


async def _lookup_dkim_selector(domain: str, selector: str) -> dict[str, Any]:
    txts = await _resolve_txt(f"{selector}._domainkey.{domain}")
    for t in txts:
        if "v=DKIM1" in t or "p=" in t:
            return {"found": True, "selector": selector, "record": t[:300]}
    return {"found": False, "selector": selector, "record": None}


async def _lookup_reverse_dns(ip: str) -> str | None:
    try:
        loop = asyncio.get_event_loop()
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3
        resolver.timeout = 3
        reversed_ip = dns.reversename.from_address(ip)
        answers = await loop.run_in_executor(
            None, lambda: resolver.resolve(reversed_ip, "PTR")
        )
        return str(answers[0]).rstrip(".")
    except Exception:
        return None


async def _enrich_ip(ip: str) -> dict[str, Any]:
    out = {"ip": ip, "asn": None, "country": None, "org": None, "rdns": None,
           "greynoise": None}
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        try:
            r = await client.get(
                "https://stat.ripe.net/data/network-info/data.json",
                params={"resource": ip},
            )
            if r.status_code == 200:
                asns = r.json().get("data", {}).get("asns", [])
                out["asn"] = asns[0] if asns else None
        except Exception:
            pass
        try:
            r = await client.get(
                "https://stat.ripe.net/data/maxmind-geo-lite/data.json",
                params={"resource": ip},
            )
            if r.status_code == 200:
                loc = r.json().get("data", {}).get("located_resources", [])
                if loc and loc[0].get("locations"):
                    first_loc = loc[0]["locations"][0]
                    out["country"] = first_loc.get("country")
                    out["org"] = first_loc.get("city")
        except Exception:
            pass

    out["rdns"] = await _lookup_reverse_dns(ip)
    return out


# ---------- BEC scoring ----------

def _score_bec_indicators(parsed: dict[str, Any]) -> dict[str, Any]:
    score = 0
    indicators = []

    auth = parsed.get("authentication", {})
    from_addrs = parsed.get("from", [])
    reply_to = parsed.get("reply_to", [])
    return_path = parsed.get("return_path", [])

    if auth.get("spf") in ("fail", "softfail"):
        score += 30
        indicators.append({
            "severity": "high",
            "name": "SPF failure",
            "detail": f"SPF result: {auth.get('spf')}",
        })

    if auth.get("dkim") in ("fail", "none") and from_addrs:
        score += 20
        indicators.append({
            "severity": "medium",
            "name": "DKIM not validated",
            "detail": f"DKIM result: {auth.get('dkim')}",
        })

    if auth.get("dmarc") in ("fail", "none"):
        score += 15
        indicators.append({
            "severity": "medium",
            "name": "DMARC not validated",
            "detail": f"DMARC result: {auth.get('dmarc')}",
        })

    if from_addrs and reply_to:
        from_dom = from_addrs[0].get("domain", "")
        reply_dom = reply_to[0].get("domain", "")
        if from_dom and reply_dom and from_dom != reply_dom:
            score += 35
            indicators.append({
                "severity": "high",
                "name": "Reply-To domain mismatch",
                "detail": f"From: {from_dom} / Reply-To: {reply_dom}",
            })

    if from_addrs and return_path:
        from_dom = from_addrs[0].get("domain", "")
        rp_dom = return_path[0].get("domain", "")
        if from_dom and rp_dom and from_dom != rp_dom:
            score += 25
            indicators.append({
                "severity": "medium",
                "name": "Return-Path domain mismatch",
                "detail": f"From: {from_dom} / Return-Path: {rp_dom}",
            })

    if from_addrs:
        first = from_addrs[0]
        display = (first.get("display") or "").lower()
        domain = first.get("domain", "").lower()
        display_domain_match = re.search(r"@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})", display)
        if display_domain_match and display_domain_match.group(1).lower() != domain:
            score += 30
            indicators.append({
                "severity": "high",
                "name": "Display name contains different domain",
                "detail": f"Display: '{display}' / Actual domain: {domain}",
            })

    if from_addrs:
        first = from_addrs[0]
        domain = first.get("domain", "").lower()
        display = (first.get("display") or "").lower()
        if domain in FREE_WEBMAIL:
            corporate_words = ["ceo", "cfo", "director", "manager", "accounting",
                               "finance", "hr", "support", "admin", "legal"]
            if any(word in display for word in corporate_words):
                score += 40
                indicators.append({
                    "severity": "high",
                    "name": "Free webmail with corporate display name",
                    "detail": f"Display: '{display}' from {domain}",
                })

    hops = parsed.get("received_chain", [])
    public_hops = [h for h in hops if h.get("ip") and _is_public_ip(h["ip"])]
    if public_hops:
        first_external = public_hops[0]
        country = first_external.get("country")
        if country:
            indicators.append({
                "severity": "info",
                "name": "Originating country",
                "detail": f"First external hop from: {country}",
            })

    score = min(score, 100)

    verdict = "low_risk"
    if score >= 70:
        verdict = "high_risk"
    elif score >= 40:
        verdict = "medium_risk"
    elif score >= 20:
        verdict = "low_risk_with_indicators"

    return {"score": score, "verdict": verdict, "indicators": indicators}


# ---------- main analyze endpoint ----------

@router.post("/api/email-header/analyze")
async def analyze(req: HeaderAnalyzeRequest):
    raw = req.raw_header.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="empty header input")
    if len(raw) > 200000:
        raise HTTPException(status_code=400, detail="header too large (max 200KB)")

    header_id = _hash_header(raw)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "SELECT response_json, fetched_at FROM email_header_cache WHERE id = ?",
        (header_id,),
    )
    row = cur.fetchone()
    conn.close()

    if row:
        cached_json, fetched_at = row
        cached = json.loads(cached_json)
        cached["cache_hit"] = True
        cached["fetched_at"] = fetched_at
        return cached

    msg = message_from_string(raw)
    headers_pairs = list(msg.items())

    parsed: dict[str, Any] = {
        "from": _parse_addresses(msg.get("From", "")),
        "to": _parse_addresses(msg.get("To", "")),
        "cc": _parse_addresses(msg.get("Cc", "")),
        "reply_to": _parse_addresses(msg.get("Reply-To", "")),
        "return_path": _parse_addresses(msg.get("Return-Path", "")),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "user_agent": msg.get("User-Agent", "") or msg.get("X-Mailer", ""),
        "list_unsubscribe": msg.get("List-Unsubscribe", ""),
        "auto_submitted": msg.get("Auto-Submitted", ""),
        "authentication": _parse_auth_results(msg.get("Authentication-Results", "")),
        "dkim_signature": msg.get("DKIM-Signature", "")[:600],
        "spf_received": msg.get("Received-SPF", ""),
        "x_headers": {k: v for k, v in headers_pairs if k.lower().startswith("x-")},
        "received_chain": _compute_hop_delays(_parse_received_chain(headers_pairs)),
    }

    from_domain = parsed["from"][0]["domain"] if parsed["from"] else None
    if from_domain:
        spf_lookup, dmarc_lookup = await asyncio.gather(
            _lookup_spf(from_domain),
            _lookup_dmarc(from_domain),
        )
        parsed["spf_live"] = spf_lookup
        parsed["dmarc_live"] = dmarc_lookup

        dkim_sig = parsed["dkim_signature"]
        sel_match = re.search(r"\bs=([\w\-]+)", dkim_sig)
        if sel_match:
            parsed["dkim_live"] = await _lookup_dkim_selector(
                from_domain, sel_match.group(1)
            )

    public_hops = [h for h in parsed["received_chain"] if h.get("ip") and _is_public_ip(h["ip"])]
    if public_hops:
        enrichment = await _enrich_ip(public_hops[0]["ip"])
        public_hops[0].update(enrichment)
        parsed["originating_ip"] = public_hops[0]

    raw_for_iocs = raw[:50000]
    iocs = {
        "urls": list(set(URL_RE.findall(raw_for_iocs)))[:20],
        "emails": list(set(EMAIL_RE.findall(raw_for_iocs)))[:30],
        "ips": list(set(h.get("ip") for h in parsed["received_chain"] if h.get("ip") and _is_public_ip(h["ip"]))),
        "sha256": list(set(SHA256_RE.findall(raw_for_iocs)))[:10],
    }
    parsed["iocs"] = iocs

    parsed["bec_assessment"] = _score_bec_indicators(parsed)
    parsed["cache_hit"] = False
    parsed["fetched_at"] = datetime.now(timezone.utc).isoformat()

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO email_header_cache (id, response_json, fetched_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
        (header_id, json.dumps(parsed)),
    )
    conn.commit()
    conn.close()

    return parsed
