"""
Email Header Analyzer.

Takes a raw email header text, parses it, runs authentication checks,
traces the Received chain, attributes hops to ASNs, and surfaces BEC indicators.
Optionally accepts an email body for scam-pattern detection.
"""
import asyncio
import hashlib
import io
import json
import re
import sqlite3
import tempfile
from datetime import datetime, timezone
from email import message_from_string
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser as _HTMLParser
from typing import Any
import logging

import dns.resolver
import httpx
from anthropic import AsyncAnthropic, APIError, APIStatusError, APITimeoutError
from fastapi import APIRouter, HTTPException, Request, UploadFile, File
from pydantic import BaseModel

from app.config import (
    DB_PATH,
    LLM_ANALYSIS_ENABLED, LLM_MAX_BODY_TOKENS,
    LLM_RATE_LIMIT_PER_DAY, LLM_TIMEOUT_SECONDS, LLM_MIN_BODY_CHARS,
    ANTHROPIC_API_KEY,
    REGEX_MAX_BODY_BYTES,
)
from app.utils.client_ip import get_client_ip
from app.utils.llm_response import clamp_int, safe_str, validate_findings_list

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

# ---- Scam / phishing body pattern library ----

SCAM_PATTERNS = {
    "urgency": {
        "weight": 10,
        "severity": "medium",
        "label": "Urgency / pressure language",
        "patterns": [
            r"\b(act|respond|verify|confirm|click|update)\s+(now|immediately|today|within\s+\d+)",
            r"\b(urgent(?:ly)?|asap|immediate(?:ly)?|last\s+(chance|warning|reminder))\b",
            r"\b(final|last)\s+(notice|warning|reminder)\b",
            r"\bwithin\s+\d+\s+(hour|minute|day)s?\b",
            r"\b(time[\s\-]sensitive|limited[\s\-]time|expires?\s+(today|soon|in\s+\d))\b",
            r"\b(deadline|due\s+date)\s+(is|today|tomorrow)\b",
            r"\b(don'?t|do\s+not)\s+(ignore|delay|miss)\b",
        ],
    },
    "threat": {
        "weight": 15,
        "severity": "high",
        "label": "Threat language",
        "patterns": [
            r"\blegal\s+(action|consequences|proceedings|notice)\b",
            r"\b(warrant|arrest|lawsuit|subpoena|prosecution|criminal\s+charges?)\b",
            r"\b(account|access|service)\s+(will\s+be|has\s+been)\s+(suspended|terminated|closed|blocked|frozen|disabled|deactivated)\b",
            r"\b(data|information|details|files?)\s+(will\s+be\s+)?(leaked|published|exposed|released|disclosed)\b",
            r"\breport(ed)?\s+to\s+(authorities|police|ftc|bir|irs|sec|nbi)\b",
            r"\b(face|facing)\s+(legal|criminal|civil)\s+(action|consequences|charges)\b",
        ],
    },
    "authority_impersonation": {
        "weight": 12,
        "severity": "medium",
        "label": "Authority impersonation",
        "patterns": [
            r"\b(IRS|Internal\s+Revenue\s+Service|BIR|Bureau\s+of\s+Internal\s+Revenue|HMRC|tax\s+(refund|authority|office|department))\b",
            r"\b(Microsoft|Apple|Google|Amazon|Norton|McAfee|Adobe)\s+(Support|Security|Account\s+Team|Helpdesk)\b",
            r"\b(DHL|FedEx|UPS|USPS|PhilPost|LBC|J&T|2GO|Ninja\s+Van)\s+(notification|delivery|customs|pending|shipment)\b",
            r"\b(GCash|Maya|PayMaya|BDO|BPI|Metrobank|UnionBank|RCBC|PNB|EastWest|Landbank|Security\s+Bank)\s+(security|verification|account)\b",
            r"\b(PayPal|Visa|MasterCard|Bank\s+of\s+America|Chase|Wells\s+Fargo|HSBC|Citibank|Barclays)\s+(security|account|fraud|verification)\b",
            r"\b(SSS|GSIS|PhilHealth|Pag-?IBIG|DSWD|COMELEC|LTO|BI)\s+(notice|notification|verification)\b",
        ],
    },
    "financial_lure": {
        "weight": 18,
        "severity": "high",
        "label": "Financial lure",
        "patterns": [
            r"\bcongratulations[!\s]+you('?ve?|\s+have)\s+(won|been\s+selected|been\s+chosen)\b",
            r"\b(lottery|jackpot|prize|raffle|sweepstakes|draw)\s+(winner|claim|won)\b",
            r"\b(inheritance|will|estate|beneficiary)\s+(of|from|left|worth)\b",
            r"\b(refund|rebate|reimbursement|compensation)\s+(of|pending|approved|available|due)\s*[\$€£]?\s*[\d,]+",
            r"\b(unclaimed|dormant|abandoned)\s+(funds|account|money|deposit|estate)\b",
            r"\b(\d+(?:\.\d+)?)\s+(million|billion)\s+(dollars|USD|EUR|GBP|pounds|euros)\b",
            r"\b(easy|quick|fast)\s+(money|cash|income|earn)\s+(opportunity|from\s+home)\b",
        ],
    },
    "credential_phishing": {
        "weight": 20,
        "severity": "high",
        "label": "Credential phishing language",
        "patterns": [
            r"\b(verify|confirm|update|validate|secure)\s+(your\s+)?(account|password|identity|credentials|details|information|profile)\b",
            r"\b(re|sign)[\-\s]?(in|enter)\s+(your\s+)?(password|credentials|account)\b",
            r"\b(click\s+(here|below|the\s+link|the\s+button))\s+to\s+(login|verify|confirm|access|continue|view|unlock|reactivate)\b",
            r"\bsuspicious\s+(login|activity|access|sign[\-\s]?in|attempt)\s+(was\s+)?(attempt|detected|noticed|observed)\b",
            r"\b(reset|change|update)\s+(your\s+)?password\s+(now|immediately|to\s+continue|here)\b",
            r"\b(unusual|new\s+device)\s+(sign[\-\s]?in|login|access)\b",
        ],
    },
    "crypto_scam": {
        "weight": 22,
        "severity": "high",
        "label": "Crypto scam indicators",
        "patterns": [
            r"\b(investment|trading|earning)\s+(opportunity|platform|signal|bot|club|circle)\b",
            r"\b(guaranteed|risk[\-\s]?free|sure|certain)\s+(returns?|profit|investment|growth)\b",
            r"\b(\d+x|\d+%\s+(daily|weekly|monthly|guaranteed))\s+(return|profit|gain|roi)",
            r"\b(double|triple|multiply|10x|100x)\s+your\s+(bitcoin|crypto|investment|money|btc|eth)\b",
            r"\b(elon\s+musk|elon|tesla|spacex)\s+(gives\s+away|giveaway|crypto|btc)\b",
            r"\bsend\s+(0?\.\d+|\d+)\s+(BTC|ETH|USDT|crypto)\s+(to|and\s+receive|wallet)\b",
            r"\b(presale|ico|defi|yield\s+farming|liquidity\s+pool)\s+(opportunity|invitation|whitelist)\b",
        ],
    },
    "romance": {
        "weight": 25,
        "severity": "high",
        "label": "Romance / pig butchering",
        "patterns": [
            r"\b(love|miss|need|adore|cherish)\s+you\s+(so\s+much|deeply|already|terribly)\b",
            r"\b(my\s+(uncle|aunt|cousin|friend))\s+(taught|told|showed)\s+me\s+(about|how\s+to)\s+(invest|trade)\b",
            r"\b(special|crypto|investment)\s+(opportunity|platform|tip)\s+(only|just)\s+for\s+(you|us|insiders)\b",
            r"\b(my\s+(heart|destiny|fate|soul))\s+(brought|told|led)\s+(us|me)\b",
            r"\b(stuck|abandoned|stranded)\s+(at|in)\s+(airport|customs|hospital|hotel)\b.{0,120}\b(send|wire|transfer|help|money|funds)\b",
            r"\b(when|until)\s+(we|i)\s+(meet|see)\s+(in\s+person|each\s+other)\b.{0,80}\b(invest|trade|business)\b",
        ],
    },
    "invoice_wire_fraud": {
        "weight": 30,
        "severity": "high",
        "label": "Invoice / wire fraud (BEC)",
        "patterns": [
            r"\b(change|update|new|revised)\s+(of\s+)?(bank|payment|wire|account|banking)\s+(details|instructions|information|account)\b",
            r"\b(updated|new|revised)\s+(invoice|payment|wire|banking)\s+(instructions|details|routing)\b",
            r"\b(routing|swift|iban|account)\s+(number|code|details)\s+(has\s+|have\s+)?(changed|been\s+updated|is\s+different|updated)\b",
            r"\b(use\s+(this|the\s+following|the\s+new))\s+(account|wire|payment|banking)\s+(details|instructions)\b",
            r"\bplease\s+(transfer|wire|send|remit|pay)\s+(the|this|payment)\b.{0,80}\b(today|asap|immediately|by\s+(end\s+of\s+day|eod|cob))\b",
            r"\b(for\s+security\s+reasons|due\s+to\s+(audit|policy))\s+(we|please)\s+(have\s+)?(changed|updated|use)\b",
        ],
    },
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "t.co",
    "rebrand.ly", "cutt.ly", "short.io", "tiny.cc", "shorturl.at",
    "bitly.com", "rb.gy", "shorturl.com", "buff.ly", "lnkd.in",
    "trib.al", "v.gd", "shrtco.de", "1url.com", "soo.gd",
}

SUSPICIOUS_ATTACHMENT_EXT = {
    ".scr", ".lnk", ".iso", ".img", ".vbs", ".js", ".jse", ".wsf",
    ".bat", ".cmd", ".com", ".exe", ".hta", ".pif", ".cpl",
    ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm",
}


class HeaderAnalyzeRequest(BaseModel):
    raw_header: str
    raw_body: str | None = None


def _init_cache():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS email_header_cache (
            id TEXT PRIMARY KEY,
            response_json TEXT NOT NULL,
            fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS llm_rate_limit (
            source_ip TEXT NOT NULL,
            called_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_rate_ip ON llm_rate_limit(source_ip, called_at)")
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

# ---------- body parsing helpers ----------

URL_BODY_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
IP_URL_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.IGNORECASE)
BTC_RE = re.compile(r"\b(bc1[a-zA-Z0-9]{25,90}|[13][a-zA-Z0-9]{25,40})\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TRX_RE = re.compile(r"\bT[A-Za-z1-9]{33}\b")
ATTACH_MENTION_RE = re.compile(
    r"([A-Za-z0-9_\-]{2,40}\.(?:scr|lnk|iso|img|vbs|jse?|wsf|bat|cmd|exe|hta|pif|cpl|docm|dotm|xlsm|xltm|pptm|potm|zip|rar|7z))\b",
    re.IGNORECASE,
)


class _AnchorExtractor(_HTMLParser):
    """Extracts <a href=...>display text</a> pairs from HTML body."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.anchors: list[dict] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            attrs_dict = {k.lower(): v for k, v in attrs}
            self._current_href = attrs_dict.get("href", "")
            self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current_href is not None:
            text = "".join(self._current_text).strip()
            self.anchors.append({"href": self._current_href, "text": text})
            self._current_href = None
            self._current_text = []


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


# ---------- body analysis ----------

def _looks_like_html(body: str) -> bool:
    lower = body[:2000].lower()
    return any(marker in lower for marker in ("<html", "<a href", "<body", "<table", "<div"))


def _detect_homoglyphs(text: str) -> list[str]:
    findings = []
    for word in re.findall(r"[A-Za-zЀ-ӿͰ-Ͽ]{4,}", text):
        has_latin = any("a" <= c.lower() <= "z" for c in word)
        has_cyrillic = any("Ѐ" <= c <= "ӿ" for c in word)
        has_greek = any("Ͱ" <= c <= "Ͽ" for c in word)
        if has_latin and (has_cyrillic or has_greek):
            findings.append(word)
    return findings[:5]


def _analyze_urls_in_body(body: str) -> dict:
    findings = []
    all_urls = list(set(URL_BODY_RE.findall(body)))

    for url in all_urls:
        if IP_URL_RE.match(url):
            findings.append({
                "severity": "medium",
                "category": "url_deception",
                "name": "IP-based URL",
                "detail": f"Direct IP link (no domain): {url[:80]}",
            })

    for url in all_urls:
        m = re.match(r"https?://([^/\s]+)", url)
        if m and m.group(1).lower() in SHORTENER_DOMAINS:
            findings.append({
                "severity": "medium",
                "category": "url_deception",
                "name": "URL shortener",
                "detail": f"Hidden destination via {m.group(1)}: {url[:80]}",
            })

    if _looks_like_html(body):
        try:
            parser = _AnchorExtractor()
            parser.feed(body)
            for anchor in parser.anchors:
                href = anchor["href"] or ""
                text = anchor["text"] or ""
                if not href or not text:
                    continue
                text_url_match = re.search(r"https?://([^/\s]+)", text)
                href_url_match = re.search(r"https?://([^/\s]+)", href)
                if text_url_match and href_url_match:
                    text_domain = text_url_match.group(1).lower()
                    href_domain = href_url_match.group(1).lower()
                    if text_domain != href_domain:
                        findings.append({
                            "severity": "high",
                            "category": "url_deception",
                            "name": "Display URL mismatches actual link",
                            "detail": f"Shows: {text[:60]} -> Goes to: {href[:60]}",
                        })
                elif text and not text.startswith("http"):
                    if any(word in text.lower() for word in ("click", "login", "verify", "secure", "account")):
                        findings.append({
                            "severity": "medium",
                            "category": "url_deception",
                            "name": "Action-word link",
                            "detail": f"'{text[:50]}' -> {href[:60]}",
                        })
        except Exception:
            pass

    return {"findings": findings, "urls": all_urls[:30]}


def _analyze_body(body: str, from_addrs: list[dict]) -> dict:
    if not body or not body.strip():
        return {
            "findings": [], "category_hits": {}, "score_delta": 0,
            "urls": [], "crypto_addresses": [], "attachment_mentions": [],
        }

    findings = []
    category_hits = {}

    text_only = re.sub(r"<[^>]+>", " ", body)
    text_only = re.sub(r"\s+", " ", text_only)
    text_only = text_only.replace("=20", " ").replace("=3D", "=").replace("=0A", " ")

    body_truncated = len(text_only) > REGEX_MAX_BODY_BYTES
    text_only = text_only[:REGEX_MAX_BODY_BYTES]

    for category, cfg in SCAM_PATTERNS.items():
        for pat in cfg["patterns"]:
            try:
                m = re.search(pat, text_only, re.IGNORECASE)
                if m:
                    category_hits[category] = cfg["weight"]
                    findings.append({
                        "severity": cfg["severity"],
                        "category": category,
                        "name": cfg["label"],
                        "detail": f"Match: '{m.group(0)[:80]}'",
                    })
                    break
            except re.error:
                continue

    url_result = _analyze_urls_in_body(body)
    findings.extend(url_result["findings"])
    if url_result["findings"]:
        category_hits["url_deception"] = 15

    crypto_addresses = []
    for addr in BTC_RE.findall(text_only):
        crypto_addresses.append({"type": "BTC", "address": addr})
    for addr in ETH_RE.findall(text_only):
        crypto_addresses.append({"type": "ETH", "address": addr})
    for addr in TRX_RE.findall(text_only):
        crypto_addresses.append({"type": "TRX", "address": addr})
    if crypto_addresses:
        findings.append({
            "severity": "high",
            "category": "crypto_address_in_body",
            "name": "Crypto wallet address in body",
            "detail": f"{len(crypto_addresses)} address(es) found - common scam payment vector",
        })
        category_hits["crypto_address_in_body"] = 15

    attachments_mentioned = []
    for m in ATTACH_MENTION_RE.finditer(text_only):
        fname = m.group(1)
        ext = "." + fname.rsplit(".", 1)[-1].lower()
        if ext in SUSPICIOUS_ATTACHMENT_EXT:
            attachments_mentioned.append({"filename": fname, "ext": ext})
    if attachments_mentioned:
        findings.append({
            "severity": "high",
            "category": "suspicious_attachment",
            "name": "Suspicious attachment referenced",
            "detail": f"Files: {', '.join(a['filename'] for a in attachments_mentioned[:3])}",
        })
        category_hits["suspicious_attachment"] = 20

    reply_match = re.search(
        r"\b(reply\s+to|send\s+(?:your\s+)?(?:reply|response)\s+to|contact\s+(?:me|us)\s+at)\s+([\w.\-]+@[\w.\-]+\.\w+)",
        text_only, re.IGNORECASE,
    )
    if reply_match and from_addrs:
        suggested_email = reply_match.group(2).lower()
        from_email = (from_addrs[0].get("email") or "").lower()
        if suggested_email and from_email and suggested_email != from_email:
            findings.append({
                "severity": "high",
                "category": "reply_trap",
                "name": "Reply trap",
                "detail": f"Body asks reply to {suggested_email} (From is {from_email})",
            })
            category_hits["reply_trap"] = 20

    homoglyphs = _detect_homoglyphs(text_only)
    if homoglyphs:
        findings.append({
            "severity": "medium",
            "category": "homoglyph",
            "name": "Unicode homoglyph in body text",
            "detail": f"Mixed-script words: {', '.join(homoglyphs[:3])}",
        })
        category_hits["homoglyph"] = 10

    score_delta = sum(category_hits.values())

    return {
        "findings": findings,
        "category_hits": category_hits,
        "score_delta": score_delta,
        "urls": url_result["urls"],
        "crypto_addresses": crypto_addresses,
        "attachment_mentions": attachments_mentioned,
        "body_truncated": body_truncated,
    }


# ---------- Email file parser ----------

def _parse_email_file(file_bytes: bytes, filename: str) -> tuple[str, str]:
    """
    Parse an uploaded email file and return (raw_header, raw_body).

    Supports .eml / .txt (RFC 822 MIME) and .msg (Outlook binary).
    Processed entirely in memory; .msg uses a tempfile that is deleted immediately
    after parsing, even if an exception is raised. Returns (header_text, body_text).
    Raises ValueError on unsupported or malformed content.
    """
    lower_name = (filename or "").lower()

    if lower_name.endswith(".eml") or lower_name.endswith(".txt"):
        try:
            text = file_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            raise ValueError(f"Could not decode .eml file: {e}")

        if "\r\n\r\n" in text:
            header_part, body_part = text.split("\r\n\r\n", 1)
        elif "\n\n" in text:
            header_part, body_part = text.split("\n\n", 1)
        else:
            header_part = text
            body_part = ""
        return header_part, body_part

    if lower_name.endswith(".msg"):
        try:
            import extract_msg
        except ImportError:
            raise ValueError(".msg support requires extract-msg package. Contact the operator.")

        with tempfile.NamedTemporaryFile(suffix=".msg", delete=True) as tmp:
            tmp.write(file_bytes)
            tmp.flush()
            try:
                msg = extract_msg.Message(tmp.name)
            except Exception as e:
                raise ValueError(f"Could not parse .msg file: {e}")

            try:
                header_lines = []
                if msg.header:
                    header_lines.append(str(msg.header))
                else:
                    if msg.sender:
                        header_lines.append(f"From: {msg.sender}")
                    if msg.to:
                        header_lines.append(f"To: {msg.to}")
                    if msg.cc:
                        header_lines.append(f"Cc: {msg.cc}")
                    if msg.subject:
                        header_lines.append(f"Subject: {msg.subject}")
                    if msg.date:
                        header_lines.append(f"Date: {msg.date}")
                    if msg.messageId:
                        header_lines.append(f"Message-ID: {msg.messageId}")

                header_text = "\n".join(header_lines)

                body_text = ""
                if msg.htmlBody:
                    body_text = msg.htmlBody if isinstance(msg.htmlBody, str) else msg.htmlBody.decode("utf-8", errors="replace")
                elif msg.body:
                    body_text = msg.body

                return header_text, body_text
            finally:
                try:
                    msg.close()
                except Exception:
                    pass

    raise ValueError(f"Unsupported file type: {filename}. Supported formats: .eml, .msg, .txt")


# ---------- LLM rate limiting ----------

def _check_llm_rate_limit(source_ip: str) -> tuple[bool, int]:
    """Returns (allowed, calls_used_in_window)."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "SELECT COUNT(*) FROM llm_rate_limit WHERE source_ip = ? AND called_at > datetime('now', '-24 hours')",
        (source_ip,),
    )
    count = cur.fetchone()[0]
    conn.close()
    return (count < LLM_RATE_LIMIT_PER_DAY, count)


def _record_llm_call(source_ip: str):
    """Insert a tracking row and clean up rows older than 48 hours."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO llm_rate_limit (source_ip) VALUES (?)", (source_ip,))
        conn.execute("DELETE FROM llm_rate_limit WHERE called_at < datetime('now', '-48 hours')")
        conn.commit()
        conn.close()
    except Exception as exc:
        log.error("Failed to write llm_rate_limit row for ip=%s: %s", source_ip, exc)


# ---------- LLM body analyzer ----------

LLM_SYSTEM_PROMPT = """You are an email security analyst specializing in scam, phishing, and BEC detection.

You will be given the body of an email (header data is analyzed separately and combined with your assessment).

Analyze the body for scam indicators. Look for:

1. Advance fee fraud: any scheme where the recipient is asked to pay a fee, tax, processing charge, application fee, evaluation fee, customs charge, lawyer fee, or any other upfront cost to receive a larger sum
2. Inheritance / lottery / compensation scams: claims of unclaimed funds, lottery wins, inheritance from a stranger, government compensation programs, UN/IMF/World Bank disbursements
3. Authority impersonation: pretending to be IRS, BIR, Microsoft Support, banks, shipping companies, government agencies, the United Nations
4. Romance / pig butchering: love bombing combined with investment opportunities or requests for money transfers
5. BEC / wire fraud: requests to change bank account details, urgent wire transfers, payment instruction updates, vendor account changes
6. Credential phishing: requests to verify accounts, click suspicious links, reset passwords, urgent account warnings
7. Crypto scams: guaranteed returns, giveaway promises, double-your-Bitcoin schemes, wallet recovery scams
8. Tech support scams: claims your computer is infected, security alerts, fake virus warnings
9. PII harvesting: requests for full name + phone + address + ID combined together
10. Reply traps: body asks reader to reply to or contact a different email/phone than the From address
11. Urgency manipulation: artificial deadlines, threats of account closure, "act now" language
12. Suspicious narrative inconsistencies: foreign-claimed sender writing in broken English, story shifts mid-email, signature does not match sender

Return ONLY valid JSON in this exact schema, no markdown, no preamble:

{
  "scam_score": <integer 0-100, where 0 = clearly legitimate, 100 = textbook scam>,
  "verdict": "<one of: clearly_legitimate, likely_legitimate, suspicious, likely_scam, textbook_scam>",
  "scam_type": "<short label like 'advance fee fraud', 'BEC wire fraud', 'crypto giveaway scam', 'credential phishing', 'legitimate', etc.>",
  "confidence": "<low|medium|high>",
  "findings": [
    {
      "severity": "<high|medium|low|info>",
      "category": "<short category label>",
      "name": "<short finding name>",
      "evidence": "<exact quoted sentence or phrase from the body that triggered this finding, max 200 chars>"
    }
  ],
  "summary": "<one-sentence explanation of your overall verdict>"
}

Be strict but fair. A clean transactional email (receipt, calendar invite, newsletter) should score 0-10. A suspicious one with one or two indicators should score 20-50. A clear scam with multiple obvious indicators (e.g. UN compensation + advance fee + reply trap + PII harvest) should score 90-100. Maximum 8 findings.
"""


async def _llm_analyze_body(body: str, sender_email: str = "") -> dict | None:
    """
    Run Claude Haiku 4.5 against the body. Returns None on any failure.

    Hard preconditions enforced inside this function (defense in depth, do not remove):
      - LLM_ANALYSIS_ENABLED must be True
      - ANTHROPIC_API_KEY must be set
      - body must be non-empty and at least LLM_MIN_BODY_CHARS after HTML stripping
      - estimated token count must not exceed LLM_MAX_BODY_TOKENS
    """
    # ===== HARDCODED MODEL: do NOT replace with a config variable =====
    # This is intentional. Even if config is misconfigured, this function
    # only ever calls Claude Haiku 4.5. To change the model, edit this line directly.
    HARDCODED_MODEL = "claude-haiku-4-5"
    # ==================================================================

    if not LLM_ANALYSIS_ENABLED:
        return None

    if not ANTHROPIC_API_KEY:
        log.warning("LLM analysis enabled but ANTHROPIC_API_KEY not set")
        return None

    if not body:
        return None

    text_only = re.sub(r"<[^>]+>", " ", body)
    text_only = re.sub(r"\s+", " ", text_only).strip()

    if len(text_only) < LLM_MIN_BODY_CHARS:
        return None

    estimated_tokens = len(text_only) // 4
    if estimated_tokens > LLM_MAX_BODY_TOKENS:
        log.info(f"Body too large for LLM analysis ({estimated_tokens} est tokens), skipping")
        return None

    text_only = text_only[:30000]

    user_msg = f"Sender (From header): {sender_email}\n\nEmail body to analyze:\n\n{text_only}"

    client = AsyncAnthropic(api_key=ANTHROPIC_API_KEY, timeout=LLM_TIMEOUT_SECONDS)

    try:
        response = await client.messages.create(
            model=HARDCODED_MODEL,
            max_tokens=1500,
            system=[
                {
                    "type": "text",
                    "text": LLM_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user_msg}],
        )
    except APITimeoutError:
        log.warning("LLM call timed out")
        return None
    except APIStatusError as e:
        log.warning(f"LLM API status error: {e.status_code} {e.message}")
        return None
    except APIError as e:
        log.warning(f"LLM API error: {e}")
        return None
    except Exception as e:
        log.warning(f"LLM call exception: {type(e).__name__}: {e}")
        return None

    actual_model = getattr(response, "model", "")
    if HARDCODED_MODEL not in actual_model:
        log.warning(f"Response model mismatch: expected {HARDCODED_MODEL}, got {actual_model}")

    raw_text = ""
    try:
        for block in response.content:
            if getattr(block, "type", None) == "text":
                raw_text += block.text

        raw_text = raw_text.strip()
        if raw_text.startswith("```"):
            raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text)
            raw_text = re.sub(r"\s*```$", "", raw_text)

        parsed = json.loads(raw_text)
        parsed["_usage"] = {
            "model": actual_model,
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "cache_read_input_tokens": getattr(response.usage, "cache_read_input_tokens", 0),
            "cache_creation_input_tokens": getattr(response.usage, "cache_creation_input_tokens", 0),
        }
        return parsed
    except (json.JSONDecodeError, AttributeError) as e:
        log.warning(f"LLM returned non-JSON: {raw_text[:200]}... ({e})")
        return None


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
async def analyze(req: HeaderAnalyzeRequest, request: Request):
    raw = req.raw_header.strip()
    body_input = (req.raw_body or "").strip()

    if not raw:
        raise HTTPException(status_code=400, detail="empty header input")
    if len(raw) > 200000:
        raise HTTPException(status_code=400, detail="header too large (max 200KB)")
    if len(body_input) > 500000:
        raise HTTPException(status_code=400, detail="body too large (max 500KB)")

    cache_key_source = raw + "\n\n----BODY----\n\n" + body_input
    header_id = _hash_header(cache_key_source)

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

    # Determine body to analyze: explicit input > auto-extracted from full email paste
    body_to_analyze = body_input
    if not body_to_analyze:
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    if ctype in ("text/html", "text/plain"):
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            body_to_analyze = payload.decode(charset, errors="replace")
                            if ctype == "text/html":
                                break
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_to_analyze = payload.decode(errors="replace")
        except Exception:
            body_to_analyze = ""

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
        spf_task = _lookup_spf(from_domain)
        dmarc_task = _lookup_dmarc(from_domain)
        spf_lookup, dmarc_lookup = await asyncio.gather(spf_task, dmarc_task)
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

    # Regex body analysis (always runs, free, no preconditions other than body presence)
    body_provided = bool(body_to_analyze and body_to_analyze.strip())
    body_analysis = _analyze_body(body_to_analyze, parsed["from"]) if body_provided else None
    parsed["body_analysis"] = body_analysis
    parsed["body_provided"] = body_provided
    parsed["body_regex_truncated"] = body_analysis.get("body_truncated", False) if body_analysis else False

    parsed["bec_assessment"] = _score_bec_indicators(parsed)
    if body_analysis:
        parsed["bec_assessment"]["score"] = min(
            100, parsed["bec_assessment"]["score"] + body_analysis["score_delta"]
        )
        parsed["bec_assessment"]["indicators"].extend(body_analysis["findings"])
        score = parsed["bec_assessment"]["score"]
        if score >= 70:
            parsed["bec_assessment"]["verdict"] = "high_risk"
        elif score >= 40:
            parsed["bec_assessment"]["verdict"] = "medium_risk"
        elif score >= 20:
            parsed["bec_assessment"]["verdict"] = "low_risk_with_indicators"
        else:
            parsed["bec_assessment"]["verdict"] = "low_risk"

    # LLM body analysis: ONLY runs if body is provided
    llm_analysis = None
    if body_provided and LLM_ANALYSIS_ENABLED and ANTHROPIC_API_KEY:
        source_ip = get_client_ip(request) if request else "unknown"
        allowed, calls_used = _check_llm_rate_limit(source_ip)
        if allowed:
            sender_email = parsed["from"][0]["email"] if parsed["from"] else ""
            llm_analysis = await _llm_analyze_body(body_to_analyze, sender_email)
            if llm_analysis:
                _record_llm_call(source_ip)
        else:
            llm_analysis = {
                "rate_limited": True,
                "message": f"LLM analysis daily limit reached for this IP ({calls_used}/{LLM_RATE_LIMIT_PER_DAY} per 24 hours). Regex analysis still applied.",
            }
    parsed["llm_analysis"] = llm_analysis

    # Merge LLM verdict into BEC score
    if llm_analysis and not llm_analysis.get("rate_limited"):
        llm_score = clamp_int(llm_analysis.get("scam_score"), 0, 100, default=0)
        current_score = parsed["bec_assessment"]["score"]
        new_score = max(current_score, llm_score)
        parsed["bec_assessment"]["score"] = new_score

        for finding in validate_findings_list(llm_analysis.get("findings")):
            parsed["bec_assessment"]["indicators"].append({
                "severity": safe_str(finding.get("severity"), 20, "medium"),
                "name": f"[LLM] {safe_str(finding.get('name'), 100, 'Detection')}",
                "detail": safe_str(finding.get("evidence"), 200, ""),
            })

        score = parsed["bec_assessment"]["score"]
        if score >= 70:
            parsed["bec_assessment"]["verdict"] = "high_risk"
        elif score >= 40:
            parsed["bec_assessment"]["verdict"] = "medium_risk"
        elif score >= 20:
            parsed["bec_assessment"]["verdict"] = "low_risk_with_indicators"
        else:
            parsed["bec_assessment"]["verdict"] = "low_risk"

        parsed["bec_assessment"]["llm_verdict"] = safe_str(llm_analysis.get("verdict"), 100, "unknown")
        parsed["bec_assessment"]["llm_scam_type"] = safe_str(llm_analysis.get("scam_type"), 100, "")
        parsed["bec_assessment"]["llm_summary"] = safe_str(llm_analysis.get("summary"), 500, "")
        parsed["bec_assessment"]["llm_note"] = (
            "llm_verdict, llm_scam_type, and llm_summary are Claude Haiku 4.5 model opinions, not verified verdicts."
        )

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


@router.post("/api/email-header/upload")
async def upload(file: UploadFile = File(...)):
    """
    Parse an uploaded .eml or .msg file and return header + body as text.

    The file is processed in memory and discarded immediately after parsing.
    Nothing is written to persistent storage; the bytes buffer is zeroed in
    the finally block. The caller submits the returned text to /analyze normally.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="no filename provided")

    MAX_UPLOAD_BYTES = 5 * 1024 * 1024
    file_bytes = await file.read()
    try:
        if len(file_bytes) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=400,
                detail=f"file too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)}MB)",
            )
        if len(file_bytes) < 50:
            raise HTTPException(status_code=400, detail="file too small to be a valid email")

        try:
            header_text, body_text = _parse_email_file(file_bytes, file.filename)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            log.warning(f"Email file upload parse exception ({file.filename}, {len(file_bytes)} bytes): {type(e).__name__}: {e}")
            raise HTTPException(status_code=400, detail="failed to parse email file")

        return {
            "filename": file.filename,
            "raw_header": header_text,
            "raw_body": body_text,
            "header_bytes": len(header_text),
            "body_bytes": len(body_text),
        }
    finally:
        file_bytes = b""
