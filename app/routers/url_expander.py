"""
URL Expander + Redirect Chain Analyzer.

Follows a user-supplied URL hop-by-hop, re-validating SSRF safety at every hop
via the shared app.utils.safe_fetch primitives (do NOT introduce a second SSRF
guard — resolve_and_check / is_private_ip are the single source of truth). For
each hop it records status, TLS certificate details (HTTPS), headers of interest,
and timing, then computes shortener / TLD-switch / punycode / port signals.

Screenshot capture is intentionally not wired in this build: Playwright is not
installed on the host, so the screenshot field always degrades gracefully. A
later release can add a hardened (private-range-blocking) browser capture.
"""
import logging
import re
import socket
import sqlite3
import ssl
import time
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from slowapi import Limiter

from app.config import DB_PATH, HTTPX_TIMEOUT, URL_EXPAND_RATE_LIMIT_PER_DAY
from app.utils.client_ip import get_client_ip, get_client_ip_key
from app.utils.safe_fetch import SafeFetchError, pinned_request, resolve_pinned

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/url", tags=["url_expander"])
limiter = Limiter(key_func=get_client_ip_key)

USER_AGENT = "FalconEye/3.6.0 (+https://falconeye.osintph.info)"
MAX_URL_LENGTH = 2048
DEFAULT_MAX_HOPS = 10

# Known URL shorteners (case-insensitive exact hostname match). Used only to
# compute a signal; not a block list.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "cutt.ly", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "tiny.cc", "shorturl.at", "x.co", "mcaf.ee",
    "po.st", "adf.ly", "bl.ink", "s.id", "lnkd.in", "fb.me", "ift.tt", "ph.link",
}

_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\']?\s*\d+\s*;\s*url=([^"\'>\s]+)',
    re.IGNORECASE,
)


# ---------- rate limit (10 / IP / 24h, mirrors dork_generator pattern) ----------

def _init_rl():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS url_expand_rate_limit (
            source_ip TEXT NOT NULL,
            called_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_url_expand_rate_ip ON url_expand_rate_limit(source_ip, called_at)"
    )
    conn.commit()
    conn.close()


_init_rl()


def _check_rate_limit(source_ip: str) -> tuple[bool, int]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "SELECT COUNT(*) FROM url_expand_rate_limit WHERE source_ip = ? AND called_at > datetime('now', '-24 hours')",
        (source_ip,),
    )
    count = cur.fetchone()[0]
    conn.close()
    return (count < URL_EXPAND_RATE_LIMIT_PER_DAY, count)


def _record_call(source_ip: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO url_expand_rate_limit (source_ip) VALUES (?)", (source_ip,))
        conn.execute("DELETE FROM url_expand_rate_limit WHERE called_at < datetime('now', '-48 hours')")
        conn.commit()
        conn.close()
    except Exception as exc:
        log.error("Failed to write url_expand_rate_limit row for ip=%s: %s", source_ip, exc)


# ---------- helpers ----------

def _grab_tls(host: str, port: int, pinned_ip: str) -> dict | None:
    """Best-effort TLS peer-cert summary for an HTTPS hop.

    Connects to *pinned_ip* — the same validated IP the HTTP fetch is pinned to
    (resolved once by resolve_pinned) — so the cert grab and the fetch hit the
    same host, and neither can be pointed at a private address. The cert is
    verified against the original hostname (invalid/self-signed -> returns None
    rather than trusting it).
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((pinned_ip, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
    except Exception:
        return None
    if not cert:
        return None

    def _flatten(rdns) -> dict:
        out: dict = {}
        for rdn in rdns or ():
            for key, value in rdn:
                out.setdefault(key, value)
        return out

    subject = _flatten(cert.get("subject"))
    issuer = _flatten(cert.get("issuer"))
    sans = [value for (typ, value) in cert.get("subjectAltName", ()) if typ == "DNS"][:10]
    return {
        "issuer": issuer.get("commonName") or issuer.get("organizationName"),
        "subject": subject.get("commonName"),
        "valid_from": cert.get("notBefore"),
        "valid_to": cert.get("notAfter"),
        "san": sans,
    }


def _parse_meta_refresh(html: str, base_url: str) -> str | None:
    match = _META_REFRESH_RE.search(html or "")
    if not match:
        return None
    return urljoin(base_url, match.group(1).strip())


def _tld(host: str) -> str:
    host = (host or "").lower().rstrip(".")
    return host.rsplit(".", 1)[-1] if "." in host else host


def _compute_signals(chain: list[dict], final_url: str) -> dict:
    hosts = []
    for hop in chain:
        h = (urlparse(hop["url"]).hostname or "").lower().rstrip(".")
        if h:
            hosts.append(h)

    shortener_depth = sum(1 for h in hosts if h in SHORTENERS)

    tlds = [_tld(h) for h in hosts]
    tld_switches = sum(1 for a, b in zip(tlds, tlds[1:]) if a != b)

    suspicious_ports = False
    for hop in chain:
        port = urlparse(hop["url"]).port
        if port is not None and port not in (80, 443):
            suspicious_ports = True
            break

    final_host = (urlparse(final_url).hostname or "").lower().rstrip(".")
    return {
        "shortener_chain_depth": shortener_depth,
        "tld_switches": tld_switches,
        "final_tld": _tld(final_host),
        "final_is_punycode": "xn--" in final_host,
        "suspicious_ports": suspicious_ports,
    }


def _screenshot_unavailable() -> dict:
    return {
        "available": False,
        "data_uri": None,
        "reason": "Screenshot unavailable: Playwright not installed on this host",
    }


async def expand_url(url: str, max_hops: int = DEFAULT_MAX_HOPS) -> dict:
    original = url
    current = url
    final = url
    chain: list[dict] = []
    blocked_at_hop: int | None = None
    blocked_reason: str | None = None
    meta_refresh_used = False

    async with httpx.AsyncClient(follow_redirects=False, verify=True, timeout=HTTPX_TIMEOUT) as client:
        hop_num = 0
        while hop_num < max_hops:
            hop_num += 1

            # Resolve + SSRF-validate + pin ONCE per hop. resolve_pinned raises
            # (fail closed) on a bad scheme, embedded userinfo, a missing/private
            # host, or an unresolvable name — so a redirect to an internal IP is
            # caught here exactly like the initial URL.
            try:
                conn = resolve_pinned(current)
            except SafeFetchError as exc:
                blocked_at_hop = hop_num
                blocked_reason = str(exc)
                break

            host = conn.host
            port = conn.port
            # Pin the cert grab to the same validated IP the fetch will use.
            tls = _grab_tls(host, port, conn.ips[0]) if conn.scheme == "https" else None

            start = time.monotonic()
            try:
                resp = await pinned_request(
                    client, "GET", current, headers={"User-Agent": USER_AGENT}, conn=conn
                )
            except httpx.TimeoutException:
                chain.append({
                    "hop": hop_num, "url": current, "status": 0, "tls": tls,
                    "server": None, "content_type": None, "location": None,
                    "elapsed_ms": int((time.monotonic() - start) * 1000),
                    "error": "request timed out",
                })
                break
            except Exception as exc:
                chain.append({
                    "hop": hop_num, "url": current, "status": 0, "tls": tls,
                    "server": None, "content_type": None, "location": None,
                    "elapsed_ms": int((time.monotonic() - start) * 1000),
                    "error": f"fetch error: {type(exc).__name__}",
                })
                break
            elapsed_ms = int((time.monotonic() - start) * 1000)

            location = resp.headers.get("location", "").strip() or None
            content_type = resp.headers.get("content-type")
            chain.append({
                "hop": hop_num,
                "url": current,
                "status": resp.status_code,
                "tls": tls,
                "server": resp.headers.get("server"),
                "content_type": content_type,
                "location": location,
                "elapsed_ms": elapsed_ms,
            })

            if resp.status_code in (301, 302, 303, 307, 308) and location:
                current = urljoin(current, location)
                final = current
                continue

            if content_type and "text/html" in content_type.lower() and not meta_refresh_used:
                meta_target = _parse_meta_refresh(resp.text, current)
                if meta_target:
                    meta_refresh_used = True
                    current = meta_target
                    final = current
                    continue

            # current is the hostname-based URL; resp.url is the internal IP-pinned
            # URL, so report current (what the user actually reached).
            final = current
            break

    return {
        "original": original,
        "final": final,
        "hop_count": len(chain),
        "chain": chain,
        "signals": _compute_signals(chain, final),
        "blocked_at_hop": blocked_at_hop,
        "blocked_reason": blocked_reason,
        "screenshot": _screenshot_unavailable(),
    }


# ---------- endpoint ----------

class ExpandRequest(BaseModel):
    url: str


@router.post("/expand")
@limiter.limit("10/minute")
async def expand(request: Request, payload: ExpandRequest):
    url = (payload.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="Provide a URL to expand.")
    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(status_code=400, detail=f"URL exceeds {MAX_URL_LENGTH} characters.")

    source_ip = get_client_ip(request)
    allowed, used = _check_rate_limit(source_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Daily limit reached ({used}/{URL_EXPAND_RATE_LIMIT_PER_DAY} URL expansions per 24 hours). Try again later.",
        )
    # Count the attempt (including SSRF-blocked ones) so the endpoint can't be
    # used as an unmetered probe of internal ranges.
    _record_call(source_ip)

    return await expand_url(url)
