"""Light active probe of one in-scope host, and the apex mail posture.

Per host: resolve (A, AAAA, CNAME, MX, NS, TXT), classify, then an HTTP/HTTPS
probe through safe_fetch, a TLS certificate grab, a header-based tech
fingerprint, and (only for the target's own infrastructure) a port scan.

Classification decides what is allowed, and it is enforced in operator mode too:
  own         the host resolves into the target's own infrastructure. Full probe
              plus port scan.
  cdn         the host sits behind a published CDN edge (by IP range or CNAME
              suffix). HTTP and TLS are probed (that is the target's own content),
              but the ports are the provider's, so it is never port scanned:
              "behind CDN, ports not scanned".
  reference   the host's CNAME points at a third-party service (SaaS) that is not
              the target. The CNAME target is recorded as a reference only and is
              never port scanned; the host itself is still fetched so a takeover
              of the target's own name can be detected.

Every outbound HTTP goes through safe_fetch, which validates and pins the
resolved public IP, so a host that resolves to a private or reserved address is
refused, not probed. No em dashes in this module.
"""
from __future__ import annotations

import asyncio
import logging
import re

import dns.resolver
import httpx

from app.asm import cdn, portscan
from app.routers.url_expander import _grab_tls
from app.scanner.scope import registrable
from app.utils.logsafe import tag
from app.utils.safe_fetch import SafeFetchError, resolve_and_check, safe_fetch

log = logging.getLogger("falconeye.asm.probe")

_UA = "FalconEye-ASM/3.37.0"
_HTTP_TIMEOUT = 10.0
_HTTP_MAX_BYTES = 300_000
_DNS_TIMEOUT = 5.0
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


def _resolve_sync(host: str) -> dict:
    out = {rt: [] for rt in _RECORD_TYPES}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = _DNS_TIMEOUT
    resolver.timeout = _DNS_TIMEOUT
    for rt in _RECORD_TYPES:
        try:
            for rdata in resolver.resolve(host, rt):
                out[rt].append(str(rdata).strip().rstrip(".").strip('"'))
        except Exception:
            continue
    return out


def _title(body: str) -> str:
    m = _TITLE_RE.search(body or "")
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:160]


def _fingerprint(headers: dict, body: str) -> list:
    tech = []
    hl = {k.lower(): str(v) for k, v in (headers or {}).items()}
    server = hl.get("server", "")
    powered = hl.get("x-powered-by", "")
    setck = hl.get("set-cookie", "")
    gen = ""
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body or "", re.IGNORECASE)
    if m:
        gen = m.group(1).strip()
    checks = [
        ("nginx", server, "nginx"), ("apache", server, "Apache"),
        ("cloudflare", server, "Cloudflare"), ("caddy", server, "Caddy"),
        ("litespeed", server, "LiteSpeed"), ("microsoft-iis", server, "IIS"),
        ("php", powered, "PHP"), ("express", powered, "Express"),
        ("asp.net", powered, "ASP.NET"), ("next.js", powered, "Next.js"),
        ("wordpress", (setck + " " + gen).lower(), "WordPress"),
        ("wp-", setck.lower(), "WordPress"), ("drupal", gen.lower(), "Drupal"),
        ("joomla", gen.lower(), "Joomla"), ("shopify", server.lower(), "Shopify"),
    ]
    for needle, haystack, label in checks:
        if needle in (haystack or "").lower() and label not in tech:
            tech.append(label)
    if gen and gen not in tech:
        tech.append(gen[:40])
    return tech


async def _http_probe(host: str) -> dict:
    """Try https then http. Returns {} when neither answers."""
    for scheme in ("https", "http"):
        try:
            res = await safe_fetch(f"{scheme}://{host}/", method="GET",
                                   headers={"User-Agent": _UA}, timeout=_HTTP_TIMEOUT,
                                   max_redirects=4, max_bytes=_HTTP_MAX_BYTES)
        except SafeFetchError:
            continue
        except Exception as exc:  # noqa: BLE001
            log.info("asm probe http error %s %s: %s", scheme, tag(host), type(exc).__name__)
            continue
        body = res.get("body", "") or ""
        hdrs = {k.lower(): v for k, v in (res.get("headers") or {}).items()}
        sec = {h: (h in hdrs) for h in (
            "strict-transport-security", "content-security-policy",
            "x-content-type-options", "x-frame-options", "referrer-policy")}
        return {
            "scheme": scheme,
            "status": res.get("status"),
            "title": _title(body),
            "server": hdrs.get("server", ""),
            "redirect_chain": res.get("redirect_chain") or [],
            "final_url": res.get("url_final"),
            "fingerprint": _fingerprint(res.get("headers") or {}, body),
            "sec": sec,
            "_body": body[:8000],
        }
    return {}


async def probe_host(host: str, reg: str, *, sem_ports: asyncio.Semaphore,
                     port_timeout: float, do_ports: bool = True) -> dict:
    """Probe one host and return its record. Never raises."""
    loop = asyncio.get_event_loop()
    dns_data = await loop.run_in_executor(None, _resolve_sync, host)
    cname = dns_data["CNAME"][0] if dns_data["CNAME"] else ""

    resolved_ips: list = []
    nxdomain = False
    try:
        resolved_ips = resolve_and_check(host)
    except SafeFetchError:
        # Either the host does not resolve (a dangling CNAME is the interesting
        # case) or it resolves only to private space (refused, not probed).
        nxdomain = bool(cname)

    cdn_match = cdn.classify_host(resolved_ips, cname)
    cname_reg = registrable(cname) if cname else ""
    is_third_party = bool(cname and cname_reg and cname_reg != reg and not cdn_match)

    if cdn_match:
        kind = "cdn"
    elif is_third_party:
        kind = "reference"
    else:
        kind = "own"

    record = {
        "host": host,
        "kind": kind,
        "resolved_ips": resolved_ips,
        "cname": cname,
        "cname_target": cname if (is_third_party or cdn_match) else "",
        "cdn_provider": cdn_match.provider if cdn_match else "",
        "is_reference": 1 if kind == "reference" else 0,
        "nxdomain": nxdomain,
        "dns": {k.lower(): v for k, v in dns_data.items()},
        "http": {},
        "tls": None,
        "fingerprint": [],
        "open_ports": [],
    }

    # HTTP probe for every host that resolves (own, cdn, reference). A dangling
    # host does not resolve, so there is nothing to fetch; its CNAME still drives
    # takeover detection in findings.py.
    if resolved_ips:
        http = await _http_probe(host)
        record["http"] = {k: v for k, v in http.items() if k != "_body"}
        record["_body"] = http.get("_body", "")
        record["fingerprint"] = http.get("fingerprint", [])
        # TLS grab on 443, pinned to the validated IP, when HTTPS is in play.
        try:
            record["tls"] = await loop.run_in_executor(
                None, _grab_tls, host, 443, resolved_ips[0])
        except Exception:  # noqa: BLE001
            record["tls"] = None

    # Port scan ONLY the target's own infrastructure. CDN and third-party hosts
    # are never port scanned, in operator mode too.
    if do_ports and kind == "own" and resolved_ips:
        record["open_ports"] = await portscan.scan(
            resolved_ips[0], timeout=port_timeout, sem=sem_ports)

    return record


# ------------------------------------------------------- apex mail posture ----

async def apex_mail_posture(domain: str) -> dict:
    """SPF, DMARC, MTA-STS and TLS-RPT on the apex, reusing the email-header
    helpers for SPF and DMARC. MTA-STS is fetched over HTTPS via safe_fetch."""
    from app.routers.email_header import _lookup_dmarc, _lookup_spf

    spf, dmarc = await asyncio.gather(_lookup_spf(domain), _lookup_dmarc(domain))

    loop = asyncio.get_event_loop()
    tlsrpt_vals = await loop.run_in_executor(None, _txt_sync, f"_smtp._tls.{domain}")
    tlsrpt = any(v.lower().startswith("v=tlsrptv1") for v in tlsrpt_vals)

    mta_sts = False
    try:
        res = await safe_fetch(f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                               method="GET", headers={"User-Agent": _UA},
                               timeout=8.0, max_redirects=1, max_bytes=20_000)
        mta_sts = res.get("status") == 200 and "version:" in (res.get("body", "") or "").lower()
    except Exception:  # noqa: BLE001
        mta_sts = False

    return {"spf": spf, "dmarc": dmarc, "mta_sts": mta_sts, "tls_rpt": tlsrpt}


def _txt_sync(name: str) -> list:
    out = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = _DNS_TIMEOUT
        resolver.timeout = _DNS_TIMEOUT
        for r in resolver.resolve(name, "TXT"):
            out.append(b"".join(r.strings).decode("utf-8", "replace").strip())
    except Exception:
        return []
    return out
