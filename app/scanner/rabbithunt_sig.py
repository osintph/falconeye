"""
Per-kit signatures and the transparent weighted scorer that matches against them.

Ported from rabbithunt.py (a copy of the REV 2 reference ships in tools/ for
CLI use). This module is REV 3. The engine that reads these records lives in
app/scanner/kit_analyzer.py and knows nothing about any specific kit: adding a
second kit means adding a record to SIGNATURES below, never editing the
analyzer.

Scoring is weighted and transparent. Every signal is returned with its weight
and whether it hit or missed, and the verdict is a percentage of achievable
points. Misses are never hidden, because a miss on a check that could have
fired is itself evidence.

REV 3, and why it differs from the shipped REV 2 script
------------------------------------------------------
REV 2 removed the `socketio_scoped_to_path` network signal, on the reasoning
that "the bundle has no socket.io. Transport is a raw WebSocket at /console".
That conclusion came from grepping the ENTRY bundle only. It is wrong: the
socket.io client library sits in the VENDOR chunk, which carries `/socket.io/`,
`EIO=`, `engine.io` and the Manager constructor, while the entry bundle carries
only the option values (`websocket`, `polling`, `/console`, `config`,
`operation`) at adjacent string-table indices. The published teardown states it
directly, "socket.io, scoped to the campaign path", and records the probe:

    /socket.io/       404
    /com/socket.io/   204
    /ws/socket.io/    404

So REV 3 restores the path-scoped socket.io check at weight 10 as the single
highest-signal live discriminator, and keeps REV 2's content tokens, weights
and verdict tiers verbatim. REV 2's raw-WebSocket-upgrade probe is NOT carried
over: it opened a bare TLS socket, which bypasses the SSRF guard that every
outbound request in this package has to go through. The HTTP status probe below
gets the same discrimination through safe_fetch.
"""

import logging
import re
from typing import Optional
from urllib.parse import urlparse

from app.utils.safe_fetch import safe_fetch, SafeFetchError

log = logging.getLogger("falconeye.rabbithunt")

PROBE_TIMEOUT = 10.0

# The iPhone UA the kit was originally acquired with. Kits routinely serve a
# different shell to desktop UAs, so the mobile UA is the accurate one here.
KIT_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 "
    "Mobile/15E148 Safari/604.1"
)


# ---------------------------------------------------------------------------
# Signature registry
#
# One record per kit. A record is DATA: literals, names, paths, weights. No
# record should ever require a code change in kit_analyzer.py to be useful.
# ---------------------------------------------------------------------------

PAPER_RABBIT = {
    "id": "paper_rabbit",
    "name": "Operation Paper Rabbit",
    "family": "Chinese-language PhaaS, live-operator relay",
    "reference": (
        "https://blog.osintph.info/"
        "operation-paper-rabbit-a-phishing-kit-with-a-live-operator-console/"
    ),
    "summary": (
        "Vue 3 over Vite, socket.io relay to a live operator console, two "
        "hardcoded AES-128-CBC contexts, MD5-hashed localStorage keys, UK and "
        "US identity harvesting in one build."
    ),

    # Both AES-128-CBC/Pkcs7 pairs, hardcoded as Utf8.parse literals.
    "crypto_pairs": [
        {"role": "storage", "key": "NLFRWBHXVQJTCPYK", "iv": "DMAGSZEIOPQUNTVC",
         "mode": "AES-128-CBC", "padding": "Pkcs7",
         "note": "wraps localStorage and sessionStorage values"},
        {"role": "transport", "key": "ZQMWLSPXJRDHKTNV", "iv": "YFBCUENAGPQLXJWR",
         "mode": "AES-128-CBC", "padding": "Pkcs7",
         "note": "wraps socket messages and exfil"},
    ],

    # localStorage.setItem(MD5(name), AES(value)) — the key name is hashed
    # before write, so MD5("t_config") = 2e14a1ac17c37597f4579a51c5f26330.
    "storage_keys": ["t_config"],

    "socket": {
        "path": "/console",
        "channels": ["config", "operation"],
        "transports": ["websocket", "polling"],
    },

    # Client-side Vue hash routes. NOT server paths: a detection rule written
    # against these as URL paths matches nothing.
    "hash_routes": [
        "/index", "/phoneCode", "/emailCode", "/pinCode",
        "/appCode", "/tempCustomCode", "/expressCvv",
    ],

    "locales": ["GB", "US"],
    "operator_path": "/console",
    "session_cookie": "_vt",

    "cjk_glossary": {
        "加密失败": "encryption failed",
        "加密异常": "encryption exception",
        "解密结果为空": "decryption result empty",
        "解密失败": "decryption failed",
        "解密异常": "decryption exception",
        "手机验证页": "phone verification page",
        "邮箱验证页": "email verification page",
        "APP验证页": "app verification page",
        "PIN验证页": "PIN verification page",
        "自定义验证码页": "custom verification code page",
        "运通CVV验证页": "Amex CVV verification page",
    },

    # Content tokens, weights carried over verbatim from REV 2. These live in
    # the DECODED string table, so bundle mode is most confident when handed an
    # analyzer report; raw text still catches what survives obfuscation.
    "content_tokens": {
        "verification_state_ls": (r"verification state (from|to) localStorage", 6),
        "hash_routes": (r"/(phoneCode|emailCode|pinCode|appCode|tempCustomCode|expressCvv)\b", 6),
        "unattended_mode": (r"\bunattended(Countdown|Router)\b", 5),
        "operator_wait": (r"Waiting for approval in your bank app", 5),
        "headless_module": (r"HeadlessDetector(Modules|Utils)", 4),
        "amex_cvv_page": (r"\bexpressCvv\b|运通CVV", 3),
        "chinese_debug": (r"验证页|加密异常|解密异常|解密失败", 6),
        "pin_encrypt_copy": (r"never store your PIN", 3),
        "console_path": (r"/console", 3),
        "aes_cbc_pkcs7": (r"\bCBC\b.*Pkcs7|Pkcs7.*\bCBC\b", 2),
    },

    "aes_literals": (
        "NLFRWBHXVQJTCPYK", "DMAGSZEIOPQUNTVC",
        "ZQMWLSPXJRDHKTNV", "YFBCUENAGPQLXJWR",
    ),
}

SIGNATURES = {PAPER_RABBIT["id"]: PAPER_RABBIT}
DEFAULT_SIGNATURE_ID = PAPER_RABBIT["id"]


def get_signature(sig_id: str = DEFAULT_SIGNATURE_ID) -> dict:
    return SIGNATURES.get(sig_id, PAPER_RABBIT)


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

def verdict(pct: int) -> str:
    if pct >= 70:
        return "STRONG MATCH"
    if pct >= 40:
        return "PARTIAL"
    if pct >= 20:
        return "WEAK"
    return "NO MATCH"


def verdict_note(pct: int) -> str:
    if pct >= 70:
        return "strong match"
    if pct >= 40:
        return "partial, investigate"
    if pct >= 20:
        return "weak, probably unrelated"
    return "no match"


def _signal(name: str, weight: int, hit: bool, detail: str = "") -> dict:
    return {"name": name, "weight": weight, "hit": bool(hit), "detail": detail}


def _tally(signals: list, extra: Optional[dict] = None) -> dict:
    got = sum(s["weight"] for s in signals if s["hit"])
    possible = sum(s["weight"] for s in signals)
    pct = round(100 * got / possible) if possible else 0
    out = {
        "score_pct": pct,
        "points": got,
        "possible": possible,
        "verdict": verdict(pct),
        "verdict_note": verdict_note(pct),
        "signals": signals,
    }
    if extra:
        out.update(extra)
    return out


# ---------------------------------------------------------------------------
# Bundle content scoring
# ---------------------------------------------------------------------------

def _haystack(analysis_or_text) -> str:
    """Build the searchable text from either an analyzer report or raw source.

    Given an analyzer report, the decoded string table is what gets searched,
    which is the confident path: the content tokens live behind the decoder in
    the raw file. Given raw text, we search it directly and the caller is told
    the checks were raw.
    """
    if isinstance(analysis_or_text, str):
        return analysis_or_text

    if not isinstance(analysis_or_text, dict):
        return ""

    parts = []
    for entry in analysis_or_text.get("decoded_sample", []):
        parts.append(entry)
    for cat in (analysis_or_text.get("indicators") or {}).values():
        for rule in cat:
            for hit in rule.get("table_hits", []):
                parts.append(hit.get("value", ""))
    for c in analysis_or_text.get("cjk_strings", []):
        parts.append(c.get("cjk", ""))
    for r in analysis_or_text.get("hash_routes", []):
        parts.append(r)
    for r in analysis_or_text.get("routes", []):
        parts.append(r.get("path", ""))
    for f in analysis_or_text.get("identity_fields", []):
        parts.append(f.get("value", ""))
    for s in analysis_or_text.get("anti_analysis", {}).get("samples", []):
        parts.append(s)
    for p in analysis_or_text.get("crypto", {}).get("pairs", []):
        parts.append(p.get("key", ""))
        parts.append(p.get("iv", ""))
        # Mode and padding stay on ONE line: tokens like the CBC/Pkcs7 pairing
        # match across a cipher declaration, not across a newline.
        parts.append(f"{p.get('mode', '')} {p.get('padding', '')}".strip())
    for k in analysis_or_text.get("storage_keys", []):
        parts.append(k.get("name", ""))
    sock = analysis_or_text.get("socket", {})
    parts.append(sock.get("path", ""))
    parts.extend(sock.get("channels", []))
    parts.extend(sock.get("transports", []))
    return "\n".join(p for p in parts if p)


def score_bundle(analysis_or_text, sig_id: str = DEFAULT_SIGNATURE_ID) -> dict:
    """Score a decoded analyzer report, or raw bundle text, against a signature.

    Every content token is reported hit or miss with its weight. Never raises.
    """
    sig = get_signature(sig_id)
    text = _haystack(analysis_or_text)
    is_report = isinstance(analysis_or_text, dict)
    signals = []

    for name, (pat, weight) in sig["content_tokens"].items():
        try:
            hit = bool(re.search(pat, text, re.I))
        except re.error:
            hit = False
        signals.append(_signal(name, weight, hit))

    hits = [a for a in sig["aes_literals"] if a in text]
    signals.append(_signal("aes_key_literal", 6, bool(hits), ",".join(hits)))

    # MD5-hashed storage keys. An analyzer report carries this as a resolved
    # fact; the raw-source regex below is a fallback for the raw-text path only.
    # `text` is built from the report's structured fields and never contains
    # resolved source, so running that regex against a report is always a miss.
    if is_report:
        md5_store = bool(analysis_or_text.get("crypto", {}).get("md5_storage")) or \
            bool(analysis_or_text.get("storage", {}).get("keys_appear_hashed"))
    else:
        md5_store = bool(re.search(
            r"(local|session)Storage\.(set|get|remove)Item\(\s*\w+\.MD5\(", text))
    signals.append(_signal("md5_hashed_storage_keys", 4, md5_store))

    # Socket shape, from the analyzer report. Each wanted channel is checked
    # independently for being registered: no proximity, no ordering, so a
    # minifier moving the two registrations apart cannot hide the signal.
    if is_report:
        sock = analysis_or_text.get("socket", {})
        want = sig["socket"]
        found = set(sock.get("channels", []))
        path_hit = sock.get("path", "") == want["path"]
        missing = [c for c in want["channels"] if c not in found]
        if missing:
            chan_detail = "missing: " + ",".join(missing)
        else:
            chan_detail = ",".join(sorted(found)) or "none"
        signals.append(_signal("socket_path", 4, path_hit, sock.get("path", "") or "none"))
        signals.append(_signal("socket_channels", 5, not missing, chan_detail))

        known_md5 = {
            "2e14a1ac17c37597f4579a51c5f26330": "t_config",
        }
        found = [k["name"] for k in analysis_or_text.get("storage_keys", [])
                 if k.get("name") in sig["storage_keys"]
                 or k.get("md5") in known_md5]
        signals.append(_signal("storage_key_name", 4, bool(found), ",".join(found)))

    note = ""
    if not is_report:
        note = ("content checks are RAW-grep on possibly obfuscated source; run "
                "against an analyzer report for full confidence")

    return _tally(signals, {"signature": sig["id"], "mode": "bundle", "note": note})


# ---------------------------------------------------------------------------
# Network scoring
# ---------------------------------------------------------------------------

async def _probe_status(url: str) -> Optional[int]:
    """Status code for a read-only probe, or None if unreachable/blocked.

    Redirects are not followed: the status itself is the signal, and following
    a redirect would change what is being measured.
    """
    try:
        resp = await safe_fetch(
            url,
            headers={"User-Agent": KIT_UA},
            timeout=PROBE_TIMEOUT,
            allow_redirects=False,
        )
        return resp.get("status")
    except SafeFetchError as exc:
        log.debug("probe blocked for %s: %s", url, exc)
        return None
    except Exception:
        log.debug("probe failed for %s", url, exc_info=True)
        return None


def _norm_path(path: str) -> str:
    if not path:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    if not path.endswith("/"):
        path += "/"
    return path


async def probe_socket(host: str, campaign_path: str = "/") -> dict:
    """The path-scoped socket.io probe, the highest-signal live check.

    Requests the socket.io handshake endpoint at the web root and again at the
    campaign path, and compares. A relay scoped to the campaign path answers
    204 there while the root 404s. Status codes only: no socket is opened and
    no frames are sent. Also checks the operator console path.
    """
    path = _norm_path(campaign_path)
    base = f"https://{host}"
    query = "?EIO=4&transport=polling"

    root_status = await _probe_status(f"{base}/socket.io/{query}")
    path_status = await _probe_status(f"{base}{path}socket.io/{query}")
    ws_status = await _probe_status(f"{base}/ws/socket.io/{query}")
    console_status = await _probe_status(f"{base}/console")
    polling_status = await _probe_status(f"{base}/console/?transport=polling")

    return {
        "root": {"path": "/socket.io/", "status": root_status},
        "campaign": {"path": f"{path}socket.io/", "status": path_status},
        "ws": {"path": "/ws/socket.io/", "status": ws_status},
        "console": {"path": "/console", "status": console_status},
        "console_polling": {"path": "/console/?transport=polling", "status": polling_status},
        "path_scoped": path_scoped_hit(root_status, path_status),
    }


def path_scoped_hit(root_status: Optional[int], path_status: Optional[int]) -> bool:
    """True when the socket.io endpoint answers at the campaign path but not at root.

    204 at the campaign path is the handshake responding. Requiring the root to
    differ is what makes this specific: an ordinary socket.io application
    answers 204 at the root too, and that is not this kit.
    """
    return path_status == 204 and root_status != 204


async def score_host(host: str, path: str = "/",
                     probe: Optional[dict] = None,
                     sig_id: str = DEFAULT_SIGNATURE_ID) -> dict:
    """Score a live host. Every outbound request goes through safe_fetch.

    Pass `probe` to reuse a socket probe the caller already ran, so a report
    does not probe the same target twice.
    """
    sig = get_signature(sig_id)
    path = _norm_path(path)
    base = f"https://{host}"
    signals = []

    if probe is None:
        probe = await probe_socket(host, path)

    root_status = probe.get("root", {}).get("status")
    path_status = probe.get("campaign", {}).get("status")
    console_status = probe.get("console", {}).get("status")
    polling_status = probe.get("console_polling", {}).get("status")

    signals.append(_signal(
        "socketio_path_scoped", 10, path_scoped_hit(root_status, path_status),
        f"root {root_status} vs {probe.get('campaign', {}).get('path', '')} {path_status}",
    ))

    console_present = console_status is not None and console_status != 404
    signals.append(_signal("operator_console_present", 5, console_present,
                           f"HTTP {console_status}"))

    signals.append(_signal("longpolling_fallback", 4,
                           polling_status in (200, 400, 426),
                           f"HTTP {polling_status}"))

    # Landing page shell and deployment markers. Lower confidence by design:
    # these are deployment-level traits, kept as weak corroboration.
    body = ""
    headers: dict = {}
    status = None
    try:
        resp = await safe_fetch(f"{base}{path}", headers={"User-Agent": KIT_UA},
                                timeout=PROBE_TIMEOUT)
        status = resp.get("status")
        headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        body = resp.get("body", "") or ""
    except SafeFetchError as exc:
        log.debug("score_host landing fetch blocked for %s: %s", host, exc)
    except Exception:
        log.debug("score_host landing fetch failed for %s", host, exc_info=True)

    setck = headers.get("set-cookie", "")
    cookie_re = re.compile(r"\b%s=" % re.escape(sig.get("session_cookie", "_vt")))
    signals.append(_signal("vt_cookie", 3, bool(cookie_re.search(setck)), setck[:60]))

    vite = bool(re.search(r'src="\.?/assets/[A-Za-z0-9_-]{6,10}\.js"', body))
    signals.append(_signal("vite_hashed_asset", 3, vite))

    shell = status == 200 and len(body) < 4000 and "assets/" in body
    signals.append(_signal("spa_shell", 2, shell, f"body={len(body)}B"))

    signals.append(_signal("cloudflare_front", 1,
                           "cloudflare" in headers.get("server", "").lower(),
                           headers.get("server", "")))

    # Pull the entry bundle and raw-grep the content tokens.
    note = ""
    m = re.search(r'src="(\.?/assets/[A-Za-z0-9_-]{6,10}\.js)"', body)
    if m:
        asset = m.group(1)
        burl = f"{base}{path}{asset.lstrip('./')}"
        btext = ""
        try:
            bresp = await safe_fetch(burl, headers={"User-Agent": KIT_UA},
                                     timeout=PROBE_TIMEOUT)
            btext = bresp.get("body", "") or ""
        except SafeFetchError as exc:
            log.debug("score_host bundle fetch blocked for %s: %s", burl, exc)
        except Exception:
            log.debug("score_host bundle fetch failed for %s", burl, exc_info=True)

        if btext:
            for name, (pat, weight) in sig["content_tokens"].items():
                try:
                    if re.search(pat, btext, re.I):
                        signals.append(_signal(f"content:{name}", weight, True, "raw match"))
                except re.error:
                    continue
            if any(a in btext for a in sig["aes_literals"]):
                signals.append(_signal("content:aes_key_literal", 4, True))
            note = ("content checks are RAW-grep on the obfuscated bundle; the "
                    "bundle verdict above is the confident one")
        signals.append(_signal("entry_bundle_fetched", 1, bool(btext), asset))
    else:
        signals.append(_signal("entry_bundle_fetched", 1, False, "no asset ref"))

    return _tally(signals, {
        "signature": sig["id"],
        "mode": "host",
        "host": host,
        "path": path,
        "note": note,
    })


def campaign_path(url: str) -> str:
    """The directory the campaign is served from, which is what gets probed.

    Anything that does not parse to an absolute path falls back to "/". Without
    that guard a malformed input becomes part of the probe URL.
    """
    try:
        p = urlparse(url).path or "/"
    except Exception:
        return "/"
    if not p.startswith("/"):
        return "/"
    if not p.endswith("/"):
        p = p.rsplit("/", 1)[0] + "/"
    return p or "/"
