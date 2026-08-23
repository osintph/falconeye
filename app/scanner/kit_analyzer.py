"""
Static analysis for string-obfuscated phishing kit bundles.

Ported from the kitanalyze.py reference used in the Operation Paper Rabbit
teardown (a copy ships unchanged in tools/kitanalyze.py). The reference was
written around one kit; this module is the generalized engine. Everything here
is kit-agnostic: it decodes the string table, resolves decoder call sites back
into the source, normalizes bracket access to dot access, and only then
searches. Per-kit values (specific AES literals, storage key names, socket
paths, CJK glosses) live in app/scanner/rabbithunt_sig.py as signature records
and are passed in, never hardcoded here. Adding a second kit means adding a
signature, not editing this file.

Design principle, carried over from the reference and from the writeup that
prompted it:

    NEVER grep the raw source of an obfuscated file and treat a miss as a
    finding. Every identifier may sit behind a decoder call, so `AES` or
    `localStorage` can be absent from the plaintext while being all over the
    program. A miss only means something after the source has been resolved.

That is why `not_found` is reported separately and is only populated once
resolution has actually run.

No network. No execution. Never eval/exec. Read-only.
"""

import base64
import hashlib
import json
import logging
import re
from collections import OrderedDict
from typing import Optional
from urllib.parse import unquote

from app.config import KIT_MAX_BUNDLE_BYTES, KIT_MAX_RESOLVE_BYTES

log = logging.getLogger("falconeye.kit_analyzer")

STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

# The lowercase-first rotation decode_kit.py hardcodes. javascript-obfuscator
# reuses a small number of rotations, so seeding this one alongside whatever
# find_alphabet discovers costs one extra decode pass and covers builds where
# the alphabet literal itself has been split or computed.
SEEDED_ALPHABETS = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=",
)

# Compute bounds. REGEX_MAX_BODY_BYTES (the 100 KB L-5 email-body cap) is
# deliberately NOT reused: real entry bundles run 85 KB to 2 MB and truncating
# them at 100 KB would silently produce wrong analysis rather than slow
# analysis. The bound here is the input cap below, plus bounded-quantifier
# patterns, plus the capped iteration counts in this section.
MAX_INPUT_BYTES = KIT_MAX_BUNDLE_BYTES
MAX_RESOLVE_BYTES = KIT_MAX_RESOLVE_BYTES
MAX_ARRAYS_DECODED = 5
MAX_TABLE_ENTRIES = 20_000
MAX_DECODER_NAMES = 24
MAX_NORMALIZE_PASSES = 6

_CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")


# ---------------------------------------------------------------------------
# Stage 1: locate string tables and custom alphabets
# ---------------------------------------------------------------------------

ARRAY_RE = re.compile(r'\[\s*(?:"(?:[^"\\]|\\.)*"\s*,\s*){9,}"(?:[^"\\]|\\.)*"\s*\]')
ARRAY_RE_SQ = re.compile(r"\[\s*(?:'(?:[^'\\]|\\.)*'\s*,\s*){9,}'(?:[^'\\]|\\.)*'\s*\]")


def _sq_to_dq(raw: str) -> str:
    """Convert a single-quoted JS array literal to valid JSON. Best effort."""
    parts = re.findall(r"'((?:[^'\\]|\\.)*)'", raw)
    fixed = []
    for p in parts:
        p = p.replace("\\'", "'").replace('"', '\\"')
        fixed.append('"' + p + '"')
    return "[" + ",".join(fixed) + "]"


def find_string_arrays(src: str) -> list:
    """Return [(offset, [strings])], longest table first. Both quote styles."""
    out = []
    for rx in (ARRAY_RE, ARRAY_RE_SQ):
        for m in rx.finditer(src):
            raw = m.group(0)
            try:
                if rx is ARRAY_RE_SQ:
                    raw = _sq_to_dq(raw)
                arr = json.loads(raw)
            except Exception:
                continue
            if isinstance(arr, list) and all(isinstance(x, str) for x in arr):
                out.append((m.start(), arr[:MAX_TABLE_ENTRIES]))
    out.sort(key=lambda t: -len(t[1]))
    return out


def find_alphabet(src: str) -> list:
    """Custom base64 alphabets: 58 to 72 chars, near-unique characters.

    This single heuristic is what makes the decode key-free. A string literal
    that long with almost no repeated characters is a shuffled base64 alphabet,
    whatever order the obfuscator put it in. Standard base64 and the seeded
    rotations are always appended as fallbacks.
    """
    found = []
    for m in re.finditer(r"""["'`]([A-Za-z0-9+/=_\-]{58,72})["'`]""", src):
        t = m.group(1)
        if len(set(t)) >= len(t) - 2:
            found.append((m.start(), t))

    known = [f[1] for f in found]
    for seeded in SEEDED_ALPHABETS:
        if seeded not in known:
            found.append((-1, seeded))
            known.append(seeded)
    if STD_B64 not in known:
        found.append((-1, STD_B64))
    return found


# ---------------------------------------------------------------------------
# Stage 2: decode
# ---------------------------------------------------------------------------

def decode_one(s: str, table: dict) -> Optional[str]:
    """Custom-alphabet base64 to bytes, then percent-decode for UTF-8."""
    try:
        t = s.translate(table)
    except Exception:
        return None
    t = re.sub(r"[^A-Za-z0-9+/=]", "", t)
    t += "=" * (-len(t) % 4)
    try:
        raw = base64.b64decode(t)
    except Exception:
        return None
    # javascript-obfuscator emits percent-encoded UTF-8 then decodeURIComponent.
    try:
        pct = "".join("%%%02x" % b for b in raw)
        return unquote(pct, encoding="utf-8", errors="strict")
    except Exception:
        pass
    try:
        return raw.decode("utf-8")
    except Exception:
        return None


def score_decode(strings: list) -> float:
    """Fraction of entries that look like real decoded content."""
    if not strings:
        return 0.0
    ok = 0
    for s in strings:
        if not s:
            continue
        printable = sum(1 for c in s if c.isprintable() or c in "\n\t")
        if printable / len(s) > 0.9:
            ok += 1
    return ok / len(strings)


def decode_string_table(arr: list, alphabets: list) -> tuple:
    """Try each alphabet, keep the highest-scoring decode.

    Returns (score, alphabet, decoded_list).
    """
    best = (0.0, None, None)
    for _off, alpha in alphabets:
        try:
            table = str.maketrans(alpha, STD_B64[: len(alpha)])
        except Exception:
            continue
        dec = [decode_one(x, table) for x in arr]
        sc = score_decode(dec)
        if sc > best[0]:
            best = (sc, alpha, dec)
        if sc > 0.85:
            break
    return best


# ---------------------------------------------------------------------------
# Stage 3: resolve call sites
# ---------------------------------------------------------------------------

def identify_decoder(src: str) -> set:
    """Identify decoder function names as {(name, offset_literal)}.

    javascript-obfuscator emits a wrapper that subtracts an offset then indexes
    the table. Short aliases called with a bare integer at high frequency are
    picked up too, since the wrapper is usually aliased.
    """
    names = set()
    for m in re.finditer(
        r"function\s+([A-Za-z_$][\w$]*)\s*\([^)]{0,40}\)\s*\{[^}]{0,80}?"
        r"(?:-=\s*(0x[0-9a-fA-F]+|\d+)|=\s*\w+\s*-\s*(0x[0-9a-fA-F]+|\d+))",
        src,
    ):
        names.add((m.group(1), m.group(2) or m.group(3) or "0"))

    freq: dict = {}
    for m in re.finditer(r"\b([A-Za-z_$][\w$]{0,2})\((\d{1,5})\)", src):
        freq[m.group(1)] = freq.get(m.group(1), 0) + 1
    existing = {x[0] for x in names}
    for n, c in sorted(freq.items(), key=lambda kv: -kv[1]):
        if c >= 20 and n not in existing:
            names.add((n, "0"))
            existing.add(n)
        if len(names) >= MAX_DECODER_NAMES:
            break
    return names


def resolve_source(src: str, decoded: list, decoder_names: set) -> str:
    """Replace NAME(idx) call sites with the decoded string as a JS literal."""
    if len(src) > MAX_RESOLVE_BYTES:
        return src
    out = src
    for name, off in list(decoder_names)[:MAX_DECODER_NAMES]:
        try:
            offv = int(off, 16) if str(off).startswith("0x") else int(off)
        except Exception:
            offv = 0
        pat = re.compile(r"\b" + re.escape(name) + r"\((\d{1,5})\)")

        def sub(m):
            i = int(m.group(1)) - offv
            if 0 <= i < len(decoded) and decoded[i] is not None:
                v = decoded[i].replace("\\", "\\\\").replace('"', '\\"')
                v = v.replace("\n", "\\n").replace("\r", "\\r")
                return '"' + v + '"'
            return m.group(0)

        out = pat.sub(sub, out)
    return out


IDENT_RE = re.compile(r'\[\s*"([A-Za-z_$][\w$]*)"\s*\]')


def normalize(resolved: str) -> str:
    """Convert obj["prop"] to obj.prop, repeating until stable.

    Resolution puts decoded strings into member-access position, so the source
    is full of c["enc"]["Utf8"]["parse"]("KEY"), which no ordinary syntax
    pattern matches. This step is why the extractors below must run on
    normalized source and never on raw source.
    """
    prev = None
    cur = resolved
    for _ in range(MAX_NORMALIZE_PASSES):
        if cur == prev:
            break
        prev = cur
        cur = IDENT_RE.sub(r".\1", cur)
    return cur


# ---------------------------------------------------------------------------
# Stage 4: generic indicator families
#
# These are pattern FAMILIES, not single-kit checks. Extend a family when a new
# technique shows up across kits; never narrow one to a specific deployment.
# ---------------------------------------------------------------------------

INDICATORS = OrderedDict([
    ("crypto", [
        (r"\bAES\b", "AES cipher"),
        (r"CryptoJS", "CryptoJS library"),
        (r"\bMD5\b", "MD5 hashing"),
        (r"\bSHA(?:1|256|512)\b", "SHA hashing"),
        (r"\bTripleDES\b|\bRC4\b|\bRabbit\b", "other CryptoJS cipher"),
        (r"\bCBC\b|\bCTR\b|\bECB\b|\bGCM\b", "cipher mode"),
        (r"Pkcs7|NoPadding|ZeroPadding", "padding scheme"),
        (r"crypto\.subtle|importKey|deriveKey", "WebCrypto"),
        (r"\batob\b|\bbtoa\b", "base64 builtin"),
    ]),
    ("storage", [
        (r"localStorage", "localStorage"),
        (r"sessionStorage", "sessionStorage"),
        (r"setItem|getItem|removeItem", "storage accessor"),
        (r"document\.cookie", "cookie access"),
        (r"indexedDB", "IndexedDB"),
    ]),
    ("network", [
        (r"socket\.io|socketio", "socket.io"),
        (r"\bwebsocket\b|new WebSocket|wss?://", "WebSocket"),
        (r"\bpolling\b", "long-polling transport"),
        (r"\bemit\b", "socket emit"),
        (r"XMLHttpRequest|\bfetch\(|axios", "HTTP client"),
        (r"sendBeacon", "beacon exfil"),
        (r"/console|/admin|/panel|/manage", "operator panel path"),
        (r"api/open/|/api/", "REST endpoint"),
        (r"https?://[A-Za-z0-9.-]+", "absolute URL"),
    ]),
    ("routes", [
        (r"^/[a-zA-Z][\w/-]*$", "route path"),
        (r"createWebHashHistory|hashHistory|#/", "hash router"),
        (r"createWebHistory", "history-mode router"),
    ]),
    ("payment", [
        (r"cardNumber|card_number|cardHolder", "card field"),
        (r"\bcvv\b|\bcvc\b|\bcid\b", "security code field"),
        (r"expiry|expiration|expDate", "expiry field"),
        (r"\bpin\b", "PIN field"),
        (r"\botp\b|one-?time", "OTP flow"),
        (r"3d ?secure|3ds", "3DS reference"),
        (r"visa|mastercard|amex|american express|unionpay|jcb", "card brand"),
        (r"gcash|maya|paymaya|grabpay|bpi|bdo|unionbank", "PH wallet/bank"),
    ]),
    ("identity", [
        (r"national insurance|\bnino?\b", "UK NI number"),
        (r"social security|\bssn\b", "US SSN"),
        (r"date of birth|\bdob\b", "date of birth"),
        (r"passport|driver.?s licen[cs]e|id ?card", "identity document"),
        (r"barangay", "PH barangay"),
        (r"postcode|postal code|zip ?code", "postal field"),
    ]),
    ("antianalysis", [
        (r"isSpider|isBot|crawler", "crawler detection"),
        (r"headless|HeadlessChrome", "headless detection"),
        (r"webdriver|ChromeDriver|DevTools", "automation detection"),
        (r"debugger", "debugger trap"),
        (r"RTCPeerConnection", "WebRTC probe"),
        (r"navigator\.plugins|navigator\.languages|screen\.", "fingerprint surface"),
        (r"Worker\(|postMessage", "Web Worker"),
    ]),
    ("operator", [
        (r"unattended", "unattended mode"),
        (r"waitVerification|waiting", "operator wait state"),
        (r"tip_fail|tip_change_card|change ?card|different card", "card retry prompt"),
        (r"instruction|command|dispatch", "command dispatch"),
    ]),
])


def run_indicators(decoded: list, resolved: str) -> OrderedDict:
    results: OrderedDict = OrderedDict()
    for cat, rules in INDICATORS.items():
        cat_out = []
        for pat, label in rules:
            rx = re.compile(pat, re.I | re.M)
            hits = []
            for i, s in enumerate(decoded):
                if s and rx.search(s):
                    hits.append({"index": i, "value": s[:200]})
            in_resolved = bool(rx.search(resolved)) if resolved else False
            cat_out.append({
                "label": label,
                "pattern": pat,
                "status": "CONFIRMED" if (hits or in_resolved) else "not found",
                "table_hits": hits[:25],
                "table_hit_count": len(hits),
                "in_resolved_source": in_resolved,
            })
        results[cat] = cat_out
    return results


# ---------------------------------------------------------------------------
# Stage 5: targeted extractors (generic shapes, signature-annotated)
# ---------------------------------------------------------------------------

_ANTI_FRAMEWORKS = (
    "Selenium", "WebDriver", "PhantomJS", "Puppeteer", "Playwright",
    "Nightmare", "Cypress", "ChromeDriver", "HeadlessChrome", "CDP",
)

# Identity fields carry a locale because the pairing is the finding: a kit
# shipping two national-ID formats in one build is harvesting for two markets.
# Generic table, extend with new markets as they appear.
LOCALE_FIELDS = (
    ("GB", r"national insurance", "National Insurance Number"),
    ("GB", r"\bni number\b|\bnino\b", "NI Number"),
    ("GB", r"\bpostcode\b", "Postcode"),
    ("GB", r"DD/MM/YYYY", "Date of Birth (DD/MM/YYYY)"),
    ("US", r"social security|\bssn\b", "Social Security number / SSN"),
    ("US", r"\bzip ?code\b", "Zip Code"),
    ("US", r"MM/DD/YYYY", "Date of Birth (MM/DD/YYYY)"),
    ("PH", r"\bbarangay\b", "Barangay"),
    ("PH", r"\bprovince\b", "Province"),
    ("CA", r"\bsocial insurance number\b|\bsin\b", "Social Insurance Number"),
    ("AU", r"\btax file number\b|\btfn\b", "Tax File Number"),
)


def extract_crypto_material(resolved: str) -> list:
    """Pull AES key/IV literals and mode/padding out of normalized source."""
    finds = []
    pats = [
        (r'enc\.Utf8\.parse\("([^"]{4,64})"\)', "Utf8.parse literal (key or IV)"),
        (r'enc\.Hex\.parse\("([0-9a-fA-F]{8,64})"\)', "Hex.parse literal"),
        (r"AES\.(?:encrypt|decrypt)\s*\(", "AES call site"),
        (r"\{\s*iv\s*:\s*([A-Za-z_$][\w$]*)", "IV variable"),
        (r'([A-Za-z_$][\w$]*)\s*=\s*[\w.$]*enc\.\w+\.parse\("[^"]{4,64}"\)',
         "key/IV assigned to variable"),
        (r"mode\s*:\s*[\w.$]*\.(CBC|CTR|ECB|CFB|OFB)", "cipher mode"),
        (r"padding\s*:\s*[\w.$]*\.(Pkcs7|NoPadding|ZeroPadding|Iso97971)", "padding"),
    ]
    for pat, label in pats:
        for m in re.finditer(pat, resolved):
            finds.append({
                "label": label,
                "value": m.group(1) if m.groups() else m.group(0),
                "offset": m.start(),
            })
    return finds


def _cipher_context(resolved: str) -> tuple:
    """Return (mode, padding) as declared in the source, blank when absent."""
    mode = ""
    padding = ""
    m = re.search(r"mode\s*:\s*[\w.$]*\.(CBC|CTR|ECB|CFB|OFB)", resolved)
    if m:
        mode = m.group(1)
    p = re.search(r"padding\s*:\s*[\w.$]*\.(Pkcs7|NoPadding|ZeroPadding|Iso97971)", resolved)
    if p:
        padding = p.group(1)
    return mode, padding


def extract_crypto_pairs(resolved: str, decoded: list, signature: Optional[dict]) -> dict:
    """Pair AES key/IV literals and label their role.

    The pairing is generic: Utf8.parse literals of equal, key-sized length are
    emitted adjacently by every CryptoJS kit we have seen, so consecutive
    literals pair up. Role naming ("storage", "transport") is signature data,
    looked up from the passed signature and left blank when there is none.
    """
    lengths = {16, 24, 32}
    literals = []
    seen = set()
    # Key material reaches the cipher two ways: parsed straight from a literal,
    # or bound to a variable first and parsed from that. Real kits mix both in
    # one file, so resolving one level of indirection is required rather than
    # optional. Source order is preserved so key and IV still pair up.
    assigned = {}
    for m in re.finditer(r'\b([A-Za-z_$][\w$]*)\s*=\s*"([^"\\]{4,64})"', resolved):
        assigned.setdefault(m.group(1), m.group(2))

    for m in re.finditer(
        r'enc\.(?:Utf8|Hex)\.parse\(\s*(?:"([^"]{4,64})"|([A-Za-z_$][\w$]*))\s*\)',
        resolved,
    ):
        v = m.group(1) if m.group(1) is not None else assigned.get(m.group(2), "")
        if v and len(v) in lengths and v not in seen:
            seen.add(v)
            literals.append(v)

    # Fall back to the decoded table when the source did not resolve cleanly:
    # key material sits in the table as plain entries of key-sized length.
    if not literals:
        known = set()
        if signature:
            for pair in signature.get("crypto_pairs", []):
                known.add(pair.get("key", ""))
                known.add(pair.get("iv", ""))
        for s in decoded:
            if s and s in known and s not in seen:
                seen.add(s)
                literals.append(s)

    mode, padding = _cipher_context(resolved)
    if not mode:
        mode = "CBC" if re.search(r"\bCBC\b", resolved) else ""
    if not padding:
        padding = "Pkcs7" if re.search(r"Pkcs7", resolved) else ""

    role_by_key = {}
    if signature:
        for pair in signature.get("crypto_pairs", []):
            role_by_key[pair.get("key", "")] = pair.get("role", "")

    pairs = []
    for i in range(0, len(literals) - 1, 2):
        key, iv = literals[i], literals[i + 1]
        bits = len(key) * 8
        pairs.append({
            "role": role_by_key.get(key, ""),
            "key": key,
            "iv": iv,
            "mode": f"AES-{bits}-{mode}" if mode else f"AES-{bits}",
            "padding": padding,
        })

    md5_storage = bool(re.search(
        r"(?:localStorage|sessionStorage)\.\w+\(\s*[\w.$]*\.?MD5\s*\(", resolved))
    return {"pairs": pairs, "md5_storage": md5_storage}


def extract_storage_keys(resolved: str, decoded: list, signature: Optional[dict]) -> dict:
    """Find storage call sites, whether keys are hashed, and the key names.

    Key names come from MD5-wrapped literal arguments in the resolved source.
    Signature-known names are checked against the decoded table as well, so a
    build that computes its key name still reports the pairing.
    """
    finds = []
    for m in re.finditer(
        r"(localStorage|sessionStorage)\.(setItem|getItem|removeItem)\s*\(([^,)]{0,120})",
        resolved,
    ):
        finds.append({
            "store": m.group(1),
            "op": m.group(2),
            "key_expr": m.group(3).strip()[:120],
            "offset": m.start(),
        })

    hashed = bool(re.search(
        r"(?:localStorage|sessionStorage)\.\w+\(\s*[\w.$]*\.?(MD5|SHA1|SHA256)\s*\(",
        resolved,
    ))

    names = []
    seen = set()
    for m in re.finditer(
        r"(?:localStorage|sessionStorage)\.\w+\(\s*[\w.$]*\.?MD5\s*\(\s*\"([^\"]{1,64})\"",
        resolved,
    ):
        n = m.group(1)
        if n not in seen:
            seen.add(n)
            names.append(n)

    if signature:
        table = {s for s in decoded if s}
        for known in signature.get("storage_keys", []):
            if known in table and known not in seen:
                seen.add(known)
                names.append(known)

    keys = [
        {"name": n, "md5": hashlib.md5(n.encode("utf-8")).hexdigest()}
        for n in names
    ]
    return {"call_sites": finds[:40], "keys_appear_hashed": hashed, "keys": keys}


# A handler-registration wrapper: a two-parameter function whose body stores or
# binds the second parameter as a callback keyed by the first. Kits routinely
# register channels through one of these rather than calling socket.on directly,
# so the callee name alone tells you nothing and the definition has to be read.
_WRAPPER_DEF_RE = re.compile(
    r"(?:function\s+([A-Za-z_$][\w$]*)"
    r"|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:function)?)"
    r"\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*([A-Za-z_$][\w$]*)\s*\)\s*(?:=>)?\s*\{([^{}]{0,240})\}"
)

MAX_WRAPPERS = 12

_SOCKET_LIFECYCLE = frozenset({
    "connect", "disconnect", "error", "connect_error", "reconnect",
    "message", "ping", "pong", "close", "open",
})


def find_registration_wrappers(resolved: str) -> set:
    """Names of functions that register a callback under a string key.

    Matches shapes like `function f(n,m){n&&typeof m==="function"&&map.set(n,m)}`
    which is how a kit builds its own channel dispatch table. Detecting the
    definition, rather than guessing from call shape, is what keeps Vue render
    calls such as createElementVNode("div", props, ...) out of the results.
    """
    out = set()
    for m in _WRAPPER_DEF_RE.finditer(resolved):
        name = m.group(1) or m.group(2)
        if not name:
            continue
        key, cb, body = m.group(3), m.group(4), m.group(5)
        registers = (
            re.search(r"typeof\s+%s\s*===?\s*[\"']function[\"']" % re.escape(cb), body)
            or re.search(r"\.set\(\s*%s\s*,\s*%s\s*\)" % (re.escape(key), re.escape(cb)), body)
            or re.search(r"\.(?:on|addEventListener)\(\s*%s\s*,\s*%s\s*\)"
                         % (re.escape(key), re.escape(cb)), body)
        )
        if registers:
            out.add(name)
        if len(out) >= MAX_WRAPPERS:
            break
    return out


def extract_socket(resolved: str, decoded: list) -> dict:
    """Extract the socket transport config.

    Generic: socket.io and raw WebSocket clients both declare a path and a
    transport list. Channel names come from .on()/.emit() arguments AND from
    calls to any handler-registration wrapper the bundle defines, because the
    kit's own channels are commonly registered through one of those.
    """
    table = [s for s in decoded if s]

    # Both shapes occur: an options object literal passed to io({...}), and
    # properties assigned onto an options object afterwards.
    path = ""
    m = re.search(r'\bpath\s*[:=]\s*"(/[^"]{0,64})"', resolved)
    if m:
        path = m.group(1)

    transports = []
    t = re.search(r"\btransports\s*[:=]\s*\[([^\]]{0,160})\]", resolved)
    if t:
        transports = re.findall(r'"([A-Za-z][\w-]{0,24})"', t.group(1))
    if not transports:
        for candidate in ("websocket", "polling", "webtransport"):
            if candidate in table:
                transports.append(candidate)

    # Direct method registrations, plus registrations through any wrapper the
    # bundle defines. Each channel is looked for independently: no proximity or
    # same-line requirement, so minification reordering cannot hide one.
    call_sites = [r'\.(?:on|once|emit)\s*\(\s*"([A-Za-z][\w.-]{0,40})"']
    for wrapper in find_registration_wrappers(resolved):
        call_sites.append(r"\b%s\s*\(\s*\"([A-Za-z][\w.-]{0,40})\"" % re.escape(wrapper))

    channels = []
    seen = set()
    for pattern in call_sites:
        for m in re.finditer(pattern, resolved):
            c = m.group(1)
            # socket.io lifecycle events are library-level, not kit channels.
            if c in seen or c in _SOCKET_LIFECYCLE:
                continue
            seen.add(c)
            channels.append(c)

    # Library markers (socket.io, engine.io, new WebSocket) usually sit in a
    # vendor chunk, not the chunk that configures the socket. Treating their
    # absence as "no socket" contradicts a path and a transport list found in
    # this same bundle, so a recovered config counts as present too.
    present = (
        bool(re.search(r"socket\.io|socketio|\bio\s*\(|new WebSocket|wss?://", resolved))
        or any(re.search(r"socket\.io|socketio", s, re.I) for s in table)
        or bool(path or transports or channels)
    )

    return {
        "present": present,
        "path": path,
        "channels": sorted(channels)[:20],
        "transports": transports[:8],
    }


# Hash-router detection. The framework helper name (createWebHashHistory) is
# the obvious marker but it does NOT survive bundling: a Vite build minifies it
# away entirely. What does survive is the hash createHref regex literal the
# router emits, /^[^#]+#/, because a regex literal cannot be renamed. Relying on
# the name alone silently returned zero victim views for a real kit that had
# seven.
_HASH_ROUTER_RE = re.compile(
    r"createWebHashHistory"      # vue-router, unminified
    r"|hashHistory"              # react-router and friends
    r"|\^\[\^#\]\+#"             # minified hash createHref regex literal
)


def is_hash_router(decoded: list, resolved: str) -> bool:
    """True when the bundle routes on the URL fragment."""
    if _HASH_ROUTER_RE.search(resolved or ""):
        return True
    return any(s and "#/" in s for s in decoded)


def extract_hash_routes(decoded: list, resolved: str,
                        exclude: Optional[set] = None) -> list:
    """Vue/SPA hash routes.

    Reported as routes only, never as URL paths: they are client-side and a
    detection rule written against them as server paths matches nothing.
    `exclude` drops server-side paths that share the shape, above all the
    socket path, which would otherwise be listed as a victim view.
    """
    if not is_hash_router(decoded, resolved):
        return []

    skip = {p for p in (exclude or set()) if p}
    routes = []
    seen = set()
    for s in decoded:
        if not s:
            continue
        m = re.fullmatch(r"#?(/[A-Za-z][\w-]{0,40})", s)
        if m:
            r = m.group(1)
            if r not in seen and r not in skip:
                seen.add(r)
                routes.append(r)
    return routes[:40]


def extract_routes(decoded: list) -> list:
    """Every route-shaped table entry, regardless of router mode."""
    return [
        {"index": i, "path": s}
        for i, s in enumerate(decoded)
        if s and re.fullmatch(r"/[A-Za-z][\w/-]{0,40}", s)
    ]


def extract_identity(decoded: list) -> tuple:
    """Return (identity_fields, locales) from the generic LOCALE_FIELDS table."""
    fields = []
    seen = set()
    for locale, pat, label in LOCALE_FIELDS:
        rx = re.compile(pat, re.I)
        for i, s in enumerate(decoded):
            if s and rx.search(s):
                if label in seen:
                    break
                seen.add(label)
                fields.append({
                    "locale": locale,
                    "field": label,
                    "index": i,
                    "value": s[:120],
                })
                break
    locales = sorted({f["locale"] for f in fields})
    return fields, locales


def extract_anti_analysis(decoded: list, resolved: str) -> dict:
    """Count anti-analysis strings, name the frameworks, list verdict tiers."""
    rx = re.compile(
        r"headless|webdriver|selenium|phantom|puppeteer|playwright|automation|"
        r"\bcdp\b|devtools|swiftshader|llvmpipe|navigator\.|screen\.|plugins|"
        r"webgl|battery|mediaDevices|permissions|emoji|spoof",
        re.I,
    )
    matches = [s for s in decoded if s and rx.search(s)]

    frameworks = sorted({
        f for f in _ANTI_FRAMEWORKS
        if any(f.lower() in s.lower() for s in decoded if s)
        or re.search(re.escape(f), resolved, re.I)
    })

    tiers = []
    seen = set()
    for s in decoded:
        if not s:
            continue
        m = re.search(r"\b((?:Likely|Definitely|Possibly|Probably)\s+Headless)\b", s, re.I)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            tiers.append(m.group(1))

    return {
        "count": len(matches),
        "frameworks": frameworks,
        "verdict_tiers": tiers,
        "samples": [s[:160] for s in matches[:10]],
    }


def extract_cjk(decoded: list, signature: Optional[dict]) -> list:
    """CJK debug strings, glossed from the signature when it carries a glossary.

    Developer debug strings never shown to a victim are among the strongest
    attribution evidence in a kit, so they are extracted generically. The
    English glosses are per-kit data and come from the signature.
    """
    glossary = (signature or {}).get("cjk_glossary", {})
    out = []
    seen = set()
    for s in decoded:
        if not s or not _CJK_RE.search(s):
            continue
        v = s.strip()
        if v in seen:
            continue
        seen.add(v)
        out.append({"cjk": v[:80], "gloss": glossary.get(v.rstrip("!：:"), "")})
    return out[:40]


# Exfil and payout identifiers. Generic families, and the pivot targets the
# tab wires through to the Telegram and Crypto modules.
_PIVOT_RES = (
    ("telegram_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("telegram_chat", re.compile(r"api\.telegram\.org/bot([^/\s\"']{10,60})")),
    ("btc", re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")),
    ("eth", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("trx", re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")),
)


def extract_pivots(decoded: list) -> list:
    """Exfil and payout identifiers worth pivoting on.

    Searched in the DECODED table only, never the resolved source: minified
    JavaScript is full of 40-character hex that is not an Ethereum address.
    """
    out = []
    seen = set()
    for kind, rx in _PIVOT_RES:
        for s in decoded:
            if not s or len(s) > 400:
                continue
            for m in rx.finditer(s):
                value = m.group(1) if m.groups() else m.group(0)
                key = (kind, value)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"kind": kind, "value": value})
    return out[:20]


def crack_hash(target: str, decoded: list, extra: Optional[list] = None) -> dict:
    """Find which table string hashes to target."""
    target = target.lower().strip()
    algos = {
        "md5": hashlib.md5, "sha1": hashlib.sha1,
        "sha256": hashlib.sha256, "sha512": hashlib.sha512,
    }
    cands = [s for s in decoded if s]
    if extra:
        cands.extend(extra)
    expanded = set()
    for c in cands:
        if len(c) > 80:
            continue
        expanded.update({c, c.lower(), c.upper()})
    hits = []
    for name, fn in algos.items():
        for c in expanded:
            for enc in ("utf-8", "utf-16-le"):
                try:
                    h = fn(c.encode(enc)).hexdigest()
                except Exception:
                    continue
                if h == target or h[: len(target)] == target:
                    hits.append({"algo": name, "encoding": enc, "plaintext": c})
    return {"target": target, "candidates_tested": len(expanded), "hits": hits}


def collect_not_found(indicators: OrderedDict) -> list:
    """Indicator families that did not fire.

    Only meaningful because the source was resolved first. Reported as a list
    of {category, labels} so the caller can render the negative space honestly.
    """
    out = []
    for cat, rules in indicators.items():
        miss = [r["label"] for r in rules if r["status"] != "CONFIRMED"]
        if miss:
            out.append({"category": cat, "labels": miss})
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _empty_report(error: str) -> dict:
    """Partial report shape. analyze() never raises, it returns this."""
    return {
        "error": error,
        "sha256": "",
        "size_bytes": 0,
        "decode_score": 0.0,
        "table_entries": 0,
        "decoder": {"functions": [], "alphabet": "", "string_arrays_found": 0},
        "crypto": {"pairs": [], "md5_storage": False},
        "crypto_material": [],
        "storage_keys": [],
        "storage": {"call_sites": [], "keys_appear_hashed": False},
        "socket": {"present": False, "path": "", "channels": [], "transports": []},
        "hash_routes": [],
        "routes": [],
        "locales": [],
        "identity_fields": [],
        "anti_analysis": {"count": 0, "frameworks": [], "verdict_tiers": [], "samples": []},
        "cjk_strings": [],
        "pivots": [],
        "urls": [],
        "indicators": {},
        "not_found": [],
        "decoded_sample": [],
    }


def extract_urls(decoded: list, resolved: str) -> list:
    urls = set()
    for s in decoded:
        if not s:
            continue
        for m in re.finditer(r"https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+", s):
            urls.add(m.group(0))
    for m in re.finditer(r"https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+", resolved or ""):
        urls.add(m.group(0))
    noise = re.compile(r"w3\.org|vuejs\.org|socket\.io/docs|github\.io|schema\.org")
    return sorted(u for u in urls if not noise.search(u))[:60]


def analyze(src: str, signature: Optional[dict] = None, crack: Optional[str] = None) -> dict:
    """Analyze one bundle. Never raises.

    `signature` is an optional per-kit record (see rabbithunt_sig.SIGNATURES).
    It only annotates: crypto pair roles, CJK glosses, and known storage key
    names. Every extraction below runs without it.

    On any internal failure the partial dict is returned with an "error" field
    populated rather than the exception propagating, so one malformed bundle
    cannot take down a report that has other bundles in it.
    """
    rep, _decoded, _resolved = analyze_full(src, signature=signature, crack=crack)
    return rep


def analyze_full(src: str, signature: Optional[dict] = None,
                 crack: Optional[str] = None) -> tuple:
    """analyze(), plus the decoded string table and resolved source.

    Used by the CLI for --strtab / --resolved. The web path uses analyze(),
    which drops both: neither belongs in an API response, since the resolved
    source is attacker-controlled kit code.
    """
    if not isinstance(src, str):
        return _empty_report("input is not text"), [], ""

    raw_bytes = src.encode("utf-8", "replace")
    if len(raw_bytes) > MAX_INPUT_BYTES:
        rep = _empty_report(
            f"input too large: {len(raw_bytes)} bytes exceeds the "
            f"{MAX_INPUT_BYTES} byte cap"
        )
        rep["size_bytes"] = len(raw_bytes)
        return rep, [], ""
    if not src.strip():
        return _empty_report("empty input"), [], ""

    rep = _empty_report("")
    rep["error"] = None
    rep["size_bytes"] = len(raw_bytes)
    rep["sha256"] = hashlib.sha256(raw_bytes).hexdigest()
    decoded: list = []
    resolved_norm = ""

    try:
        arrays = find_string_arrays(src)
        alphabets = find_alphabet(src)
        rep["decoder"]["string_arrays_found"] = len(arrays)

        if not arrays:
            resolved = src
            rep["note"] = ("no string table found; file may be a vendor chunk or "
                           "unobfuscated. Indicators run against raw source.")
        else:
            merged: list = []
            best_alpha, best_score = None, 0.0
            for _off, arr in arrays[:MAX_ARRAYS_DECODED]:
                sc, alpha, dec = decode_string_table(arr, alphabets)
                if dec and sc > 0.5:
                    if sc > best_score:
                        best_score, best_alpha = sc, alpha
                    if len(dec) > len(merged):
                        merged = dec
            decoded = merged
            rep["decode_score"] = round(best_score, 3)
            rep["table_entries"] = len(decoded)
            rep["decoder"]["alphabet"] = best_alpha or ""
            names = identify_decoder(src)
            rep["decoder"]["functions"] = sorted(n for n, _o in names)
            resolved = resolve_source(src, decoded, names) if decoded else src

        resolved_norm = normalize(resolved)

        rep["indicators"] = run_indicators(decoded, resolved_norm)
        rep["not_found"] = collect_not_found(rep["indicators"])
        rep["crypto_material"] = extract_crypto_material(resolved_norm)
        rep["crypto"] = extract_crypto_pairs(resolved_norm, decoded, signature)
        storage = extract_storage_keys(resolved_norm, decoded, signature)
        rep["storage"] = {
            "call_sites": storage["call_sites"],
            "keys_appear_hashed": storage["keys_appear_hashed"],
        }
        rep["storage_keys"] = storage["keys"]
        if storage["keys_appear_hashed"]:
            rep["crypto"]["md5_storage"] = True
        rep["socket"] = extract_socket(resolved_norm, decoded)
        rep["hash_routes"] = extract_hash_routes(
            decoded, resolved_norm, exclude={rep["socket"].get("path", "")}
        )
        rep["routes"] = extract_routes(decoded)
        rep["identity_fields"], rep["locales"] = extract_identity(decoded)
        rep["anti_analysis"] = extract_anti_analysis(decoded, resolved_norm)
        rep["cjk_strings"] = extract_cjk(decoded, signature)
        rep["pivots"] = extract_pivots(decoded)
        rep["urls"] = extract_urls(decoded, resolved_norm)
        rep["decoded_sample"] = [s[:160] for s in decoded[:40] if s]
        if crack:
            rep["hash_crack"] = crack_hash(crack, decoded)
    except Exception as exc:
        log.warning("kit_analyzer.analyze failed", exc_info=True)
        rep["error"] = f"analysis failed: {type(exc).__name__}"

    return rep, decoded, resolved_norm


# ---------------------------------------------------------------------------
# CLI, mirroring the kitanalyze reference flags
# ---------------------------------------------------------------------------

def _main() -> None:
    import argparse
    import os

    ap = argparse.ArgumentParser(description="Static analysis for obfuscated kit bundles.")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--json", help="write JSON report here")
    ap.add_argument("--resolved", help="directory to write resolved sources")
    ap.add_argument("--strtab", help="directory to write decoded string tables")
    ap.add_argument("--crack", help="hex hash to crack against the string table")
    args = ap.parse_args()

    reports = []
    for path in args.files:
        with open(path, "r", errors="replace") as fh:
            src = fh.read()
        rep, decoded, resolved = analyze_full(src, crack=args.crack)
        rep["file"] = os.path.basename(path)
        reports.append(rep)

        if args.resolved:
            os.makedirs(args.resolved, exist_ok=True)
            out = os.path.join(args.resolved, os.path.basename(path) + ".resolved.js")
            with open(out, "w") as fh:
                fh.write(resolved)
        if args.strtab:
            os.makedirs(args.strtab, exist_ok=True)
            out = os.path.join(args.strtab, os.path.basename(path) + ".strtab.txt")
            with open(out, "w") as fh:
                for i, v in enumerate(decoded):
                    fh.write("%5d\t%s\n" % (i, (v or "<undecoded>").replace("\n", "\\n")))

        print("=" * 78)
        print("FILE      ", rep["file"])
        print("SHA-256   ", rep["sha256"])
        print("SIZE      ", rep["size_bytes"], "bytes")
        print("TABLE     ", rep["table_entries"], "entries, decode score", rep["decode_score"])
        print("DECODERS  ", ", ".join(rep["decoder"]["functions"]) or "none found")
        if rep.get("error"):
            print("ERROR     ", rep["error"])
        print("=" * 78)
        for pair in rep["crypto"]["pairs"]:
            print("  CRYPTO   %-10s key=%s iv=%s %s/%s"
                  % (pair["role"] or "?", pair["key"], pair["iv"],
                     pair["mode"], pair["padding"]))
        for k in rep["storage_keys"]:
            print("  STORAGE  %s  md5=%s" % (k["name"], k["md5"]))
        s = rep["socket"]
        if s["present"]:
            print("  SOCKET   path=%s transports=%s channels=%s"
                  % (s["path"] or "?", ",".join(s["transports"]), ",".join(s["channels"])))
        if rep["hash_routes"]:
            print("  ROUTES   " + " ".join(rep["hash_routes"]))
        if rep["locales"]:
            print("  LOCALES  " + ", ".join(rep["locales"]))
        aa = rep["anti_analysis"]
        if aa["count"]:
            print("  ANTI     %d strings, frameworks: %s, tiers: %s"
                  % (aa["count"], ", ".join(aa["frameworks"]) or "none",
                     ", ".join(aa["verdict_tiers"]) or "none"))
        for c in rep["cjk_strings"]:
            print("  CJK      %-24s %s" % (c["cjk"], c["gloss"]))
        if rep.get("hash_crack"):
            hc = rep["hash_crack"]
            for h in hc["hits"]:
                print("  CRACK    %s(%s) -> %r" % (h["algo"], h["encoding"], h["plaintext"]))
            if not hc["hits"]:
                print("  CRACK    no match in this table (value likely server-issued)")
        print("\n[NOT FOUND]  meaningful only because source was resolved")
        for nf in rep["not_found"]:
            print("  %-14s %s" % (nf["category"], ", ".join(nf["labels"])))
        print()

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(reports, fh, indent=2)
        print("JSON report ->", args.json)


if __name__ == "__main__":
    _main()
