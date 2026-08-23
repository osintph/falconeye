#!/usr/bin/env python3
"""
kitanalyze.py - static analysis for string-obfuscated phishing kit bundles.

Design principle
----------------
NEVER grep the raw source of an obfuscated file and treat a miss as a finding.
Every identifier may sit behind a decoder call. This tool decodes the string
table FIRST, resolves call sites back into the source, and only THEN searches.

Reports two confidence levels for every indicator:
  CONFIRMED  - found in decoded strings or resolved source
  ABSENT*    - not found, but only meaningful because the source was resolved

Usage
-----
  kitanalyze.py file.js [file2.js ...]            analyze
  kitanalyze.py --resolved out/ file.js           also write resolved source
  kitanalyze.py --crack 2e14a1... file.js         crack a hashed value
  kitanalyze.py --json report.json file.js        machine-readable output

No network. No execution. Read-only.
"""

import re
import sys
import json
import base64
import hashlib
import os
import argparse
from collections import OrderedDict

STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="


# --------------------------------------------------------------------------
# Stage 1: locate string tables and custom alphabets
# --------------------------------------------------------------------------

ARRAY_RE = re.compile(
    r'\[\s*(?:"(?:[^"\\]|\\.)*"\s*,\s*){9,}"(?:[^"\\]|\\.)*"\s*\]'
)
ARRAY_RE_SQ = re.compile(
    r"\[\s*(?:'(?:[^'\\]|\\.)*'\s*,\s*){9,}'(?:[^'\\]|\\.)*'\s*\]"
)


def find_string_arrays(src):
    """Return list of (offset, list_of_strings). Handles both quote styles."""
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
                out.append((m.start(), arr))
    # dedupe by offset, keep longest first
    out.sort(key=lambda t: -len(t[1]))
    return out


def _sq_to_dq(raw):
    """Convert a single-quoted JS array literal to valid JSON. Best effort."""
    parts = re.findall(r"'((?:[^'\\]|\\.)*)'", raw)
    fixed = []
    for p in parts:
        p = p.replace('\\\'', "'").replace('"', '\\"')
        fixed.append('"' + p + '"')
    return "[" + ",".join(fixed) + "]"


def find_alphabets(src):
    """Custom base64 alphabets: 58-72 chars, near-unique."""
    found = []
    for m in re.finditer(r'''["'`]([A-Za-z0-9+/=_\-]{58,72})["'`]''', src):
        t = m.group(1)
        if len(set(t)) >= len(t) - 2:
            found.append((m.start(), t))
    if not found:
        found.append((-1, STD_B64))
    elif STD_B64 not in [f[1] for f in found]:
        found.append((-1, STD_B64))
    return found


# --------------------------------------------------------------------------
# Stage 2: decode
# --------------------------------------------------------------------------

def decode_one(s, table):
    """Custom-alphabet base64 -> bytes -> percent-decode -> utf8."""
    try:
        t = s.translate(table)
    except Exception:
        return None
    t = re.sub(r'[^A-Za-z0-9+/=]', '', t)
    t += "=" * (-len(t) % 4)
    try:
        raw = base64.b64decode(t)
    except Exception:
        return None
    # javascript-obfuscator emits percent-encoded UTF-8 then decodeURIComponent
    try:
        txt = raw.decode('latin-1')
        pct = "".join("%%%02x" % b for b in raw)
        from urllib.parse import unquote
        cand = unquote(pct, encoding='utf-8', errors='strict')
        return cand
    except Exception:
        pass
    try:
        return raw.decode('utf-8')
    except Exception:
        return None


def score(strings):
    """Fraction that look like real decoded content."""
    if not strings:
        return 0.0
    ok = 0
    for s in strings:
        if s is None:
            continue
        if not s:
            continue
        printable = sum(1 for c in s if c.isprintable() or c in '\n\t')
        if printable / len(s) > 0.9:
            ok += 1
    return ok / len(strings)


def best_decode(arr, alphabets):
    """Try each alphabet, and array rotations, pick highest score."""
    best = (0.0, None, None, 0)
    for _off, alpha in alphabets:
        table = str.maketrans(alpha, STD_B64[:len(alpha)])
        dec = [decode_one(x, table) for x in arr]
        sc = score(dec)
        if sc > best[0]:
            best = (sc, alpha, dec, 0)
        if sc > 0.85:
            break
    return best


# --------------------------------------------------------------------------
# Stage 3: resolve call sites
# --------------------------------------------------------------------------

def find_decoder_names(src):
    """
    Identify decoder function names. javascript-obfuscator emits a wrapper
    that subtracts an offset then indexes the table, with a memo cache.
    Also catch short aliases assigned to it.
    """
    names = set()
    # function _(v,z){v-=0;...}  or  function b(n){n=n-0x1a4;...}
    for m in re.finditer(
        r'function\s+([A-Za-z_$][\w$]*)\s*\([^)]{0,40}\)\s*\{[^}]{0,80}?'
        r'(?:-=\s*(0x[0-9a-fA-F]+|\d+)|=\s*\w+\s*-\s*(0x[0-9a-fA-F]+|\d+))',
        src
    ):
        names.add((m.group(1), m.group(2) or m.group(3) or "0"))
    # any short identifier called with a bare integer, high frequency
    freq = {}
    for m in re.finditer(r'\b([A-Za-z_$][\w$]{0,2})\((\d{1,5})\)', src):
        freq[m.group(1)] = freq.get(m.group(1), 0) + 1
    for n, c in freq.items():
        if c >= 20 and n not in [x[0] for x in names]:
            names.add((n, "0"))
    return names


def resolve(src, decoded, decoder_names):
    """Replace NAME(idx) with the decoded string as a JS string literal."""
    out = src
    for name, off in decoder_names:
        try:
            offv = int(off, 16) if str(off).startswith("0x") else int(off)
        except Exception:
            offv = 0
        pat = re.compile(r'\b' + re.escape(name) + r'\((\d{1,5})\)')

        def sub(m):
            i = int(m.group(1)) - offv
            if 0 <= i < len(decoded) and decoded[i] is not None:
                v = decoded[i].replace('\\', '\\\\').replace('"', '\\"')
                v = v.replace('\n', '\\n').replace('\r', '\\r')
                return '"' + v + '"'
            return m.group(0)

        out = pat.sub(sub, out)
    return out


# --------------------------------------------------------------------------
# Stage 4: indicator modules
# --------------------------------------------------------------------------

INDICATORS = OrderedDict([
    ("crypto", [
        (r'\bAES\b', "AES cipher"),
        (r'CryptoJS', "CryptoJS library"),
        (r'\bMD5\b', "MD5 hashing"),
        (r'\bSHA(?:1|256|512)\b', "SHA hashing"),
        (r'\bTripleDES\b|\bRC4\b|\bRabbit\b', "other CryptoJS cipher"),
        (r'\bCBC\b|\bCTR\b|\bECB\b|\bGCM\b', "cipher mode"),
        (r'Pkcs7|NoPadding|ZeroPadding', "padding scheme"),
        (r'crypto\.subtle|importKey|deriveKey', "WebCrypto"),
        (r'\batob\b|\bbtoa\b', "base64 builtin"),
    ]),
    ("storage", [
        (r'localStorage', "localStorage"),
        (r'sessionStorage', "sessionStorage"),
        (r'setItem|getItem|removeItem', "storage accessor"),
        (r'document\.cookie', "cookie access"),
        (r'indexedDB', "IndexedDB"),
    ]),
    ("network", [
        (r'socket\.io|socketio', "socket.io"),
        (r'\bwebsocket\b|new WebSocket|wss?://', "WebSocket"),
        (r'\bpolling\b', "long-polling transport"),
        (r'\bemit\b', "socket emit"),
        (r'XMLHttpRequest|\bfetch\(|axios', "HTTP client"),
        (r'sendBeacon', "beacon exfil"),
        (r'/console|/admin|/panel|/manage', "operator panel path"),
        (r'api/open/|/api/', "REST endpoint"),
        (r'https?://[A-Za-z0-9.-]+', "absolute URL"),
    ]),
    ("routes", [
        (r'^/[a-zA-Z][\w/-]*$', "route path"),
        (r'createWebHashHistory|hashHistory|#/', "hash router"),
        (r'createWebHistory', "history-mode router"),
    ]),
    ("payment", [
        (r'cardNumber|card_number|cardHolder', "card field"),
        (r'\bcvv\b|\bcvc\b|\bcid\b', "security code field"),
        (r'expiry|expiration|expDate', "expiry field"),
        (r'\bpin\b', "PIN field"),
        (r'\botp\b|one-?time', "OTP flow"),
        (r'3d ?secure|3ds', "3DS reference"),
        (r'visa|mastercard|amex|american express|unionpay|jcb', "card brand"),
        (r'gcash|maya|paymaya|grabpay|bpi|bdo|unionbank', "PH wallet/bank"),
    ]),
    ("identity", [
        (r'national insurance|\bnino?\b', "UK NI number"),
        (r'social security|\bssn\b', "US SSN"),
        (r'date of birth|\bdob\b', "date of birth"),
        (r'passport|driver.?s licen[cs]e|id ?card', "identity document"),
        (r'barangay', "PH barangay"),
        (r'postcode|postal code|zip ?code', "postal field"),
    ]),
    ("antianalysis", [
        (r'isSpider|isBot|crawler', "crawler detection"),
        (r'headless|HeadlessChrome', "headless detection"),
        (r'webdriver|ChromeDriver|DevTools', "automation detection"),
        (r'debugger', "debugger trap"),
        (r'RTCPeerConnection', "WebRTC probe"),
        (r'navigator\.plugins|navigator\.languages|screen\.', "fingerprint surface"),
        (r'Worker\(|postMessage', "Web Worker"),
    ]),
    ("operator", [
        (r'unattended', "unattended mode"),
        (r'waitVerification|waiting', "operator wait state"),
        (r'tip_fail|tip_change_card|change ?card|different card', "card retry prompt"),
        (r'instruction|command|dispatch', "command dispatch"),
    ]),
])


def run_indicators(decoded, resolved):
    hay = [d for d in decoded if d]
    results = OrderedDict()
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


# --------------------------------------------------------------------------
# Stage 5: targeted extractors
# --------------------------------------------------------------------------

IDENT_RE = re.compile(r'\[\s*"([A-Za-z_$][\w$]*)"\s*\]')


def normalize(resolved):
    """
    Resolved source contains obj["prop"] because the decoder returned strings
    into member-access position. Convert to obj.prop so ordinary syntax
    patterns match. Repeat until stable for chained access.

    This step is why extractors must never run on raw or naively-resolved
    source: c["enc"]["Utf8"]["parse"]("KEY") will not match /enc\\.Utf8/.
    """
    prev = None
    cur = resolved
    for _ in range(6):
        if cur == prev:
            break
        prev = cur
        cur = IDENT_RE.sub(r'.\1', cur)
    return cur


def extract_crypto_material(resolved):
    """Pull AES key/IV literals out of resolved source."""
    resolved = normalize(resolved)
    finds = []
    pats = [
        (r'enc\.Utf8\.parse\("([^"]{4,64})"\)', "Utf8.parse literal (key or IV)"),
        (r'enc\.Hex\.parse\("([0-9a-fA-F]{8,64})"\)', "Hex.parse literal"),
        (r'AES\.(?:encrypt|decrypt)\s*\(', "AES call site"),
        (r'\{\s*iv\s*:\s*([A-Za-z_$][\w$]*)', "IV variable"),
        (r'([A-Za-z_$][\w$]*)\s*=\s*[\w.$]*enc\.\w+\.parse\("[^"]{4,64}"\)',
         "key/IV assigned to variable"),
        (r'mode\s*:\s*[\w.$]*\.(CBC|CTR|ECB|CFB|OFB)', "cipher mode"),
        (r'padding\s*:\s*[\w.$]*\.(Pkcs7|NoPadding|ZeroPadding|Iso97971)', "padding"),
    ]
    for pat, label in pats:
        for m in re.finditer(pat, resolved):
            finds.append({"label": label,
                          "value": m.group(1) if m.groups() else m.group(0),
                          "offset": m.start()})
    return finds


def extract_storage_keys(resolved):
    """Find how storage keys are derived and what plaintext names are used."""
    resolved = normalize(resolved)
    finds = []
    for m in re.finditer(
        r'(localStorage|sessionStorage)\.(setItem|getItem|removeItem)\s*\(([^,)]{0,120})',
        resolved
    ):
        finds.append({"store": m.group(1), "op": m.group(2),
                      "key_expr": m.group(3).strip()[:120], "offset": m.start()})
    hashed = bool(re.search(
        r'(?:localStorage|sessionStorage)\.\w+\(\s*[\w.$]*\.?(MD5|SHA1|SHA256)\s*\(', resolved))
    return {"call_sites": finds[:40], "keys_appear_hashed": hashed}


def extract_routes(decoded):
    routes = [ {"index": i, "path": s}
               for i, s in enumerate(decoded)
               if s and re.fullmatch(r'/[A-Za-z][\w/-]{0,40}', s) ]
    return routes


def extract_urls(decoded, resolved):
    urls = set()
    for s in decoded:
        if not s:
            continue
        for m in re.finditer(r'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+', s):
            urls.add(m.group(0))
    for m in re.finditer(r'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+', resolved or ""):
        urls.add(m.group(0))
    noise = re.compile(r'w3\.org|vuejs\.org|socket\.io/docs|github\.io|schema\.org')
    return sorted(u for u in urls if not noise.search(u))


# --------------------------------------------------------------------------
# Stage 6: hash cracking
# --------------------------------------------------------------------------

def crack_hash(target, decoded, extra=None):
    """Try to find which table string hashes to target."""
    target = target.lower().strip()
    algos = {
        "md5": hashlib.md5, "sha1": hashlib.sha1,
        "sha256": hashlib.sha256, "sha512": hashlib.sha512,
    }
    cands = [s for s in decoded if s]
    if extra:
        cands.extend(extra)
    # add case variants and common decorations
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
                if h == target or h[:len(target)] == target:
                    hits.append({"algo": name, "encoding": enc, "plaintext": c})
    return {"target": target, "candidates_tested": len(expanded), "hits": hits}


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def analyze_file(path, want_resolved=False, crack=None):
    src = open(path, "r", errors="replace").read()
    rep = {"file": os.path.basename(path),
           "size_bytes": len(src),
           "sha256": hashlib.sha256(open(path, "rb").read()).hexdigest()}

    arrays = find_string_arrays(src)
    alphabets = find_alphabets(src)
    rep["string_arrays_found"] = len(arrays)
    rep["alphabet_candidates"] = [a for _o, a in alphabets if a != STD_B64]

    if not arrays:
        rep["decoded"] = []
        rep["note"] = ("no string table found; file may be a vendor chunk or "
                       "unobfuscated. Indicators run against raw source.")
        decoded, resolved = [], src
    else:
        # decode every array, merge (some kits split tables)
        merged, best_alpha, best_score = [], None, 0.0
        for _off, arr in arrays[:5]:
            sc, alpha, dec, _rot = best_decode(arr, alphabets)
            if dec and sc > 0.5:
                if sc > best_score:
                    best_score, best_alpha = sc, alpha
                if len(dec) > len(merged):
                    merged = dec
        decoded = merged
        rep["decode_score"] = round(best_score, 3)
        rep["alphabet_used"] = best_alpha
        rep["table_entries"] = len(decoded)
        names = find_decoder_names(src)
        rep["decoder_functions"] = sorted(n for n, _o in names)
        resolved = resolve(src, decoded, names) if decoded else src

    rep["indicators"] = run_indicators(decoded, resolved)
    rep["crypto_material"] = extract_crypto_material(resolved)
    rep["storage"] = extract_storage_keys(resolved)
    rep["routes"] = extract_routes(decoded)
    rep["urls"] = extract_urls(decoded, resolved)
    if crack:
        rep["hash_crack"] = crack_hash(crack, decoded)

    return rep, decoded, resolved


def print_report(rep):
    W = 78
    print("=" * W)
    print("FILE      ", rep["file"])
    print("SHA-256   ", rep["sha256"])
    print("SIZE      ", rep["size_bytes"], "bytes")
    if "table_entries" in rep:
        print("TABLE     ", rep["table_entries"], "entries, decode score",
              rep.get("decode_score"))
        print("DECODERS  ", ", ".join(rep.get("decoder_functions", [])) or "none found")
        if rep.get("alphabet_candidates"):
            print("ALPHABET  ", rep["alphabet_candidates"][0])
    if rep.get("note"):
        print("NOTE      ", rep["note"])
    print("=" * W)

    for cat, rules in rep["indicators"].items():
        conf = [r for r in rules if r["status"] == "CONFIRMED"]
        if not conf:
            continue
        print("\n[%s]" % cat.upper())
        for r in conf:
            where = []
            if r["table_hit_count"]:
                where.append("%d string%s" % (r["table_hit_count"],
                                              "" if r["table_hit_count"] == 1 else "s"))
            if r["in_resolved_source"]:
                where.append("resolved src")
            print("  CONFIRMED  %-28s (%s)" % (r["label"], ", ".join(where)))
            for h in r["table_hits"][:3]:
                v = h["value"].replace("\n", "\\n")
                print("             %4d  %s" % (h["index"], v[:88]))

    if rep["crypto_material"]:
        print("\n[CRYPTO MATERIAL]")
        for f in rep["crypto_material"][:20]:
            print("  %-28s %s" % (f["label"], str(f["value"])[:60]))

    st = rep["storage"]
    if st["call_sites"]:
        print("\n[STORAGE CALL SITES]  keys hashed:", st["keys_appear_hashed"])
        for c in st["call_sites"][:12]:
            print("  %s.%s(%s" % (c["store"], c["op"], c["key_expr"][:70]))

    if rep["routes"]:
        print("\n[ROUTES]")
        for r in rep["routes"][:30]:
            print("  %4d  %s" % (r["index"], r["path"]))

    if rep["urls"]:
        print("\n[URLS]")
        for u in rep["urls"][:30]:
            print("  ", u)

    if "hash_crack" in rep:
        hc = rep["hash_crack"]
        print("\n[HASH CRACK]  target %s  tested %d candidates"
              % (hc["target"][:32], hc["candidates_tested"]))
        if hc["hits"]:
            for h in hc["hits"]:
                print("  MATCH  %s(%s)  ->  %r" % (h["algo"], h["encoding"], h["plaintext"]))
        else:
            print("  no match in this table (value likely server-issued)")

    # explicit negative reporting
    print("\n[NOT FOUND]  meaningful only because source was resolved")
    for cat, rules in rep["indicators"].items():
        miss = [r["label"] for r in rules if r["status"] != "CONFIRMED"]
        if miss:
            print("  %-14s %s" % (cat, ", ".join(miss)))
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--json", help="write JSON report here")
    ap.add_argument("--resolved", help="directory to write resolved sources")
    ap.add_argument("--strtab", help="directory to write decoded string tables")
    ap.add_argument("--crack", help="hex hash to crack against the string table")
    args = ap.parse_args()

    all_reports = []
    for p in args.files:
        rep, decoded, resolved = analyze_file(p, crack=args.crack)
        print_report(rep)
        all_reports.append(rep)
        if args.resolved:
            os.makedirs(args.resolved, exist_ok=True)
            with open(os.path.join(args.resolved,
                                   os.path.basename(p) + ".resolved.js"), "w") as f:
                f.write(resolved)
        if args.strtab:
            os.makedirs(args.strtab, exist_ok=True)
            with open(os.path.join(args.strtab,
                                   os.path.basename(p) + ".strtab.txt"), "w") as f:
                for i, v in enumerate(decoded):
                    f.write("%5d\t%s\n" % (i, (v or "<undecoded>").replace("\n", "\\n")))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(all_reports, f, indent=2)
        print("JSON report ->", args.json)


if __name__ == "__main__":
    main()
