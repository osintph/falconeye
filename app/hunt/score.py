"""Score a probed Hunt candidate and assign a verdict with visible evidence.

Verdicts: likely phishing, suspicious, parked, unknown, unrelated. The score is a
0 to 100 sum of weighted signals; the evidence list is what the report and the
portal show, so a verdict is never a bare number.

The model, from the v3.38.2 brief. LIKELY PHISHING requires at least one STRONG
signal: content imitating the hunted brand or its legitimate site (favicon hash
match, a close title match, or brand-impersonation markers for the hunted brand),
a known-bad listing, or a recent registration (under 90 days) together with live
non-parked content. A keyword in the name plus MX alone is SUSPICIOUS at most. A
registration older than two years with no content signal is lowered. Parking,
registry and marketplace landing pages are PARKED; a domain that resolves but
could not be fetched is UNKNOWN. No em dashes in this module.
"""
from __future__ import annotations

from app.scanner.scope import registrable

try:
    from rapidfuzz import fuzz as _fuzz
except Exception:  # noqa: BLE001 - optional; similarity just contributes less
    _fuzz = None

_PHISH_WORDS = ("login", "signin", "verify", "verification", "refund", "payment",
                "update", "portal", "claim", "secure", "account", "confirm", "billing")

LIKELY = 65
SUSPICIOUS = 30


def _label(domain: str) -> str:
    reg = registrable(domain) or domain
    return reg.split(".", 1)[0]


def score_candidate(c: dict, keyword: str, legit_domain: str) -> dict:
    ev = list(c.get("evidence") or [])
    dom = c.get("domain", "")
    label = _label(dom)

    if not c.get("resolves"):
        c["score"] = 0
        c["verdict"] = "unrelated"
        c["evidence"] = ev or ["does not resolve"]
        return c

    score = 0
    kw = (keyword or "").lower()
    legit_label = _label(legit_domain) if legit_domain else ""

    # Weak, structural signals. None of these alone is enough for likely phishing.
    brand_in_name = bool((kw and kw in label) or (legit_label and legit_label in label
                                                   and label != legit_label))
    if brand_in_name:
        score += 20
        ev.append("uses the brand name in the domain")
    if legit_domain and _fuzz and label != legit_label and _fuzz.ratio(label, legit_label) >= 80:
        score += 20
        ev.append("close permutation of the legitimate domain")
    title = (c.get("title") or "").lower()
    if any(w in label or w in title for w in _PHISH_WORDS):
        score += 20
        ev.append("phishing keyword in the name or page title")
    if c.get("has_mx"):
        score += 10
        ev.append("MX configured (can send or receive mail)")
    if c.get("fresh_cert"):
        score += 15
        ev.append("certificate issued within 30 days")

    parked = bool(c.get("parked"))
    fetched = bool(c.get("fetched"))
    live_content = fetched and not parked
    age = c.get("reg_age_days")
    recent = isinstance(age, int) and 0 <= age <= 90

    # Strong, content signals. assess_content suppresses brand and PH markers on
    # parked and marketplace pages, so payment logos there do not count.
    favicon = bool(c.get("favicon_match"))
    title_imitates = c.get("legit_title_sim", 0) >= 70
    hunted_brand = c.get("brand_markers", 0) > 0
    known_bad = bool(c.get("known_bad"))
    if favicon:
        score += 35
    if title_imitates:
        score += 30
    if hunted_brand:
        score += 30
    if known_bad:
        score += 50
    if c.get("ph_indicators") and not parked:
        score += 10
        ev.append(f"PH phishing indicators ({c['ph_indicators']})")

    if isinstance(age, int) and age >= 0:
        if age <= 7:
            score += 25
            ev.append(f"registered {age} days ago")
        elif age <= 30:
            score += 18
            ev.append(f"registered {age} days ago")
        elif age <= 90:
            score += 10
            ev.append(f"registered {age} days ago")

    strong = bool(favicon or title_imitates or hunted_brand or known_bad or
                  (recent and live_content))

    # An old domain (over two years) with no content signal is almost never an
    # active impersonation, so lower it.
    if isinstance(age, int) and age > 730 and not strong:
        score = max(0, score - 15)
        ev.append("registered over two years ago with no content signal")

    score = min(100, score)
    c["score"] = score
    c["strong"] = strong

    if parked:
        c["verdict"] = "parked"
    elif not fetched:
        c["verdict"] = "unknown"
        ev.append("resolves but is behind a Cloudflare challenge, could not assess"
                  if c.get("cloudflare") else "resolves but the homepage could not be fetched")
    elif known_bad or (strong and score >= LIKELY):
        c["verdict"] = "likely phishing"
    elif score >= SUSPICIOUS:
        c["verdict"] = "suspicious"
    else:
        c["verdict"] = "unrelated"

    c["evidence"] = ev or ["no impersonation markers"]
    return c
