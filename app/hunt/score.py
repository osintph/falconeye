"""Score a probed Hunt candidate and assign a verdict with visible evidence.

Verdicts: likely phishing, suspicious, parked, unrelated. The score is a 0 to 100
sum of weighted signals; the evidence list is what the report and the portal
show, so a verdict is never a bare number. No em dashes in this module.
"""
from __future__ import annotations

from app.scanner.scope import registrable

try:
    from rapidfuzz import fuzz as _fuzz
except Exception:  # noqa: BLE001 - optional; similarity just contributes less
    _fuzz = None

_COMBO = ("login", "verify", "refund", "payment", "update", "portal", "secure", "account")


def _label(domain: str) -> str:
    reg = registrable(domain) or domain
    return reg.split(".", 1)[0]


def score_candidate(c: dict, keyword: str, legit_domain: str) -> dict:
    score = 0
    ev = list(c.get("evidence") or [])

    if not c.get("resolves"):
        c["score"] = 0
        c["verdict"] = "unrelated"
        c["evidence"] = ev or ["does not resolve"]
        return c

    age = c.get("reg_age_days")
    if age is not None:
        if age <= 7:
            score += 35
            ev.append(f"registered {age} days ago")
        elif age <= 30:
            score += 25
            ev.append(f"registered {age} days ago")
        elif age <= 90:
            score += 10
            ev.append(f"registered {age} days ago")
    if c.get("fresh_cert"):
        score += 15
        ev.append("certificate issued within 30 days")
    if c.get("has_mx"):
        score += 10
        ev.append("MX configured")
    if c.get("brand_markers"):
        score += 20
        ev.append(f"brand markers for {c.get('brand') or 'a known brand'}")
    if c.get("ph_indicators"):
        score += 20
        ev.append(f"PH phishing indicators ({c['ph_indicators']})")
    if c.get("favicon_match"):
        score += 25
    if c.get("cloudflare"):
        score += 8
    title = (c.get("title") or "").lower()
    dom = c.get("domain", "")
    if any(w in dom or w in title for w in _COMBO):
        score += 10
        ev.append("phishing keyword in the name or title")

    # String closeness to the legitimate label (homoglyph or typo).
    if legit_domain and _fuzz:
        sim = _fuzz.ratio(_label(dom), _label(legit_domain))
        if sim >= 80 and _label(dom) != _label(legit_domain):
            score += 15
            ev.append("close permutation of the legitimate domain")

    score = min(100, score)
    c["score"] = score

    if c.get("parked"):
        c["verdict"] = "parked"
        ev.append("parking or for-sale page")
    elif score >= 70:
        c["verdict"] = "likely phishing"
    elif score >= 35:
        c["verdict"] = "suspicious"
    else:
        c["verdict"] = "unrelated"
    c["evidence"] = ev or ["no impersonation markers"]
    return c
