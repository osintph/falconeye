"""Score a probed Hunt candidate and assign a verdict with visible evidence.

Verdicts: likely phishing, suspicious, parked, unknown, unrelated. The score is a
0 to 100 sum of weighted signals; the evidence list is what the report and the
portal show, so a verdict is never a bare number.

The model, from the v3.38.1 brief: a registered lookalike that carries a second
signal (MX, a phishing keyword, a recent registration or fresh cert, or brand
impersonation content) lands in SUSPICIOUS or LIKELY PHISHING. The brand name
alone in the domain is not enough, so an old unrelated company that happens to
contain the word stays unrelated. A domain that resolves but could not be fetched
is UNKNOWN, never counted as a clean unrelated. No em dashes in this module.
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

    # A non-resolving candidate is not registered (as far as we can see); it is
    # never a verdict row, so it scores zero and reads unrelated.
    if not c.get("resolves"):
        c["score"] = 0
        c["verdict"] = "unrelated"
        c["evidence"] = ev or ["does not resolve"]
        return c

    score = 0

    # The brand name sits in the domain. On its own this is weak (many legitimate
    # firms contain the word), so it needs a second signal to cross a threshold.
    kw = (keyword or "").lower()
    legit_label = _label(legit_domain) if legit_domain else ""
    brand_in_name = bool((kw and kw in label) or (legit_label and legit_label in label
                                                   and label != legit_label))
    if brand_in_name:
        score += 25
        ev.append("uses the brand name in the domain")

    # A close typo or homoglyph of the legitimate label.
    if legit_domain and _fuzz and label != legit_label:
        sim = _fuzz.ratio(label, legit_label)
        if sim >= 80:
            score += 20
            ev.append("close permutation of the legitimate domain")

    age = c.get("reg_age_days")
    if isinstance(age, int) and age >= 0:
        if age <= 7:
            score += 30
            ev.append(f"registered {age} days ago")
        elif age <= 30:
            score += 22
            ev.append(f"registered {age} days ago")
        elif age <= 90:
            score += 12
            ev.append(f"registered {age} days ago")
    if c.get("fresh_cert"):
        score += 18
        ev.append("certificate issued within 30 days")
    if c.get("has_mx"):
        score += 15
        ev.append("MX configured (can send or receive mail)")

    title = (c.get("title") or "").lower()
    if any(w in label or w in title for w in _PHISH_WORDS):
        score += 25
        ev.append("phishing keyword in the name or page title")

    if c.get("brand_markers"):
        score += 25
        ev.append(f"brand impersonation content for {c.get('brand') or 'a known brand'}")
    if c.get("ph_indicators"):
        score += 22
        ev.append(f"PH phishing indicators ({c['ph_indicators']})")
    if c.get("favicon_match"):
        score += 30
        # evidence for the favicon match is added at probe time
    if c.get("cloudflare"):
        score += 5

    score = min(100, score)
    c["score"] = score

    resolves = c.get("resolves")
    fetched = c.get("fetched")
    if c.get("parked"):
        c["verdict"] = "parked"
        ev.append("parking or for-sale page")
    elif score >= LIKELY:
        c["verdict"] = "likely phishing"
    elif score >= SUSPICIOUS:
        c["verdict"] = "suspicious"
    elif resolves and not fetched:
        # It exists but we could not read it (probe failed or a Cloudflare
        # challenge). Not a clean unrelated.
        c["verdict"] = "unknown"
        if c.get("cloudflare"):
            ev.append("resolves but is behind a Cloudflare challenge, could not assess")
        else:
            ev.append("resolves but the homepage could not be fetched")
    else:
        c["verdict"] = "unrelated"

    c["evidence"] = ev or ["no impersonation markers"]
    return c
