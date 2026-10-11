"""Score a probed Hunt candidate and assign a verdict with visible evidence.

Verdicts: likely phishing, suspicious, parked, unknown, unrelated.

The v3.38.6 model recognises real campaigns. Likely Phishing when ANY of: the
brand with a theme term and a registration under 90 days; membership of a campaign
cluster; an urlscan malicious or phishing label; or page content imitating the
brand (favicon match, close title match, hunted-brand markers, or a URLhaus
listing). Cheap, abuse-heavy TLDs add weight. A domain urlscan observed recently
that no longer resolves is "possibly taken down": it keeps its urlscan evidence
and score and is never dropped to Unknown. No em dashes in this module.
"""
from __future__ import annotations

from app.hunt import themes as themes_mod
from app.scanner.scope import registrable

try:
    from rapidfuzz import fuzz as _fuzz
except Exception:  # noqa: BLE001
    _fuzz = None

LIKELY = 65
SUSPICIOUS = 30


def _label(domain: str) -> str:
    reg = registrable(domain) or domain
    return reg.split(".", 1)[0]


def _malicious(labels) -> bool:
    return any(str(x).lower() in ("phishing", "malicious", "suspicious")
               for x in (labels or []))


def score_candidate(c: dict, keyword: str, legit_domain: str) -> dict:
    ev = list(c.get("evidence") or [])
    dom = c.get("domain", "")
    label = _label(dom)
    urls = c.get("urlscan") or {}
    observed = bool(urls)
    resolves = bool(c.get("resolves"))
    fetched = bool(c.get("fetched"))
    # Possibly taken down: urlscan saw it recently, but it no longer resolves.
    taken_down = observed and not resolves

    if not resolves and not observed:
        c["score"] = 0
        c["verdict"] = "unrelated"
        c["evidence"] = ev or ["does not resolve"]
        return c

    score = 0
    kw = (keyword or "").lower()
    legit_label = _label(legit_domain) if legit_domain else ""

    brand_in_name = bool((kw and kw in label) or (legit_label and legit_label in label
                                                  and label != legit_label))
    if brand_in_name:
        score += 15
        ev.append("uses the brand name in the domain")
    if legit_domain and _fuzz and label != legit_label and _fuzz.ratio(label, legit_label) >= 80:
        score += 15
        ev.append("close permutation of the legitimate domain")

    title = (c.get("title") or urls.get("title") or "")
    theme_terms = sorted(set(c.get("themes") or []) | set(themes_mod.matched_themes(title, keyword)))
    theme_hit = bool(theme_terms)
    if theme_hit:
        score += 25
        ev.append(f"brand theme term in the name or title ({', '.join(theme_terms)})")
    if any(w in label or w in title.lower() for w in themes_mod.PHISH_TERMS):
        score += 10
        ev.append("phishing keyword in the name or title")

    # Registration age: prefer RDAP/whois, fall back to urlscan's reported age.
    age = c.get("reg_age_days")
    if age is None and isinstance(urls.get("age_days"), int):
        age = urls["age_days"]
    recent = isinstance(age, int) and 0 <= age <= 90
    if isinstance(age, int) and age >= 0:
        if age <= 7:
            score += 35
        elif age <= 30:
            score += 28
        elif age <= 90:
            score += 18
        else:
            score += 0
        ev.append(f"registered {age} days ago")

    cheap = themes_mod.cheap_tld(dom)
    if cheap:
        score += 12
        ev.append("cheap, abuse-heavy TLD")
    if c.get("has_mx"):
        score += 8
        ev.append("MX configured")
    if c.get("fresh_cert"):
        score += 12
        ev.append("certificate issued within 30 days")

    favicon = bool(c.get("favicon_match"))
    title_imitates = c.get("legit_title_sim", 0) >= 70
    hunted_brand = c.get("brand_markers", 0) > 0
    known_bad = bool(c.get("known_bad"))
    urlscan_malicious = _malicious(urls.get("labels"))
    if favicon:
        score += 30
    if title_imitates:
        score += 28
    if hunted_brand:
        score += 28
    if known_bad:
        score += 50
        ev.append("listed on URLhaus")
    if urlscan_malicious:
        score += 45
        ev.append(f"urlscan flagged it ({', '.join(urls.get('labels') or [])})")
    if observed:
        score += 6
        ev.append("observed live by urlscan")
    if c.get("ph_indicators") and not c.get("parked"):
        score += 8
        ev.append(f"PH phishing indicators ({c['ph_indicators']})")

    campaign = bool(c.get("campaign_member"))
    if campaign:
        score += 40
        ev.append("member of a detected campaign cluster")

    score = min(100, score)
    c["score"] = score

    page_class = c.get("page_class") or ""
    informational = page_class == "informational"
    # Phishing CONTENT: a credential or payment form, imitation of the legit site
    # (favicon or close title match), or a page urlscan or the engine flagged.
    phish_content = bool(page_class == "phishing" or favicon or title_imitates
                         or c.get("has_cred_form") or c.get("has_payment_form") or known_bad)

    # Likely Phishing requires at least one strong, evidenced condition. A brand
    # plus theme name alone, especially on an old informational page, is not enough.
    theme_recent_live = bool(theme_hit and recent and fetched and not informational
                             and not c.get("parked"))
    likely = bool(campaign or phish_content or urlscan_malicious or theme_recent_live)

    if taken_down:
        ev.append("possibly taken down (urlscan observed it recently, no longer resolves)")

    if c.get("parked"):
        c["verdict"] = "parked"
    elif likely:
        c["verdict"] = "likely phishing"
    elif informational:
        c["verdict"] = "brand-referencing"
    elif score >= SUSPICIOUS:
        c["verdict"] = "suspicious"
    elif resolves and not fetched and not observed:
        c["verdict"] = "unknown"
        ev.append("resolves but is behind a Cloudflare challenge, could not assess"
                  if c.get("cloudflare") else "resolves but the homepage could not be fetched")
    else:
        c["verdict"] = "unrelated"

    c["evidence"] = ev or ["no impersonation markers"]
    return c
