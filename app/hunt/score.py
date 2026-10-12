"""Score a probed Hunt candidate and assign a verdict with visible evidence.

Verdicts: likely phishing, suspicious, brand-referencing, parked, unknown,
unrelated.

The v3.38.9 model. Age is the domain registration date (RDAP or whois) or, when
that is unavailable, the earliest certificate ever logged in certificate
transparency (first live); the current certificate is not a signal. A credential
or payment form is phishing evidence only alongside brand imitation (hunted brand
name, favicon hash or close title match) or a registration or first-live under 90
days; a generic login on an old domain with no brand imitation is Unrelated. A
young brand-themed domain that serves a blank or near-empty page is a possible
geofenced kit. Campaigns boost only when corroborated. No em dashes here.
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
    taken_down = observed and not resolves
    c["drop_noise"] = False

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
    close_perm = bool(legit_domain and _fuzz and label != legit_label
                      and _fuzz.ratio(label, legit_label) >= 80)
    if close_perm:
        score += 15
        ev.append("close permutation of the legitimate domain")

    title = (c.get("title") or urls.get("title") or "")
    theme_terms = sorted(set(c.get("themes") or []) | set(themes_mod.matched_themes(title, keyword)))
    exact_terms = sorted(set(c.get("themes_exact") or [])
                         | set(themes_mod.exact_matched_themes(title, keyword)))
    theme_hit = bool(theme_terms)
    exact_theme_hit = bool(exact_terms)
    if theme_hit:
        score += 25
        ev.append(f"brand theme term in the name or title ({', '.join(theme_terms)})")
    if any(w in label or w in title.lower() for w in themes_mod.PHISH_TERMS):
        score += 10
        ev.append("phishing keyword in the name or title")

    # Age: registration date, else first-live from certificate transparency.
    reg_age = c.get("reg_age_days")
    if reg_age is None and isinstance(urls.get("age_days"), int):
        reg_age = urls["age_days"]
    ct_age = c.get("ct_first_seen_age")
    ages = [a for a in (reg_age, ct_age) if isinstance(a, int) and a >= 0]
    first_live = min(ages) if ages else None
    young = first_live is not None and first_live <= 90
    old = isinstance(reg_age, int) and reg_age > 730
    if young:
        bump = 35 if first_live <= 7 else (28 if first_live <= 30 else 18)
        score += bump
        basis = "registered" if reg_age == first_live else "first seen in CT"
        ev.append(f"{basis} {first_live} days ago")
    # Dormant domain recently activated: old registration, fresh first CT cert.
    dormant = old and isinstance(ct_age, int) and ct_age <= 90
    if dormant:
        score += 10
        ev.append(f"dormant domain recently activated (registered {reg_age} days ago, "
                  f"first certificate {ct_age} days ago)")

    cheap = themes_mod.cheap_tld(dom)
    if cheap:
        score += 12
        ev.append("cheap, abuse-heavy TLD")
    if c.get("has_mx"):
        score += 8
        ev.append("MX configured")

    favicon = bool(c.get("favicon_match"))
    title_imitates = c.get("legit_title_sim", 0) >= 80
    # Brand imitation requires the brand in page furniture, a favicon match, or two
    # or more non-name brand markers (assess_content decides and sets this flag). A
    # bare brand-name mention, including the domain's own name on its page, is NOT
    # imitation.
    hunted_brand = bool(c.get("brand_imitation"))
    known_bad = bool(c.get("known_bad"))
    urlscan_malicious = _malicious(urls.get("labels"))
    page_class = c.get("page_class") or ""
    brand_imitation = bool(favicon or title_imitates or hunted_brand
                           or page_class == "imitation")
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
        if c.get("campaign_join"):
            ev.append(c["campaign_join"])

    form = bool(c.get("has_cred_form") or c.get("has_payment_form"))
    # A form is phishing evidence only with brand imitation or a young domain.
    form_phishing = form and (brand_imitation or young)
    if form and not form_phishing:
        ev.append("has a login or payment form, but no brand imitation and not a young domain")
    geofenced_kit = bool(theme_hit and young and page_class == "thin")
    if geofenced_kit:
        ev.append("possible geofenced kit (young brand-themed domain serving a blank page)")

    score = min(100, score)
    c["score"] = score

    informational = page_class == "informational"
    phish_content = bool(brand_imitation or known_bad or urlscan_malicious or form_phishing)
    # A theme hit drives Likely on its own only when it is an EXACT theme term, not
    # a maintained spelling variant: a variant match is never the sole evidence for
    # Likely Phishing (it still boosts score and clustering, and a variant-themed
    # domain can be Likely via a corroborated campaign or real phishing content).
    theme_recent_live = bool(exact_theme_hit and young and fetched and not informational
                             and not c.get("parked"))
    # A corroborated campaign requires a distinctive shared attribute (generic
    # consumer hosting and CDN or cloud ASNs do not count), so membership is strong
    # evidence on its own: a member is Likely even if it currently serves an
    # informational page (campaigns cloak benign content to our vantage). The
    # protection against boosting informational name-matches is that they never
    # become campaign members when the only thing shared is generic hosting.
    # Exception: a gambling or payment-method page that names the brand (and does
    # not imitate its login or app) is brand-referencing even inside a cluster, so
    # campaign membership does not make it Likely.
    payment_ref = bool(c.get("payment_ref"))
    likely = bool((campaign and not payment_ref) or phish_content or theme_recent_live)

    # Irrelevant noise: a short-brand close permutation, over two years old, with no
    # theme and no content or campaign signal (mmdata.com.br). Dropped by the engine.
    short_brand = len(kw) <= 4
    if (short_brand and close_perm and old and not theme_hit and not phish_content
            and not campaign):
        c["drop_noise"] = True

    if taken_down:
        ev.append("possibly taken down (urlscan observed it recently, no longer resolves)")

    if c["drop_noise"]:
        c["verdict"] = "unrelated"
    elif c.get("parked"):
        c["verdict"] = "parked"
    elif likely:
        c["verdict"] = "likely phishing"
    elif informational:
        c["verdict"] = "brand-referencing"
    elif old and not brand_imitation and not campaign and not known_bad and not urlscan_malicious:
        # An old domain merely containing the brand: a form or theme without brand
        # imitation is not phishing (example: an old generic admin login).
        c["verdict"] = "unrelated"
    elif resolves and not fetched and not observed:
        c["verdict"] = "unknown"
        ev.append("resolves but is behind a Cloudflare challenge, could not assess"
                  if c.get("cloudflare") else "resolves but the homepage could not be fetched")
    elif score >= SUSPICIOUS:
        c["verdict"] = "suspicious"
    else:
        c["verdict"] = "unrelated"

    c["evidence"] = ev or ["no impersonation markers"]
    return c
