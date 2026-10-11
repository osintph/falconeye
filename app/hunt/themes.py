"""Brand theme lexicons, keyword-relevance classification and cheap-TLD list for
the Phishing Domain Hunt.

A keyword match is only interesting when the brand appears as a real token or next
to a brand theme term (mmda+ncap, philhealth+member), not when the brand letters
are buried inside an unrelated word (stammdaten, hommdays). A theme term in the
domain or the page title is a strong impersonation signal and the seed for
campaign clustering. No em dashes in this module.
"""
from __future__ import annotations

from app.scanner.scope import registrable

# Per-brand theme terms. A term appearing in the domain or page title alongside
# the brand is a strong signal. Keyed by the hunt keyword (lowercased).
THEMES = {
    "mmda": ["ncap", "lto", "ncr", "violation", "fine", "penalty", "ticket",
             "apprehension", "plate", "license", "citation"],
    "philhealth": ["member", "konsulta", "benefit", "contribution", "claim", "refund",
                   "portal", "registration", "yakap", "ekonsulta"],
    "sss": ["contribution", "member", "loan", "benefit", "pension", "sickness",
            "maternity", "umid", "registration", "disbursement"],
    "pagibig": ["loan", "contribution", "member", "savings", "mp2", "housing",
                "calamity", "registration", "virtual"],
    "pag-ibig": ["loan", "contribution", "member", "savings", "mp2", "housing",
                 "calamity", "registration", "virtual"],
    "bir": ["tax", "efps", "tin", "filing", "return", "payment", "registration",
            "ereg", "orus", "refund"],
    "lto": ["license", "plate", "registration", "renewal", "violation", "driver",
            "ltms", "portal", "ncap"],
    "dfa": ["passport", "appointment", "apostille", "visa", "consular", "renewal",
            "schedule", "epassport"],
    "gsis": ["pension", "loan", "member", "benefit", "ecard", "retirement", "claim",
             "touchpoint"],
    "gcash": ["wallet", "cashin", "verify", "account", "otp", "send", "reward",
              "voucher", "borrow", "gcredit"],
    "maya": ["wallet", "account", "verify", "otp", "cashin", "reward", "credit",
             "savings"],
    "bdo": ["online", "banking", "account", "verify", "otp", "card", "rewards",
            "unlock", "secure"],
    "bpi": ["online", "banking", "account", "verify", "otp", "card", "rewards",
            "unlock", "secure"],
    "landbank": ["online", "banking", "account", "verify", "iaccess", "link",
                 "weaccess", "secure"],
    "metrobank": ["online", "banking", "account", "verify", "otp", "card", "rewards",
                  "secure", "mb"],
}

# Generic phishing words (brand independent). Adjacent to a brand they add weight.
PHISH_TERMS = ["login", "signin", "verify", "verification", "secure", "account",
               "confirm", "update", "portal", "claim", "refund", "payment", "billing",
               "otp", "apply", "registration", "support", "help", "official", "gov"]

# Cheap, abuse-heavy TLDs that add weight to a candidate. Maintained here.
CHEAP_TLDS = {"icu", "sbs", "work", "club", "qpon", "yoga", "surf", "luxe", "top",
              "xyz", "cam", "vip", "buzz", "rest", "monster", "cfd", "bond", "quest",
              "lol", "makeup", "skin", "fun", "online", "site", "shop", "click",
              "link", "live", "ltd", "space", "store", "website", "pw", "gq", "cfd"}


try:
    from rapidfuzz.distance import DamerauLevenshtein as _DL
except Exception:  # noqa: BLE001
    _DL = None


def themes_for(keyword: str) -> list:
    return THEMES.get((keyword or "").lower(), [])


def _fuzzy_find(label: str, term: str):
    """Return the substring of *label* that matches *term*, exactly or as a close
    variant: edit distance 1 for terms of 4+ characters (so ncpa matches ncap), and
    for 3-letter terms only an exact match or a transposition of the same letters
    (lot matches lto), never an indel or substitution (which would match nc or ncp
    to ncr). More distant scrambles (ncpo, nocp) are caught by the campaign
    infrastructure merge, not here. Returns the matched variant or None."""
    term = term.lower()
    if term in label:
        return term
    if _DL is None:
        return None
    L = len(term)
    if L <= 3:
        for i in range(0, len(label) - L + 1):
            sub = label[i:i + L]
            if sorted(sub) == sorted(term) and _DL.distance(sub, term) <= 1:
                return sub
        return None
    for w in (L - 1, L, L + 1):
        for i in range(0, len(label) - w + 1):
            sub = label[i:i + w]
            if _DL.distance(sub, term) <= 1:
                return sub
    return None


def theme_variants(text: str, keyword: str) -> list:
    """List of (term, matched_variant) for brand theme terms found in *text*,
    including near variants. The variant drives the evidence line."""
    low = (text or "").lower()
    out = []
    for t in themes_for(keyword):
        v = _fuzzy_find(low, t)
        if v:
            out.append((t, v))
    return out


def _reg_label(domain: str) -> str:
    reg = registrable(domain) or domain
    return reg.split(".", 1)[0]


def cheap_tld(domain: str) -> bool:
    reg = registrable(domain) or domain
    suffix = reg.split(".", 1)[1] if "." in reg else ""
    # Any label of the suffix in the cheap set (covers .sbs and foo.sbs).
    return any(part in CHEAP_TLDS for part in suffix.split("."))


def matched_themes(text: str, keyword: str) -> list:
    """Theme terms present in *text*, matching near variants (ncpa ~ ncap)."""
    return [t for t, _ in theme_variants(text, keyword)]


def classify(domain: str, keyword: str, title: str = "") -> dict:
    """Classify a keyword hit. Returns relevant/buried plus the theme and phishing
    terms found. The brand is relevant when it is a real token (a hyphen-split
    part, the whole label, or a prefix or suffix of the label) or when a theme or
    phishing term appears in the label; otherwise the brand letters are buried in
    an unrelated word and the hit is irrelevant."""
    brand = (keyword or "").lower()
    label = _reg_label(domain)
    # Exact theme matches gate relevance (keep/drop); fuzzy matches only populate
    # the themes used for clustering and scoring, so a fuzzy near-match (plate ~
    # pdate in "updaten") can never keep an otherwise irrelevant domain.
    exact_label_themes = [t for t in themes_for(keyword) if t in label]
    label_themes = matched_themes(label, keyword)
    title_themes = matched_themes(title, keyword)
    phish = [t for t in PHISH_TERMS if t in label]
    parts = label.split("-")
    # The brand is a clean token when it is the whole label, a hyphen-split part,
    # or sits at an edge of the label as either a long distinctive brand (6+ chars)
    # or with only a short affix attached. A short brand buried in the middle of a
    # longer word (mmdancesupplies, stammdaten) is not a token.
    at_edge = (label != brand) and (label.startswith(brand) or label.endswith(brand))
    short_affix = (len(label) - len(brand)) <= 5
    clean_token = (label == brand or brand in parts
                   or (at_edge and (len(brand) >= 6 or short_affix)))
    # Relevance uses the brand token and brand-specific theme terms only. Generic
    # phishing words are NOT part of the keep/drop gate because they substring
    # match foreign words (the German "updaten" contains "update"), which would
    # keep unrelated sites. Phishing words still add score once a hit is kept.
    relevant = bool(clean_token or exact_label_themes)
    buried = (brand in label) and not relevant
    variants = theme_variants(label, keyword) + theme_variants(title, keyword)
    # Evidence strings: "ncpa ~ ncap" for a near variant, "ncap" when exact.
    ev = sorted({(f"{v} ~ {t}" if v != t else t) for t, v in variants})
    return {
        "relevant": relevant, "buried": buried, "token": clean_token,
        "themes": sorted(set(label_themes) | set(title_themes)),
        "theme_evidence": ev, "label_themes": label_themes, "phish": phish,
    }
