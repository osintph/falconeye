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

# Per-brand LURE FAMILIES. A family groups the theme terms that advance the same
# lure (traffic fines, benefits, membership, ...), with the English and Tagalog
# spellings together. Campaign clustering keys on the family, not the single term,
# so mmda-mayhuliks (huli) and mmdancap (ncap) cluster as one traffic-fine
# campaign when they pass the corroboration gate. Keyed by the hunt keyword.
FAMILIES = {
    "mmda": {
        "traffic-fines": ["ncap", "lto", "ncr", "violation", "fine", "penalty",
                          "ticket", "apprehension", "plate", "license", "citation",
                          "huli", "mayhuli", "hulihan", "multa", "sitasyon", "bawal"],
    },
    "philhealth": {
        "benefits": ["benefit", "benepisyo", "claim", "refund", "konsulta",
                     "ekonsulta", "yakap"],
        "membership": ["member", "miyembro", "registration", "portal",
                       "contribution", "kontribusyon", "tulong"],
    },
    "sss": {
        "benefits": ["benefit", "benepisyo", "pension", "pensyon", "sickness",
                     "maternity", "disbursement"],
        "membership": ["member", "contribution", "kontribusyon", "registration", "umid"],
        "loans": ["loan", "utang"],
    },
    "pagibig": {
        "loans": ["loan", "utang", "calamity"],
        "savings": ["savings", "mp2", "ipon"],
        "housing": ["housing", "pabahay"],
        "membership": ["member", "contribution", "registration", "virtual"],
    },
    "bir": {
        "tax": ["tax", "buwis", "efps", "tin", "filing", "return", "payment",
                "registration", "ereg", "orus", "refund"],
    },
    "lto": {
        "licensing": ["license", "lisensya", "plate", "registration", "rehistro",
                      "renewal", "driver", "ltms", "portal"],
        "violations": ["violation", "ncap", "multa"],
    },
    "dfa": {
        "passport": ["passport", "pasaporte", "appointment", "appointmnt", "apostille",
                     "visa", "consular", "renewal", "schedule", "epassport"],
    },
    "gsis": {
        "benefits": ["pension", "pensyon", "benefit", "benepisyo", "retirement", "claim"],
        "membership": ["member", "loan", "ecard", "touchpoint"],
    },
    "gcash": {
        "wallet": ["wallet", "cashin", "verify", "account", "otp", "send", "gcredit",
                   "borrow"],
        "rewards": ["reward", "voucher", "padala", "premyo", "panalo"],
    },
    "maya": {
        "wallet": ["wallet", "account", "verify", "otp", "cashin", "credit", "savings"],
        "rewards": ["reward", "padala", "premyo", "panalo"],
    },
    "bdo": {"banking": ["online", "banking", "account", "verify", "otp", "card",
                        "rewards", "unlock", "secure"]},
    "bpi": {"banking": ["online", "banking", "account", "verify", "otp", "card",
                        "rewards", "unlock", "secure"]},
    "landbank": {"banking": ["online", "banking", "account", "verify", "iaccess",
                            "link", "weaccess", "secure"]},
    "metrobank": {"banking": ["online", "banking", "account", "verify", "otp", "card",
                             "rewards", "secure", "mb"]},
}
FAMILIES["pag-ibig"] = FAMILIES["pagibig"]

# Flat per-brand theme list, derived from the families (one source of truth), and
# the reverse term -> family map used to key campaign clustering.
THEMES = {brand: sorted({t for terms in fams.values() for t in terms})
          for brand, fams in FAMILIES.items()}
_TERM_FAMILY = {brand: {t: fam for fam, terms in fams.items() for t in terms}
                for brand, fams in FAMILIES.items()}

# Generic phishing words (brand independent). Adjacent to a brand they add weight.
PHISH_TERMS = ["login", "signin", "verify", "verification", "secure", "account",
               "confirm", "update", "portal", "claim", "refund", "payment", "billing",
               "otp", "apply", "registration", "support", "help", "official", "gov"]

# Cheap, abuse-heavy TLDs that add weight to a candidate. Maintained here.
CHEAP_TLDS = {"icu", "sbs", "work", "club", "qpon", "yoga", "surf", "luxe", "top",
              "xyz", "cam", "vip", "buzz", "rest", "monster", "cfd", "bond", "quest",
              "lol", "makeup", "skin", "fun", "online", "site", "shop", "click",
              "link", "live", "ltd", "space", "store", "website", "pw", "gq", "cfd"}


# Explicit, maintained spelling variants of a theme term (observed scrambles), per
# term. This REPLACES generic edit-distance matching, which drifted onto common
# words (cashin ~ casino). A variant must never be a common dictionary word. A
# variant match is flagged and can never be the sole evidence for Likely Phishing.
VARIANTS = {
    # traffic-fines: NCAP scrambles seen in the wild.
    "ncap": ("ncpo", "ncpa", "nocp", "ncapp", "ncop", "nccap", "ncaap"),
}


def themes_for(keyword: str) -> list:
    return THEMES.get((keyword or "").lower(), [])


def _variant_match(text: str, term: str):
    """(matched_substring, is_exact) for *term* in *text*: the exact term, else a
    maintained variant, else (None, False). No edit distance, so a variant never
    lands on a common word."""
    if term in text:
        return term, True
    for v in VARIANTS.get(term, ()):
        if v in text:
            return v, False
    return None, False


def family_of(keyword: str, term: str) -> str | None:
    """The lure family a theme term belongs to for this brand, or None."""
    return _TERM_FAMILY.get((keyword or "").lower(), {}).get(term)


def families_of(keyword: str, terms) -> list:
    """The sorted set of lure families covered by the given matched theme terms.
    This is the key campaign clustering groups on, not the single term."""
    fams = _TERM_FAMILY.get((keyword or "").lower(), {})
    return sorted({fams[t] for t in (terms or []) if t in fams})


def theme_variants(text: str, keyword: str) -> list:
    """List of (term, matched, is_exact) for brand theme terms found in *text*,
    matching the exact term or a maintained variant. The matched string drives the
    evidence line; is_exact marks whether it was an exact hit."""
    low = (text or "").lower()
    out = []
    for t in themes_for(keyword):
        matched, exact = _variant_match(low, t)
        if matched:
            out.append((t, matched, exact))
    return out


def _reg_label(domain: str) -> str:
    # PSL-private aware: a platform subdomain (foo.pages.dev) keeps its own label
    # so the brand in the subdomain is seen, not the platform apex.
    reg = registrable(domain, private=True) or domain
    return reg.split(".", 1)[0]


def cheap_tld(domain: str) -> bool:
    reg = registrable(domain, private=True) or domain
    suffix = reg.split(".", 1)[1] if "." in reg else ""
    # Any label of the suffix in the cheap set (covers .sbs and foo.sbs).
    return any(part in CHEAP_TLDS for part in suffix.split("."))


def matched_themes(text: str, keyword: str) -> list:
    """Theme terms present in *text* (exact term or a maintained variant)."""
    return [t for t, _m, _e in theme_variants(text, keyword)]


def exact_matched_themes(text: str, keyword: str) -> list:
    """Theme terms present in *text* by an EXACT match only (not a variant)."""
    return [t for t, _m, exact in theme_variants(text, keyword) if exact]


def classify(domain: str, keyword: str, title: str = "") -> dict:
    """Classify a keyword hit. Returns relevant/buried plus the theme and phishing
    terms found. The brand is relevant when it is a real token (a hyphen-split
    part, the whole label, or a prefix or suffix of the label) or when a theme or
    phishing term appears in the label; otherwise the brand letters are buried in
    an unrelated word and the hit is irrelevant."""
    brand = (keyword or "").lower()
    label = _reg_label(domain)
    # Exact theme matches gate relevance (keep/drop); variant matches only populate
    # the themes used for clustering and scoring, so a variant hit can never keep an
    # otherwise irrelevant domain.
    exact_label_themes = [t for t in themes_for(keyword) if t in label]
    label_themes = matched_themes(label, keyword)
    title_themes = matched_themes(title, keyword)
    exact_themes = sorted(set(exact_matched_themes(label, keyword))
                          | set(exact_matched_themes(title, keyword)))
    phish = [t for t in PHISH_TERMS if t in label]
    parts = label.split("-")
    # The brand is a clean token when it is the whole label, a hyphen-split part, or
    # at a label edge. A short brand (under 6 chars) is a token at an edge only when
    # it is the PREFIX with a short remainder (gcash-xyz): a short brand at the
    # SUFFIX with an unknown prefix is the brand's letters buried in another word
    # (dan+gcash, mixin+gcash) and is not a token. A long brand (6+) at either edge
    # is a token. A short brand buried in the middle (stammdaten) is never a token.
    prefix = (label != brand) and label.startswith(brand)
    suffix = (label != brand) and label.endswith(brand)
    short_affix = (len(label) - len(brand)) <= 5
    clean_token = (label == brand or brand in parts
                   or (prefix and (len(brand) >= 6 or short_affix))
                   or (suffix and len(brand) >= 6))
    # The brand at an edge joined to a known phishing or theme affix (mmdaportal,
    # login-gcash) is relevant: brand plus a lure word, not buried letters. The
    # affix is the edge remainder, and it counts only when it begins or ends with a
    # known term, so a foreign word that merely contains one (the German "updaten")
    # is not kept.
    affix_terms = set(PHISH_TERMS) | set(themes_for(keyword)) | {"online", "member", "ph"}
    for _t in themes_for(keyword):  # maintained theme variants count as known affixes
        affix_terms |= set(VARIANTS.get(_t, ()))
    affixes = []
    if prefix:
        affixes.append(label[len(brand):].strip("-"))
    if suffix:
        affixes.append(label[:-len(brand)].strip("-"))
    affix_relevant = any(
        a and (a in affix_terms or any(a.startswith(t) or a.endswith(t) for t in affix_terms))
        for a in affixes)
    relevant = bool(clean_token or exact_label_themes or affix_relevant)
    buried = (brand in label) and not relevant
    variants = theme_variants(label, keyword) + theme_variants(title, keyword)
    # Evidence strings: "ncpo ~ ncap" for a variant, "ncap" when exact.
    ev = sorted({(f"{m} ~ {t}" if not exact else t) for t, m, exact in variants})
    return {
        "relevant": relevant, "buried": buried, "token": clean_token,
        "themes": sorted(set(label_themes) | set(title_themes)),
        "exact_themes": exact_themes,
        "theme_evidence": ev, "label_themes": label_themes, "phish": phish,
    }
