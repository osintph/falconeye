"""
PH banking and e-wallet phishing kit indicators.

Each indicator is a dict with:
  id          — unique snake_case identifier
  type        — "url_path", "domain_pattern", "html_content", or "html_structure"
  pattern     — string to search for (case-insensitive substring match)
  severity    — "high" | "medium" | "low"
  description — human-readable explanation for the analyst
  category    — short tag for grouping in the UI

TODO: Google Safe Browsing enrichment (GSB_API_KEY) — requires
  https://developers.google.com/safe-browsing/v4/lookup-api
  Add as a separate enrichment pass similar to urlscan, so GSB verdict
  supplements rather than overwrites indicator matching.
"""

from typing import Optional

# ---------------------------------------------------------------------------
# URL path patterns — suspicious path segments combined with PH bank context
# ---------------------------------------------------------------------------
URL_PATH_INDICATORS = [
    {
        "id": "ph_path_cancel",
        "type": "url_path",
        "pattern": "/cancel/",
        "severity": "medium",
        "description": "Suspicious /cancel/ path — common in PH banking phish URLs (e.g. BPI cancel-account flows)",
        "category": "ph_banking",
    },
    {
        "id": "ph_path_verify",
        "type": "url_path",
        "pattern": "/verify/",
        "severity": "medium",
        "description": "Suspicious /verify/ path — common in credential-harvesting flows targeting PH banks",
        "category": "ph_banking",
    },
    {
        "id": "ph_path_update",
        "type": "url_path",
        "pattern": "/update/",
        "severity": "low",
        "description": "Suspicious /update/ path — used in account-update phishing flows",
        "category": "ph_banking",
    },
    {
        "id": "ph_path_confirm",
        "type": "url_path",
        "pattern": "/confirm/",
        "severity": "low",
        "description": "Suspicious /confirm/ path — used in transaction-confirm phishing flows",
        "category": "ph_banking",
    },
    {
        "id": "ph_path_suspended",
        "type": "url_path",
        "pattern": "/suspended/",
        "severity": "high",
        "description": "Suspicious /suspended/ path — account-suspension lure, high phishing signal",
        "category": "ph_banking",
    },
    {
        "id": "ph_path_reactivate",
        "type": "url_path",
        "pattern": "/reactivate/",
        "severity": "high",
        "description": "Suspicious /reactivate/ path — account-reactivation lure, high phishing signal",
        "category": "ph_banking",
    },
    {
        "id": "ph_path_otp",
        "type": "url_path",
        "pattern": "/otp/",
        "severity": "high",
        "description": "OTP path in URL — direct OTP-capture flow indicator",
        "category": "ph_banking",
    },
]

# ---------------------------------------------------------------------------
# Domain impersonation patterns — typosquats and lookalikes
# ---------------------------------------------------------------------------
DOMAIN_INDICATORS = [
    # BPI impersonation
    {
        "id": "dom_gobpi",
        "type": "domain_pattern",
        "pattern": "gobpi",
        "severity": "high",
        "description": "gobpi* domain pattern — known BPI impersonation TLD family (gobpi.cc etc.)",
        "category": "ph_banking",
    },
    {
        "id": "dom_bpiverify",
        "type": "domain_pattern",
        "pattern": "bpiverify",
        "severity": "high",
        "description": "bpiverify* domain — BPI verification page impersonation",
        "category": "ph_banking",
    },
    {
        "id": "dom_bpi_hyphen",
        "type": "domain_pattern",
        "pattern": "bpi-online",
        "severity": "high",
        "description": "bpi-online* domain — BPI online banking impersonation with hyphen",
        "category": "ph_banking",
    },
    {
        "id": "dom_bpi_secure",
        "type": "domain_pattern",
        "pattern": "bpisecure",
        "severity": "high",
        "description": "bpisecure* domain — BPI secure login impersonation",
        "category": "ph_banking",
    },
    # BDO impersonation
    {
        "id": "dom_bdo_online",
        "type": "domain_pattern",
        "pattern": "bdo-online",
        "severity": "high",
        "description": "bdo-online* domain — BDO online banking impersonation with hyphen",
        "category": "ph_banking",
    },
    {
        "id": "dom_bdo_verify",
        "type": "domain_pattern",
        "pattern": "bdoverify",
        "severity": "high",
        "description": "bdoverify* domain — BDO verification page impersonation",
        "category": "ph_banking",
    },
    # GCash impersonation
    {
        "id": "dom_gcash_verify",
        "type": "domain_pattern",
        "pattern": "gcash-verify",
        "severity": "high",
        "description": "gcash-verify* domain — GCash verification impersonation",
        "category": "ph_banking",
    },
    {
        "id": "dom_gcash_update",
        "type": "domain_pattern",
        "pattern": "gcash-update",
        "severity": "high",
        "description": "gcash-update* domain — GCash update page impersonation",
        "category": "ph_banking",
    },
    # Maya / PayMaya impersonation
    {
        "id": "dom_maya_cancel",
        "type": "domain_pattern",
        "pattern": "maya-cancel",
        "severity": "high",
        "description": "maya-cancel* domain — Maya cancel-account lure impersonation",
        "category": "ph_banking",
    },
    {
        "id": "dom_maya_verify",
        "type": "domain_pattern",
        "pattern": "maya-verify",
        "severity": "high",
        "description": "maya-verify* domain — Maya verify page impersonation",
        "category": "ph_banking",
    },
    {
        "id": "dom_paymaya",
        "type": "domain_pattern",
        "pattern": "paymaya-",
        "severity": "high",
        "description": "paymaya-* domain — PayMaya impersonation with hyphen suffix",
        "category": "ph_banking",
    },
    # UnionBank / Metrobank / Landbank / DBP
    {
        "id": "dom_unionbank_verify",
        "type": "domain_pattern",
        "pattern": "unionbank-verify",
        "severity": "high",
        "description": "unionbank-verify* domain — UnionBank verification page impersonation",
        "category": "ph_banking",
    },
    {
        "id": "dom_metrobank_verify",
        "type": "domain_pattern",
        "pattern": "metrobank-verify",
        "severity": "high",
        "description": "metrobank-verify* domain — Metrobank verification page impersonation",
        "category": "ph_banking",
    },
    {
        "id": "dom_landbank_ph",
        "type": "domain_pattern",
        "pattern": "landbank-ph",
        "severity": "high",
        "description": "landbank-ph* domain — Landbank PH impersonation",
        "category": "ph_banking",
    },
    {
        "id": "dom_dbp_ph",
        "type": "domain_pattern",
        "pattern": "dbp-online",
        "severity": "high",
        "description": "dbp-online* domain — Development Bank of the Philippines impersonation",
        "category": "ph_banking",
    },
]

# ---------------------------------------------------------------------------
# HTML content indicators — brand references + credential capture signals
# ---------------------------------------------------------------------------
HTML_CONTENT_INDICATORS = [
    # Brand mention + OTP field combos
    {
        "id": "html_bpi_otp_field",
        "type": "html_content",
        "pattern": "one-time password",
        "severity": "high",
        "description": "OTP field label in HTML — credential-capture signal",
        "category": "ph_banking",
    },
    {
        "id": "html_otp_input_name",
        "type": "html_content",
        "pattern": 'name="otp"',
        "severity": "high",
        "description": 'OTP input field (name="otp") — credential-capture signal',
        "category": "ph_banking",
    },
    {
        "id": "html_otp_input_id",
        "type": "html_content",
        "pattern": 'id="otp"',
        "severity": "high",
        "description": 'OTP input field (id="otp") — credential-capture signal',
        "category": "ph_banking",
    },
    # TIN / government ID capture
    {
        "id": "html_tin_field",
        "type": "html_content",
        "pattern": "tin number",
        "severity": "high",
        "description": "TIN (Tax Identification Number) field — identity theft signal, PH-specific",
        "category": "ph_banking",
    },
    {
        "id": "html_tin_input",
        "type": "html_content",
        "pattern": 'name="tin"',
        "severity": "high",
        "description": 'TIN input field (name="tin") — identity theft signal',
        "category": "ph_banking",
    },
    # Brand references (page content, not URL)
    {
        "id": "html_bpi_brand",
        "type": "html_content",
        "pattern": "bank of the philippine islands",
        "severity": "medium",
        "description": "BPI full brand name in HTML — confirm with form action check",
        "category": "ph_banking",
    },
    {
        "id": "html_bdo_brand",
        "type": "html_content",
        "pattern": "banco de oro",
        "severity": "medium",
        "description": "BDO full brand name in HTML — confirm with form action check",
        "category": "ph_banking",
    },
    {
        "id": "html_gcash_brand",
        "type": "html_content",
        "pattern": "gcash account",
        "severity": "medium",
        "description": "GCash account reference in HTML body",
        "category": "ph_banking",
    },
    {
        "id": "html_maya_brand",
        "type": "html_content",
        "pattern": "maya account",
        "severity": "medium",
        "description": "Maya account reference in HTML body",
        "category": "ph_banking",
    },
    # Generic credential harvest helpers
    {
        "id": "html_account_number_field",
        "type": "html_content",
        "pattern": 'name="account_number"',
        "severity": "high",
        "description": 'Bare account_number input field (name="account_number")',
        "category": "ph_banking",
    },
    {
        "id": "html_card_number_field",
        "type": "html_content",
        "pattern": 'name="card_number"',
        "severity": "high",
        "description": 'Card number input field (name="card_number") — card data exfil signal',
        "category": "ph_banking",
    },
    {
        "id": "html_cvv_field",
        "type": "html_content",
        "pattern": 'name="cvv"',
        "severity": "high",
        "description": 'CVV input field (name="cvv") — card data exfil signal',
        "category": "ph_banking",
    },
    {
        "id": "html_pin_field",
        "type": "html_content",
        "pattern": 'name="pin"',
        "severity": "high",
        "description": 'PIN input field (name="pin") — credential-capture signal',
        "category": "ph_banking",
    },
    # PHP capture scripts seen in PH banking kit families
    {
        "id": "html_submit_php",
        "type": "html_content",
        "pattern": "submit.php",
        "severity": "high",
        "description": "submit.php action in HTML — PHP credential-capture endpoint",
        "category": "ph_banking",
    },
    {
        "id": "html_process_php",
        "type": "html_content",
        "pattern": "process.php",
        "severity": "high",
        "description": "process.php action — PHP credential processing endpoint",
        "category": "ph_banking",
    },
    {
        "id": "html_send_php",
        "type": "html_content",
        "pattern": "send.php",
        "severity": "medium",
        "description": "send.php action — PHP data-send endpoint seen in phishing kits",
        "category": "ph_banking",
    },
]

# ---------------------------------------------------------------------------
# HTML structure indicators — form action mismatch, hidden fields
# ---------------------------------------------------------------------------
HTML_STRUCTURE_INDICATORS = [
    {
        "id": "html_hidden_bank_name",
        "type": "html_structure",
        "pattern": 'name="bank_name"',
        "severity": "high",
        "description": 'Hidden bank_name field — multi-bank kit targeting signal',
        "category": "ph_banking",
    },
    {
        "id": "html_hidden_account_type",
        "type": "html_structure",
        "pattern": 'name="account_type"',
        "severity": "medium",
        "description": 'Hidden account_type field — kit infrastructure signal',
        "category": "ph_banking",
    },
    {
        "id": "html_hidden_target_bank",
        "type": "html_structure",
        "pattern": 'name="target_bank"',
        "severity": "high",
        "description": 'Hidden target_bank field — multi-bank kit routing field',
        "category": "ph_banking",
    },
]

# ---------------------------------------------------------------------------
# Certificate / infrastructure indicators (checked against URL / metadata)
# ---------------------------------------------------------------------------
CERT_INDICATORS = [
    {
        "id": "cert_we1_issuer",
        "type": "cert",
        "pattern": "WE1",
        "severity": "medium",
        "description": "WE1 Let's Encrypt issuer — free short-lived cert heavily used by phishing infra",
        "category": "ph_banking",
    },
    {
        "id": "cert_r3_issuer",
        "type": "cert",
        "pattern": "R3",
        "severity": "low",
        "description": "R3 Let's Encrypt issuer — common on phishing kits (also used by legitimate sites)",
        "category": "ph_banking",
    },
]

# ---------------------------------------------------------------------------
# Master list — combine all groups for simple iteration
# ---------------------------------------------------------------------------
PH_BANK_INDICATORS = (
    URL_PATH_INDICATORS
    + DOMAIN_INDICATORS
    + HTML_CONTENT_INDICATORS
    + HTML_STRUCTURE_INDICATORS
)


def match_ph_indicators(html: str, url: str) -> list[dict]:
    """
    Returns matched PH banking indicator dicts for the given html and url.
    URL-path and domain indicators are checked against the URL.
    HTML-content and HTML-structure indicators are checked against the HTML body.
    Matching is case-insensitive.
    """
    html_lower = html.lower()
    url_lower = url.lower()
    matched = []
    for ind in PH_BANK_INDICATORS:
        target = url_lower if ind["type"] in ("url_path", "domain_pattern") else html_lower
        if ind["pattern"].lower() in target:
            matched.append(ind)
    return matched


def match_age_indicators(age_result: dict) -> list[dict]:
    """
    Returns domain-age-based indicators given the result of check_domain_age().

    Fires nothing when age_result["found"] is False — no false positives
    from lookup failures.

    dom_age_recent  — HIGH  if age_days ≤ 7
                    — MEDIUM if 8 ≤ age_days ≤ 30
    dom_age_moderate — LOW  if 31 ≤ age_days ≤ 90
    """
    if not age_result.get("found"):
        return []

    age_days = age_result.get("age_days", -1)
    created_at = age_result.get("created_at", "")

    if age_days < 0:
        return []

    if age_days <= 7:
        return [
            {
                "id": "dom_age_recent",
                "type": "domain_age",
                "pattern": f"age_days={age_days}",
                "severity": "high",
                "description": (
                    f"Domain registered {age_days} day{'s' if age_days != 1 else ''} ago"
                    f" on {created_at[:10]}. Newly registered domains are the primary"
                    " infrastructure for banking phishing."
                ),
                "category": "ph_banking",
            }
        ]

    if age_days <= 30:
        return [
            {
                "id": "dom_age_recent",
                "type": "domain_age",
                "pattern": f"age_days={age_days}",
                "severity": "medium",
                "description": (
                    f"Domain registered {age_days} days ago on {created_at[:10]}."
                    " Newly registered domains are the primary infrastructure for banking phishing."
                ),
                "category": "ph_banking",
            }
        ]

    if age_days <= 90:
        return [
            {
                "id": "dom_age_moderate",
                "type": "domain_age",
                "pattern": f"age_days={age_days}",
                "severity": "low",
                "description": (
                    f"Domain registered {age_days} days ago on {created_at[:10]}."
                    " Recent registration is a mild phishing signal."
                ),
                "category": "ph_banking",
            }
        ]

    return []


# ---------------------------------------------------------------------------
# PH brand impersonation registry
#
# Banking indicators above answer "does this look like a PH bank phish". This
# registry answers a different and broader question: "whose brand is this page
# wearing, and is it being served from that brand's own domain".
#
# Brand-identical content on an unrelated registrable domain is impersonation by
# definition. Before this existed it scored exactly zero, because every content
# check in the scorer was looking for kit internals rather than for whose logo
# was on the page.
#
# Markers are content fingerprints, chosen to be distinctive rather than
# obvious. Several of these brands are ordinary English words (Shell, Globe,
# Smart, Grab, SM), so a bare brand token would fire on any page that happened
# to use the word. The markers for those are qualified: a domain reference, a
# full legal name, or a product name that is not a common noun.
# ---------------------------------------------------------------------------

PH_BRANDS = [
    # Fuel and energy
    {"name": "Petron", "domains": ["petron.com", "petron.com.ph"],
     "markers": ["petron corporation", "petron.com", "petron blaze", "petron gasul",
                 "petron value card", "- petron", "petron fuels"]},
    {"name": "Shell PH", "domains": ["shell.com.ph", "shell.com", "pilipinas.shell.com.ph"],
     "markers": ["shell.com.ph", "pilipinas shell", "shell v-power", "shell select",
                 "shell go+", "pilipinas shell petroleum"]},
    {"name": "Caltex", "domains": ["caltex.com", "caltex.com.ph"],
     "markers": ["caltex.com", "caltex philippines", "techron", "caltex starcard",
                 "chevron philippines"]},

    # Utilities and telco
    {"name": "Meralco", "domains": ["meralco.com.ph"],
     "markers": ["meralco.com.ph", "meralco", "manila electric company",
                 "meralco online", "kuryente load"]},
    {"name": "PLDT", "domains": ["pldt.com", "pldt.com.ph", "pldthome.com"],
     "markers": ["pldt.com", "pldt home", "pldt enterprise", "philippine long distance",
                 "myhome fibr", "pldt fibr"]},
    {"name": "Globe", "domains": ["globe.com.ph", "globe.com"],
     "markers": ["globe.com.ph", "globe telecom", "globe at home", "globeone",
                 "globe myaccount", "globe postpaid"]},
    {"name": "Smart", "domains": ["smart.com.ph"],
     "markers": ["smart.com.ph", "smart communications", "smart bro", "giga life",
                 "smart infinity", "smart prepaid"]},

    # Retail, food and malls
    {"name": "Jollibee", "domains": ["jollibee.com.ph", "jollibee.com"],
     "markers": ["jollibee.com", "jollibee foods", "chickenjoy", "jolly spaghetti",
                 "yumburger", "jollibee delivery"]},
    {"name": "SM", "domains": ["smsupermalls.com", "sm-investments.com", "smmarkets.ph"],
     "markers": ["sm supermalls", "smsupermalls.com", "sm investments", "sm prestige",
                 "sm advantage card", "sm store"]},
    {"name": "Robinsons", "domains": ["robinsonsmalls.com", "robinsonsretail.com.ph",
                                      "robinsonsbank.com.ph"],
     "markers": ["robinsons malls", "robinsonsmalls.com", "robinsons retail",
                 "robinsons supermarket", "go rewards"]},

    # Logistics
    {"name": "LBC", "domains": ["lbcexpress.com", "lbcexpress.ph"],
     "markers": ["lbcexpress.com", "lbc express", "lbc padala", "lbc tracking",
                 "lbc remittance"]},
    {"name": "J&T Express", "domains": ["jtexpress.ph", "jtexpress.com", "jtexpress.com.ph"],
     "markers": ["jtexpress.ph", "j&t express", "jt express", "j&amp;t express",
                 "jtexpress tracking"]},

    # Marketplaces and ride hailing
    {"name": "Lazada", "domains": ["lazada.com.ph", "lazada.com"],
     "markers": ["lazada.com", "lazada philippines", "lazmall", "lazada wallet",
                 "lazada seller"]},
    {"name": "Shopee", "domains": ["shopee.ph", "shopee.com"],
     "markers": ["shopee.ph", "shopee philippines", "shopeepay", "shopee mall",
                 "shopee guarantee"]},
    {"name": "Grab", "domains": ["grab.com", "grab.ph"],
     "markers": ["grab.com", "grabpay", "grabfood", "grabcar", "grabexpress",
                 "grab philippines"]},

    # Banks and e-wallets, mirroring the banking indicators above
    {"name": "BPI", "domains": ["bpi.com.ph", "bpiexpressonline.com"],
     "markers": ["bpi.com.ph", "bpiexpressonline", "bank of the philippine islands",
                 "bpi online", "bpi express"]},
    {"name": "BDO", "domains": ["bdo.com.ph"],
     "markers": ["bdo.com.ph", "banco de oro", "bdo unibank", "bdo online banking",
                 "bdo nomura"]},
    {"name": "GCash", "domains": ["gcash.com", "globe.com.ph"],
     "markers": ["gcash.com", "gcash", "gscore", "gsave", "ginvest", "gcredit"]},
    {"name": "Maya", "domains": ["maya.ph", "paymaya.com"],
     "markers": ["maya.ph", "paymaya", "maya bank", "maya wallet", "maya savings"]},
    {"name": "Landbank", "domains": ["landbank.com"],
     "markers": ["landbank.com", "land bank of the philippines", "landbank iaccess",
                 "landbank mobile banking"]},
    {"name": "UnionBank", "domains": ["unionbankph.com", "unionbank.com"],
     "markers": ["unionbankph.com", "union bank of the philippines", "unionbank online",
                 "ubp online"]},
    {"name": "RCBC", "domains": ["rcbc.com"],
     "markers": ["rcbc.com", "rizal commercial banking", "rcbc pulz", "rcbc diskartech"]},
    {"name": "Metrobank", "domains": ["metrobank.com.ph"],
     "markers": ["metrobank.com.ph", "metropolitan bank and trust", "metrobank online",
                 "metrobank direct"]},
    {"name": "Security Bank", "domains": ["securitybank.com"],
     "markers": ["securitybank.com", "security bank corporation", "securitybank online"]},
    {"name": "PNB", "domains": ["pnb.com.ph"],
     "markers": ["pnb.com.ph", "philippine national bank", "pnb digital banking"]},
]

# Where a brand name shows up in page furniture rather than in body copy. A hit
# here is worth more than a loose substring match anywhere in the document.
_STRONG_MARKER_CONTEXTS = (
    'og:site_name" content="{b}',
    "og:site_name' content='{b}",
    "<title>{b}",
    "{b}</title>",
    "copyright &copy; {b}",
    "copyright © {b}",
    "&copy; {b}",
    "© {b}",
)


def detect_brand(html: str) -> dict:
    """Identify whose brand a page is wearing.

    Returns {brand, confidence, matched_markers, domains}. `brand` is None when
    nothing matched, so a caller can tell "no brand detected" apart from
    "detected and it is fine".

    Confidence is high when the brand name appears in page furniture (title,
    og:site_name, a copyright line) or when three or more markers hit, medium at
    two markers, low at one. The furniture rule matters because a phishing clone
    copies the whole page head verbatim, which is exactly where it is most
    expensive for the operator to strip the brand out.
    """
    empty = {"brand": None, "confidence": None, "matched_markers": [], "domains": []}
    if not html:
        return empty

    lowered = html.lower()
    best = None

    for entry in PH_BRANDS:
        matched = [m for m in entry["markers"] if m in lowered]
        if not matched:
            continue

        name = entry["name"].lower()
        strong = any(ctx.format(b=name) in lowered for ctx in _STRONG_MARKER_CONTEXTS)

        if strong or len(matched) >= 3:
            confidence = "high"
        elif len(matched) == 2:
            confidence = "medium"
        else:
            confidence = "low"

        rank = ({"high": 3, "medium": 2, "low": 1}[confidence], len(matched))
        if best is None or rank > best[0]:
            best = (rank, {
                "brand": entry["name"],
                "confidence": confidence,
                "matched_markers": matched[:8],
                "domains": list(entry["domains"]),
                "strong_context": strong,
            })

    return best[1] if best else empty


def brand_domains(brand_name: str) -> list:
    """Registered domains for a brand name, empty when it is not in the registry."""
    for entry in PH_BRANDS:
        if entry["name"] == brand_name:
            return list(entry["domains"])
    return []


def brand_for_domain(host: str) -> Optional[dict]:
    """The registry entry that owns *host*, or None.

    Matched at the registrable level, so www.petron.com and petron.com both
    resolve to Petron. Used to answer "did this redirect land on a brand we
    know" without depending on content detection, which a redirect response
    body is usually too small to support.
    """
    if not host:
        return None
    # Imported here rather than at module top: scope imports nothing from this
    # module, but keeping the dependency lazy makes the direction obvious.
    from app.scanner.scope import registrable

    target = registrable(host)
    if not target:
        return None
    for entry in PH_BRANDS:
        if any(registrable(d) == target for d in entry["domains"]):
            return entry
    return None
