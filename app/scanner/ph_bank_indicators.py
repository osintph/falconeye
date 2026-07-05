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
