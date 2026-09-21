from app.utils.env import getenv_clean

DB_PATH = getenv_clean("FALCONEYE_DB", "/opt/falconeye/data/falconeye.db")
HTTPX_TIMEOUT = 10.0
NEWS_CACHE_TTL_MINUTES = 30

# Per source IP per rolling 24-hour window, for the URL Expander and QR Analyzer tabs.
URL_EXPAND_RATE_LIMIT_PER_DAY = 10
QR_DECODE_RATE_LIMIT_PER_DAY = 10

# Secrets, loaded from /opt/falconeye/.env via systemd EnvironmentFile.
# DO NOT log, print, or expose these values anywhere in application code.
GREYNOISE_API_KEY = getenv_clean("GREYNOISE_API_KEY")
ABUSECH_AUTH_KEY = getenv_clean("ABUSECH_AUTH_KEY")

# LLM body scam analysis - flags and limits ONLY.
# The model name is intentionally NOT in config to prevent accidental swaps to a more expensive model.
# See _llm_analyze_body() in routers/email_header.py where the model is hardcoded.
LLM_ANALYSIS_ENABLED = getenv_clean("LLM_ANALYSIS_ENABLED", "true").lower() == "true"
LLM_MAX_BODY_TOKENS = 8000          # roughly 32KB of body text, skip LLM if larger
LLM_RATE_LIMIT_PER_DAY = 10         # per source IP per rolling 24-hour window
LLM_TIMEOUT_SECONDS = 15
LLM_MIN_BODY_CHARS = 50             # below this, skip LLM (too short to analyze meaningfully)
REGEX_MAX_BODY_BYTES = 100_000      # regex pass only; 100KB cap prevents compute amplification on adversarial input

# Deep kit report (Phishing Kit Scanner tab). The bundle caps are the
# kit-analysis analogue of REGEX_MAX_BODY_BYTES above. That 100KB cap is NOT
# reused here: real entry bundles run 85KB to 2MB, so truncating at 100KB would
# produce wrong analysis rather than slower analysis. Compute stays bounded by
# these caps plus the bounded-quantifier patterns in kit_analyzer.
KIT_MAX_BUNDLE_BYTES = 8_000_000     # reject a single bundle larger than this
KIT_MAX_RESOLVE_BYTES = 4_000_000    # above this, skip decoder call-site resolution
KIT_MAX_ASSETS = 12                  # most assets fetched per target
KIT_REPORT_RATE_LIMIT_PER_DAY = 10   # per source IP per rolling 24-hour window

ANTHROPIC_API_KEY = getenv_clean("ANTHROPIC_API_KEY")
URLSCAN_API_KEY = getenv_clean("URLSCAN_API_KEY")

# Telegram Intelligence tab, tier 2 (Bot API) and tier 3 (MTProto/Telethon).
# Any of these being empty is a normal, expected configuration (graceful
# per-tier degradation), not an error.
TELEGRAM_API_ID = getenv_clean("TELEGRAM_API_ID")
TELEGRAM_API_HASH = getenv_clean("TELEGRAM_API_HASH")
TELEGRAM_BOT_TOKEN = getenv_clean("TELEGRAM_BOT_TOKEN")
TELEGRAM_SESSION_PATH = getenv_clean("TELEGRAM_SESSION_PATH")

# Hudson Rock infostealer intelligence (v3.33.0, GitHub issue #1).
# Default OFF. The free "osint-tools" endpoints need no API key, but they carry
# no published rate limit and no published terms of use, so this is a
# best-effort source an operator opts into rather than one that is on by
# default. See "Hudson Rock" in docs/deploy-runbook.md.
HUDSONROCK_ENABLED = getenv_clean("HUDSONROCK_ENABLED", "false").lower() == "true"
# Upstream answers with Cache-Control: max-age=14400, so 4 hours matches what
# the vendor itself considers fresh. Do not raise it above that without reason.
HUDSONROCK_CACHE_TTL_HOURS = 4
# Per-IP daily cap. The upstream quota is not ours to spend, so this is capped
# the same way the paid LLM endpoints are.
HUDSONROCK_PER_DAY = max(1, int(getenv_clean("HUDSONROCK_PER_DAY", "25")))

# Breach Check tab (Have I Been Pwned, Core 1 subscription).
HIBP_API_KEY = getenv_clean("HIBP_API_KEY")

# Ransomware Watch tab. The collector (app/collectors/ransomware_collect.py,
# run by an out-of-repo systemd timer) is the only thing that ever calls
# ransomware.live / RansomLook; the tab itself reads RANSOMWARE_DB only.
RANSOMWARE_LIVE_API_KEY = getenv_clean("RANSOMWARE_LIVE_API_KEY")
RANSOMWARE_DB = getenv_clean("RANSOMWARE_DB", "/opt/falconeye/data/ransomware.db")
# PH-relevant search terms, one per line, '#' comments allowed. Kept outside
# the git tree deliberately (see docs/ransomware-watch-runbook.md) since it's
# operational config, not application code.
RANSOMWARE_WATCHLIST_PATH = getenv_clean("RANSOMWARE_WATCHLIST_PATH", "/opt/falconeye/private/ransomware_watchlist.txt")


# ----- Operator identity (v3.33.0) -----
# Who runs THIS instance. Every default reproduces the public instance exactly,
# so an existing deployment that sets none of these is unchanged.
#
# A self-hoster sets these so the site does not present someone else's name,
# inbox and privacy policy as its own. The AGPL attribution and the link to the
# upstream repository are NOT covered by these settings and always render: that
# is the licence, not branding.
OPERATOR_NAME = getenv_clean("OPERATOR_NAME", "OSINT-PH")
OPERATOR_URL = getenv_clean("OPERATOR_URL", "https://blog.osintph.info")
OPERATOR_CONTACT_EMAIL = getenv_clean("OPERATOR_CONTACT_EMAIL", "security@osintph.info")
# One clause describing the operator, rendered after the name in the About box.
# Operator-specific prose, so it has to be settable; the default is what the
# public instance says. Set it empty to render just the name.
OPERATOR_TAGLINE = getenv_clean(
    "OPERATOR_TAGLINE", "a Philippine-based OSINT and incident response practice")
# A second profile URL for the JSON-LD sameAs array (the public instance lists
# its GitHub org alongside the blog). Set empty to publish only OPERATOR_URL.
OPERATOR_PROFILE_URL = getenv_clean("OPERATOR_PROFILE_URL", "https://github.com/osintph")
OPERATOR_PRIVACY_EMAIL = getenv_clean("OPERATOR_PRIVACY_EMAIL", "privacy@osintph.info")
# Public origin of this instance, used in canonical/OG tags and the privacy policy.
OPERATOR_SITE_ORIGIN = getenv_clean("SITE_ORIGIN", "https://falconeye.osintph.info")

# The Contact tab. "true" (the default) keeps it exactly as the public instance
# has it. A self-hoster who does not want to field mail sets this to "false":
# the nav entry disappears, the panel is not rendered, and GET /contact returns
# 404 rather than an empty page.
CONTACT_ENABLED = getenv_clean("CONTACT_ENABLED", "true").lower() != "false"
# Where the contact form posts. Hardcoded to the upstream operator's Formspree
# form until v3.33.0, which meant a self-hoster's visitors mailed someone else.
# Empty disables the form while leaving the rest of the tab intact.
CONTACT_FORM_ACTION = getenv_clean("CONTACT_FORM_ACTION", "https://formspree.io/f/mojoezkp")
