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

# Censys Platform host lookup (v3.34.0). Enrichment only: ports and services,
# never a reputation vote.
#
# Default OFF because the call is metered. Verified 2026-09-27 against
# https://docs.censys.com/docs/platform-credits-free-starter: an entity lookup
# costs 1 Censys credit, Censys Free gets 100 credits a month and they expire at
# the end of the month, so an instance with the free allowance can serve about
# three lookups a day before the balance is gone. When it is gone the API
# answers HTTP 422 and the card says so, quietly.
CENSYS_ENABLED = getenv_clean("CENSYS_ENABLED", "false").lower() == "true"

# Registered-service enumeration on the Email Header tab (v3.34.0), via the
# holehe library. DEFAULT OFF, and it should stay off unless the operator has
# read "holehe" in docs/deploy-runbook.md.
#
# This one is not a vendor lookup: it makes THIS server start a signup or login
# flow at each allowlisted third-party service to see which ones say the address
# is taken. Enabling it means our IP makes twenty outbound probes per lookup, to
# sites that may rate limit or flag us for it. The library is not in
# requirements.txt; if it is not installed the source behaves as disabled.
HOLEHE_ENABLED = getenv_clean("HOLEHE_ENABLED", "false").lower() == "true"
# Per-IP daily cap. An order of magnitude below every other source, because one
# lookup is twenty outbound requests rather than one.
HOLEHE_PER_DAY = max(1, int(getenv_clean("HOLEHE_PER_DAY", "5")))
# Wall clock for the whole enumeration. Deliberately shorter than the sum of the
# per-request timeouts: services that do not answer in time are dropped, not
# waited for, and the card reports how many answered.
HOLEHE_TIMEOUT_SECONDS = float(getenv_clean("HOLEHE_TIMEOUT_SECONDS", "20"))
# How many services may be probed at once. Hard-capped at 8 whatever the
# environment says: this is a property of being a good neighbour on someone
# else's infrastructure, not a tuning knob.
HOLEHE_CONCURRENCY = max(1, min(8, int(getenv_clean("HOLEHE_CONCURRENCY", "4"))))
# Cached longer than the reputation sources: the answer changes when someone signs
# up somewhere, which is rare, and every cache hit is twenty probes not made.
HOLEHE_CACHE_TTL_HOURS = 12

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

# The contact token every outbound User-Agent carries, so an upstream API that
# wants to complain about our traffic knows who to complain to. Until v3.33.1
# this was hardcoded to the upstream operator's domain, which meant every API a
# self-hoster queried saw osintph.info as the responsible party for traffic it
# had nothing to do with. Some upstreams (ransomware.live) require attribution,
# so this is a value to set rather than remove.
OPERATOR_CONTACT_UA = getenv_clean("OPERATOR_CONTACT_UA", "osintph.info")

# The Contact tab. "true" (the default) keeps it exactly as the public instance
# has it. A self-hoster who does not want to field mail sets this to "false":
# the nav entry disappears, the panel is not rendered, and GET /contact returns
# 404 rather than an empty page.
CONTACT_ENABLED = getenv_clean("CONTACT_ENABLED", "true").lower() != "false"
# Where the contact form posts. Hardcoded to the upstream operator's Formspree
# form until v3.33.0, which meant a self-hoster's visitors mailed someone else.
# Empty disables the form while leaving the rest of the tab intact.
CONTACT_FORM_ACTION = getenv_clean("CONTACT_FORM_ACTION", "https://formspree.io/f/mojoezkp")


# ----- Route Map tab (v3.35.0) -----
# Hostname-first traceroute geolocation. The trace always comes from the user's
# own machine, either pasted or uploaded by the one-line command the tab shows.
# This server never runs a traceroute and is never the origin of the path.

# CAIDA Hoiho, the router-hostname geolocation source. Default ON: it is free,
# keyless, published research infrastructure, and the data sent to it is router
# hostnames from a pasted trace, never anything about the visitor. The gate on
# what may leave is is_routable_hostname() in app/routemap/parse.py, so a
# private hop or a LAN label is never sent. Set to "false" and the tab falls
# back to IP geolocation alone, which is exactly the inaccuracy the tab exists
# to correct, so turn it off only deliberately.
HOIHO_ENABLED = getenv_clean("HOIHO_ENABLED", "true").lower() != "false"
HOIHO_BASE_URL = getenv_clean("HOIHO_BASE_URL", "https://api.hoiho.caida.org")
# 30 days. A hostname's embedded location changes when a carrier renames a
# router, which is a thing that happens on the scale of years, and the ruleset
# itself is regenerated a few times a year (ruleset_date was 2024-08 when this
# was written). Every cache hit is a request CAIDA does not have to serve.
HOIHO_CACHE_TTL_HOURS = 24 * 30
HOIHO_TIMEOUT_SECONDS = float(getenv_clean("HOIHO_TIMEOUT_SECONDS", "12"))

# Run-locally upload (Mode B). FalconEye never runs a traceroute itself: the
# user runs it on their own machine and the one-line command we show pipes the
# output to the ingest endpoint. So there is no probe traffic from this server,
# no raw-socket capability, no new system package, and the path drawn is the
# path from where the user actually is.
#
# The handoff between the shell that uploads and the browser that renders is
# short-lived state keyed by a single-use token. See app/routemap/tokens.py.
#
# Ten minutes: long enough to copy a command into a terminal and watch a
# 30-hop trace finish, short enough that a token left on screen is not a
# standing invitation.
ROUTEMAP_TOKEN_TTL_SECONDS = max(60, int(getenv_clean("ROUTEMAP_TOKEN_TTL_SECONDS", "600")))
# Ceiling on an uploaded trace. The parser's own cap is 256 KB; this is the
# transport cap, applied before the body is read into memory, because the
# endpoint is unauthenticated by construction (the token is the only credential
# and it arrives in the URL).
ROUTEMAP_MAX_UPLOAD_BYTES = 256_000
# Per-IP daily caps through the shared SQLite rate limiter. Issuing a token is
# cheap; uploading means we parse and then geolocate, which costs CAIDA and
# RIPEstat requests, so the two are capped separately.
ROUTEMAP_TOKENS_PER_DAY = max(1, int(getenv_clean("ROUTEMAP_TOKENS_PER_DAY", "30")))
ROUTEMAP_ANALYSES_PER_DAY = max(1, int(getenv_clean("ROUTEMAP_ANALYSES_PER_DAY", "60")))


# ----- RIPE Atlas (Route Map tab, v3.35.0) -----
# The primary way the tab gets a trace: ask an Atlas probe on the user's own
# network to run it. FalconEye still never runs a traceroute itself.
#
# DEFAULT OFF, and it needs a key. Enabling it has three consequences an
# operator must agree to deliberately:
#
#   1. Measurements created here are PUBLIC. RIPE Atlas publishes one-off
#      measurements, including the target, in its measurement database. The tab
#      says so next to the button and the privacy policy says so.
#   2. They cost credits. A traceroute is 30 credits per result. An account
#      earns about 21,600 credits a day per probe it hosts, and a new account
#      can claim a one-time 50,000.
#   3. The target a visitor types is sent to RIPE. The visitor's coordinates
#      are NOT: probe selection goes by ASN and country only. See the module
#      docstring in app/routemap/atlas.py.
ATLAS_ENABLED = getenv_clean("ATLAS_ENABLED", "false").lower() == "true"
ATLAS_API_KEY = getenv_clean("ATLAS_API_KEY")
ATLAS_BASE_URL = getenv_clean("ATLAS_BASE_URL", "https://atlas.ripe.net/api/v2")
# This instance's own daily ceiling, enforced here and not only by RIPE. At 30
# credits a traceroute, the default is about 166 traces a day, which a single
# hosted probe (about 21,600 credits a day) more than covers.
ATLAS_DAILY_CREDIT_CAP = max(0, int(getenv_clean("ATLAS_DAILY_CREDIT_CAP", "5000")))
# Wall clock for one measurement, after which the tab offers the Advanced
# fallback. One-off Atlas traceroutes usually return well inside this.
ATLAS_MEASUREMENT_TIMEOUT_SECONDS = float(
    getenv_clean("ATLAS_MEASUREMENT_TIMEOUT_SECONDS", "120"))
# Per-IP daily cap on measurements, through the shared SQLite rate limiter.
ATLAS_PER_DAY = max(1, int(getenv_clean("ATLAS_PER_DAY", "10")))
# Probe lists per ASN or country move slowly and are not the interesting part
# of the budget.
ATLAS_PROBE_CACHE_TTL_HOURS = 6


# ----- Attack Surface Management (v3.37.0) -----
# ASM maps the internet-facing surface of a domain the requester has PROVEN they
# control (DNS TXT or a role-address email), or any domain in operator mode for an
# authorized engagement. No ASM output of any kind is returned for an unverified
# or blocked domain outside operator mode. Discovery is passive (CT logs, passive
# DNS, Wayback, RIPEstat); active checks stay inside the target apex. Every
# outbound HTTP to a target goes through app.utils.safe_fetch; the port scan is a
# pure-Python TCP connect scan that still resolves through resolve_and_check so a
# private or reserved address is never connected to. No em dashes in any ASM copy
# (a test enforces it); keep this section ASCII.

# Signing key for grants, management links, email-confirm tokens and the operator
# session cookie (itsdangerous). The setup script writes a high-entropy value here
# so grants survive a restart. Left unset, app/asm/signing.py falls back to a
# per-process random key: everything still works, but every restart invalidates
# outstanding grants and links. Never log this value.
ASM_SIGNING_KEY = getenv_clean("ASM_SIGNING_KEY")

# A successful verification issues a grant bound to the requester's browser
# session. 30 days by default.
ASM_GRANT_DAYS = max(1, int(getenv_clean("ASM_GRANT_DAYS", "30")))
# Verification tokens (DNS token, email link) are single use and expire this fast.
ASM_VERIFY_TOKEN_TTL_HOURS = max(1, int(getenv_clean("ASM_VERIFY_TOKEN_TTL_HOURS", "24")))

# Verification attempt caps, so the email method cannot be used to mail-bomb a
# target's postmaster and the DNS method cannot be used as an unmetered probe.
ASM_VERIFY_START_PER_HOUR = max(1, int(getenv_clean("ASM_VERIFY_START_PER_HOUR", "5")))
ASM_VERIFY_START_PER_DOMAIN_PER_DAY = max(1, int(getenv_clean("ASM_VERIFY_START_PER_DOMAIN_PER_DAY", "3")))
ASM_VERIFY_EMAIL_PER_DOMAIN_PER_DAY = max(1, int(getenv_clean("ASM_VERIFY_EMAIL_PER_DOMAIN_PER_DAY", "2")))

# Scan hard caps. Per run: at most this many discovered hosts are actively probed
# and port scanned; a per-host timeout, a whole-run timeout, and two concurrency
# ceilings. These bound a run whatever a target's zone looks like.
ASM_MAX_HOSTS_PER_RUN = max(1, int(getenv_clean("ASM_MAX_HOSTS_PER_RUN", "50")))
ASM_HOST_TIMEOUT_SECONDS = float(getenv_clean("ASM_HOST_TIMEOUT_SECONDS", "20"))
ASM_RUN_TIMEOUT_SECONDS = float(getenv_clean("ASM_RUN_TIMEOUT_SECONDS", "240"))
ASM_PORT_TIMEOUT_SECONDS = float(getenv_clean("ASM_PORT_TIMEOUT_SECONDS", "2.5"))
# Hard-capped like holehe's concurrency: being a good neighbour is not a tuning knob.
ASM_PORT_CONCURRENCY = max(1, min(100, int(getenv_clean("ASM_PORT_CONCURRENCY", "50"))))
ASM_HOST_CONCURRENCY = max(1, min(20, int(getenv_clean("ASM_HOST_CONCURRENCY", "10"))))

# Scans run as background jobs, not in the request worker. At most this many run
# at once; further requests queue up to the queue cap, then are refused.
ASM_MAX_CONCURRENT_SCANS = max(1, min(8, int(getenv_clean("ASM_MAX_CONCURRENT_SCANS", "2"))))
ASM_SCAN_QUEUE_MAX = max(1, int(getenv_clean("ASM_SCAN_QUEUE_MAX", "20")))

# Per source IP daily cap on on-demand scans (burst is a separate slowapi limit).
ASM_SCAN_PER_DAY = max(1, int(getenv_clean("ASM_SCAN_PER_DAY", "10")))

# Monitoring. Opt-in per verified (or operator-added) domain, run by a systemd
# timer. Default OFF so a self-hoster turns it on deliberately.
ASM_MONITORING_ENABLED = getenv_clean("ASM_MONITORING_ENABLED", "false").lower() == "true"
ASM_MAX_MONITORED = max(1, int(getenv_clean("ASM_MAX_MONITORED", "50")))
ASM_MAX_PER_NOTIFY = max(1, int(getenv_clean("ASM_MAX_PER_NOTIFY", "10")))
# Snapshots older than this are pruned. Deleting a domain removes everything now.
ASM_SNAPSHOT_RETENTION_DAYS = max(1, int(getenv_clean("ASM_SNAPSHOT_RETENTION_DAYS", "180")))

# Free-mail blocklist: a local override file merged on top of the vendored
# willwhite/freemail list (app/asm/data/free_email_domains.txt). One domain per
# line, '#' comments allowed. Kept outside the tree like the ransomware watchlist.
ASM_FREEMAIL_OVERRIDE_PATH = getenv_clean("ASM_FREEMAIL_OVERRIDE_PATH", "/opt/falconeye/private/asm_freemail_override.txt")
# Extra operator-defined blocked domains, comma separated, merged into the
# free-mail block layer. Same "this domain cannot be assessed here" response.
ASM_BLOCKED_DOMAINS = getenv_clean("ASM_BLOCKED_DOMAINS")

# CertSpotter free key lifts the unauthenticated full-domain quota (10/hr). The
# discovery CT fetchers fall back to unauthenticated use when it is empty.
CERTSPOTTER_API_KEY = getenv_clean("CERTSPOTTER_API_KEY")

# Shodan enrichment (host ports/services and CVEs). DEFAULT OFF, enrichment only,
# never changes the host list or a finding on its own. The keyless InternetDB
# endpoint and the keyed host API both sit behind this one flag. Verified
# 2026-10-11: shodan/host/{ip} spends no query credits, internetdb.shodan.io is
# keyless and free for non-commercial use, rate limit 1 req/s.
SHODAN_ENABLED = getenv_clean("SHODAN_ENABLED", "false").lower() == "true"
SHODAN_API_KEY = getenv_clean("SHODAN_API_KEY")

# Bright Data Web Unlocker. DEFAULT OFF and OPERATOR ONLY: its acceptable-use
# policy forbids reselling proxy access, so anonymous users' fetches are never
# routed through it. Used only to fetch a page the direct safe_fetch probe could
# not complete, never to scan or port scan. Verified 2026-10-11 against
# https://brightdata.com/acceptable-use-policy.
BRIGHTDATA_ENABLED = getenv_clean("BRIGHTDATA_ENABLED", "false").lower() == "true"
BRIGHTDATA_API_KEY = getenv_clean("BRIGHTDATA_API_KEY")
BRIGHTDATA_ZONE = getenv_clean("BRIGHTDATA_ZONE")

# Operator mode (master key). Disabled unless BOTH are set. Self-hosters get no
# operator mode by default and the feature leaves no visible trace in the UI when
# off. The setup script (scripts/asm_operator_setup.py) generates the key and the
# TOTP secret, prints both once, and stores only the bcrypt hash and the TOTP
# secret here. Never configure these on the public instance from an automated run.
ASM_OPERATOR_KEY_HASH = getenv_clean("ASM_OPERATOR_KEY_HASH")
ASM_OPERATOR_TOTP_SECRET = getenv_clean("ASM_OPERATOR_TOTP_SECRET")
# Optional source restriction for the unlock route (e.g. a tailnet range). Comma
# separated CIDRs; empty means any source may attempt an unlock.
ASM_OPERATOR_ALLOWED_CIDRS = getenv_clean("ASM_OPERATOR_ALLOWED_CIDRS")
# Operator session lifetime once unlocked.
ASM_OPERATOR_SESSION_HOURS = max(1, int(getenv_clean("ASM_OPERATOR_SESSION_HOURS", "8")))
# The operator's own daily scan cap, which may be higher than a normal user's.
ASM_OPERATOR_SCAN_PER_DAY = max(1, int(getenv_clean("ASM_OPERATOR_SCAN_PER_DAY", "200")))

# The local stdio MCP server counts as operator context ONLY when this is set in
# ITS OWN environment. It must NEVER be set in the gunicorn/systemd environment of
# the public web app: the web process never has it, so a browser cannot reach the
# operator path even by forging the in-process marker header. See app/mcp_server.py.
ASM_MCP_OPERATOR = getenv_clean("ASM_MCP_OPERATOR", "false").lower() == "true"


def asm_operator_configured() -> bool:
    """True when operator mode is set up on this instance.

    Read live (not frozen at import) so a test can set the two env vars and the
    unlock route stops being 404-shaped. When this is False the UI shows no trace
    of operator mode and the unlock routes answer 404.
    """
    return bool(
        getenv_clean("ASM_OPERATOR_KEY_HASH") and getenv_clean("ASM_OPERATOR_TOTP_SECRET")
    )


# ----- v3.38.0: one-time results + Phishing Hunt -----
import os as _os  # noqa: E402  (only needed for the PDF directory path)

# Where server-side report PDFs are written before download. One per finished
# run, deleted after the download completes or by the TTL sweep.
ASM_PDF_DIR = getenv_clean("ASM_PDF_DIR") or _os.path.join(_os.path.dirname(DB_PATH), "asm_pdfs")
# How long an undownloaded result (on-screen payload plus PDF) is kept before the
# lazy sweep purges it. ASM scans and Hunt queries are one-time; nothing is kept
# beyond this.
ASM_RESULT_TTL_SECONDS = max(60, int(getenv_clean("ASM_RESULT_TTL_SECONDS", "3600")))

# Phishing Domain Hunt (public, ungated). Finds brand-impersonation domains. It
# hunts attacker infrastructure, so it is NOT behind the ASM ownership gate.
HUNT_ENABLED = getenv_clean("HUNT_ENABLED", "true").lower() != "false"
HUNT_MAX_CANDIDATES = max(10, int(getenv_clean("HUNT_MAX_CANDIDATES", "120")))
HUNT_MAX_FETCHES = max(5, int(getenv_clean("HUNT_MAX_FETCHES", "40")))
HUNT_PER_DAY = max(1, int(getenv_clean("HUNT_PER_DAY", "20")))
HUNT_CANDIDATE_TIMEOUT = float(getenv_clean("HUNT_CANDIDATE_TIMEOUT", "8"))
# Newly registered domain feed (WHOISDS). DEFAULT OFF: set this to a URL that
# returns a daily list of newly registered domains (plain text or a zipped text
# list), which WHOISDS provides to an account. Until set, new-registration
# coverage is off and the report says so. Verified 2026-10-11: WHOISDS lists are
# free and permissively reusable but automated download needs an account.
HUNT_NRD_URL = getenv_clean("HUNT_NRD_URL")
