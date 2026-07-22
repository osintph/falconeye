from app.utils.env import getenv_clean

DB_PATH = getenv_clean("FALCONEYE_DB", "/opt/falconeye/data/falconeye.db")
HTTPX_TIMEOUT = 10.0
NEWS_CACHE_TTL_MINUTES = 30

# Per source IP per rolling 24-hour window, for the URL Expander and QR Analyzer tabs.
URL_EXPAND_RATE_LIMIT_PER_DAY = 10
QR_DECODE_RATE_LIMIT_PER_DAY = 10

# Secrets — loaded from /opt/falconeye/.env via systemd EnvironmentFile.
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

ANTHROPIC_API_KEY = getenv_clean("ANTHROPIC_API_KEY")
URLSCAN_API_KEY = getenv_clean("URLSCAN_API_KEY")

# Telegram Intelligence tab — tier 2 (Bot API) and tier 3 (MTProto/Telethon).
# Any of these being empty is a normal, expected configuration (graceful
# per-tier degradation), not an error.
TELEGRAM_API_ID = getenv_clean("TELEGRAM_API_ID")
TELEGRAM_API_HASH = getenv_clean("TELEGRAM_API_HASH")
TELEGRAM_BOT_TOKEN = getenv_clean("TELEGRAM_BOT_TOKEN")
TELEGRAM_SESSION_PATH = getenv_clean("TELEGRAM_SESSION_PATH")

# Breach Check tab (Have I Been Pwned, Core 1 subscription).
HIBP_API_KEY = getenv_clean("HIBP_API_KEY")
