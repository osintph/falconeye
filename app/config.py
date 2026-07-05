import os

DB_PATH = os.getenv("FALCONEYE_DB", "/opt/falconeye/data/falconeye.db")
HTTPX_TIMEOUT = 10.0
NEWS_CACHE_TTL_MINUTES = 30

# Secrets — loaded from /opt/falconeye/.env via systemd EnvironmentFile.
# DO NOT log, print, or expose these values anywhere in application code.
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")

# LLM body scam analysis - flags and limits ONLY.
# The model name is intentionally NOT in config to prevent accidental swaps to a more expensive model.
# See _llm_analyze_body() in routers/email_header.py where the model is hardcoded.
LLM_ANALYSIS_ENABLED = os.getenv("LLM_ANALYSIS_ENABLED", "true").lower() == "true"
LLM_MAX_BODY_TOKENS = 8000          # roughly 32KB of body text, skip LLM if larger
LLM_RATE_LIMIT_PER_DAY = 10         # per source IP per rolling 24-hour window
LLM_TIMEOUT_SECONDS = 15
LLM_MIN_BODY_CHARS = 50             # below this, skip LLM (too short to analyze meaningfully)
REGEX_MAX_BODY_BYTES = 100_000      # regex pass only; 100KB cap prevents compute amplification on adversarial input

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
