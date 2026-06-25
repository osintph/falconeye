import os

DB_PATH = os.getenv("FALCONEYE_DB", "/opt/falconeye/data/falconeye.db")
HTTPX_TIMEOUT = 10.0
NEWS_CACHE_TTL_MINUTES = 30

# Secrets — loaded from /opt/falconeye/.env via systemd EnvironmentFile.
# DO NOT log, print, or expose these values anywhere in application code.
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY", "")
