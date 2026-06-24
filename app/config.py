import os

DB_PATH = os.getenv("FALCONEYE_DB", "/opt/falconeye/data/falconeye.db")
HTTPX_TIMEOUT = 10.0
NEWS_CACHE_TTL_MINUTES = 30
