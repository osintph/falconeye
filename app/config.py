import os

DB_PATH = os.getenv("FALCONEYE_DB", "/opt/falconeye/data/falconeye.db")
HTTPX_TIMEOUT = 3.0  # seconds — do not increase
MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2MB hard cap
