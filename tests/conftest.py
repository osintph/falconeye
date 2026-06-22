import os

# Provide required env vars so the test suite runs without a secrets.env in scope.
# Tests that need to verify the ConfigError path use monkeypatch.delenv to clear these.
os.environ.setdefault("FALCONEYE_DB_PATH", "db/falconeye.db")
os.environ.setdefault("FALCONEYE_OUTPUT_DIR", "public")
