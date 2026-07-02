import os

# Set required env vars before any app module is imported.
# SEARCHAPI_KEY must be present or SearchAPIClient.__init__ raises KeyError.
os.environ.setdefault("SEARCHAPI_KEY", "test-key-do-not-use")
os.environ.setdefault("PROSPECT_ENABLED", "true")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")
os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")
