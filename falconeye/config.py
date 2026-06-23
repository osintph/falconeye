from __future__ import annotations

import os


class ConfigError(RuntimeError):
    pass


def get_db_path() -> str:
    val = os.environ.get("FALCONEYE_DB_PATH")
    if not val:
        raise ConfigError(
            "FALCONEYE_DB_PATH is not set. "
            "Set it in your environment or source /opt/falconeye/config/secrets.env before running."
        )
    return val


def get_output_dir() -> str:
    val = os.environ.get("FALCONEYE_OUTPUT_DIR")
    if not val:
        raise ConfigError(
            "FALCONEYE_OUTPUT_DIR is not set. "
            "Set it in your environment or source /opt/falconeye/config/secrets.env before running."
        )
    return val


def get_ghost_api_url() -> str:
    val = os.environ.get("GHOST_API_URL")
    if not val:
        raise ConfigError(
            "GHOST_API_URL is not set (e.g. https://blog.osintph.info). "
            "Add it to /opt/falconeye/config/secrets.env."
        )
    return val.rstrip("/")


def get_ghost_admin_key() -> str:
    val = os.environ.get("GHOST_ADMIN_KEY")
    if not val:
        raise ConfigError(
            "GHOST_ADMIN_KEY is not set (format: id:secret_hex). "
            "Obtain it at Ghost Admin → Integrations → Add custom integration."
        )
    return val


def get_ghost_author_slug() -> str:
    val = os.environ.get("GHOST_AUTHOR_SLUG")
    if not val:
        raise ConfigError(
            "GHOST_AUTHOR_SLUG is not set (the Ghost author slug for digest posts). "
            "Add it to /opt/falconeye/config/secrets.env."
        )
    return val


def get_digest_mode() -> str:
    """Return 'draft' or 'published'. Defaults to 'draft' if unset."""
    return os.environ.get("FALCONEYE_DIGEST_MODE", "draft")
