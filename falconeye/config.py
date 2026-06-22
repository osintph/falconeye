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
