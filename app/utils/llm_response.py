"""
Helpers for safely consuming LLM JSON output.

Prevents 500s when a model returns unexpected types and provides a consistent
interface for clamping, truncating, and filtering fields before they reach
application logic or client responses.
"""

import json
import re
from typing import Any, Optional, Set

_FINDINGS_ALLOWED_KEYS: Set[str] = {"severity", "category", "name", "evidence", "detail"}


def parse_llm_json(raw: str) -> dict:
    """Strip markdown code fences and parse JSON; return empty dict on any failure."""
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```\s*$", "", raw.strip())
    try:
        result = json.loads(raw)
        if isinstance(result, dict):
            return result
        return {}
    except (json.JSONDecodeError, ValueError):
        return {}


def clamp_int(value: Any, min_val: int, max_val: int, default: int = 0) -> int:
    """Coerce value to int and clamp to [min_val, max_val]; return default on failure."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    return max(min_val, min(max_val, v))


def safe_str(value: Any, max_len: int = 500, default: str = "") -> str:
    """Coerce value to str and truncate to max_len; return default for None."""
    if value is None:
        return default
    try:
        s = str(value)
    except Exception:
        return default
    return s[:max_len]


def validate_findings_list(
    value: Any,
    allowed_keys: Optional[Set[str]] = None,
) -> list:
    """Return a sanitized list of dicts from value.

    Drops any entry that is not a dict, and strips any key not in allowed_keys.
    """
    if allowed_keys is None:
        allowed_keys = _FINDINGS_ALLOWED_KEYS
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        if not isinstance(item, dict):
            continue
        cleaned = {k: v for k, v in item.items() if k in allowed_keys}
        result.append(cleaned)
    return result
