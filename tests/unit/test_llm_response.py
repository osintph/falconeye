"""
Unit tests for app/utils/llm_response.py — LLM output sanitization helpers.
"""

import pytest
from app.utils.llm_response import (
    parse_llm_json,
    clamp_int,
    safe_str,
    validate_findings_list,
)


# ---------------------------------------------------------------------------
# parse_llm_json
# ---------------------------------------------------------------------------

def test_parse_llm_json_clean():
    assert parse_llm_json('{"a": 1}') == {"a": 1}


def test_parse_llm_json_strips_code_fences():
    raw = '```json\n{"key": "value"}\n```'
    assert parse_llm_json(raw) == {"key": "value"}


def test_parse_llm_json_strips_bare_fences():
    raw = '```\n{"key": "value"}\n```'
    assert parse_llm_json(raw) == {"key": "value"}


def test_parse_llm_json_returns_empty_dict_on_malformed():
    assert parse_llm_json("this is not json") == {}


def test_parse_llm_json_returns_empty_dict_on_array():
    # Root must be a dict; array root is rejected.
    assert parse_llm_json('[1, 2, 3]') == {}


def test_parse_llm_json_returns_empty_dict_on_empty():
    assert parse_llm_json("") == {}


# ---------------------------------------------------------------------------
# clamp_int
# ---------------------------------------------------------------------------

def test_clamp_int_within_range():
    assert clamp_int(50, 0, 100) == 50


def test_clamp_int_coerces_string():
    assert clamp_int("42", 0, 100) == 42


def test_clamp_int_clamps_out_of_range_high():
    assert clamp_int(150, 0, 100) == 100


def test_clamp_int_clamps_out_of_range_low():
    assert clamp_int(-5, 0, 100) == 0


def test_clamp_int_returns_default_on_non_numeric():
    assert clamp_int("banana", 0, 100, default=0) == 0


def test_clamp_int_returns_default_on_none():
    assert clamp_int(None, 0, 100, default=99) == 99


def test_clamp_int_coerces_float():
    assert clamp_int(73.9, 0, 100) == 73


# ---------------------------------------------------------------------------
# safe_str
# ---------------------------------------------------------------------------

def test_safe_str_normal():
    assert safe_str("hello", 100) == "hello"


def test_safe_str_truncates():
    assert safe_str("abcdef", 3) == "abc"


def test_safe_str_coerces_int():
    assert safe_str(42, 100) == "42"


def test_safe_str_returns_default_for_none():
    assert safe_str(None, 100, default="fallback") == "fallback"


def test_safe_str_empty_default():
    assert safe_str(None, 100) == ""


# ---------------------------------------------------------------------------
# validate_findings_list
# ---------------------------------------------------------------------------

def test_validate_findings_list_normal():
    findings = [{"severity": "high", "name": "Foo", "extra": "drop_me"}]
    result = validate_findings_list(findings)
    assert result == [{"severity": "high", "name": "Foo"}]


def test_validate_findings_list_drops_unknown_keys():
    findings = [{"severity": "low", "injected_key": "evil", "name": "X"}]
    result = validate_findings_list(findings)
    assert "injected_key" not in result[0]
    assert result[0]["name"] == "X"


def test_validate_findings_list_drops_non_dict_entries():
    findings = ["not a dict", 42, {"severity": "info", "name": "ok"}]
    result = validate_findings_list(findings)
    assert len(result) == 1
    assert result[0]["name"] == "ok"


def test_validate_findings_list_returns_empty_for_non_list():
    assert validate_findings_list("not a list") == []
    assert validate_findings_list(None) == []
    assert validate_findings_list({"key": "val"}) == []


def test_validate_findings_list_custom_allowed_keys():
    findings = [{"query": "dork", "risk_level": "high", "other": "drop"}]
    result = validate_findings_list(findings, allowed_keys={"query", "risk_level"})
    assert result == [{"query": "dork", "risk_level": "high"}]
