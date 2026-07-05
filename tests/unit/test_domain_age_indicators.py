"""
Unit tests for match_age_indicators() in app/scanner/ph_bank_indicators.py
"""

from app.scanner.ph_bank_indicators import match_age_indicators

_FOUND_BASE = {
    "found": True,
    "created_at": "2026-07-01T00:00:00+00:00",
    "source": "rdap",
    "error": None,
}


def test_fires_high_severity_when_age_1_day():
    result = match_age_indicators({**_FOUND_BASE, "age_days": 1})
    assert len(result) == 1
    assert result[0]["id"] == "dom_age_recent"
    assert result[0]["severity"] == "high"


def test_fires_high_severity_when_age_7_days():
    result = match_age_indicators({**_FOUND_BASE, "age_days": 7})
    assert len(result) == 1
    assert result[0]["id"] == "dom_age_recent"
    assert result[0]["severity"] == "high"


def test_fires_high_severity_when_age_0_days():
    result = match_age_indicators({**_FOUND_BASE, "age_days": 0})
    assert len(result) == 1
    assert result[0]["severity"] == "high"


def test_fires_medium_severity_when_age_8_days():
    result = match_age_indicators({**_FOUND_BASE, "age_days": 8})
    assert len(result) == 1
    assert result[0]["id"] == "dom_age_recent"
    assert result[0]["severity"] == "medium"


def test_fires_medium_severity_when_age_30_days():
    result = match_age_indicators({**_FOUND_BASE, "age_days": 30})
    assert len(result) == 1
    assert result[0]["id"] == "dom_age_recent"
    assert result[0]["severity"] == "medium"


def test_fires_low_severity_when_age_31_days():
    result = match_age_indicators({**_FOUND_BASE, "age_days": 31})
    assert len(result) == 1
    assert result[0]["id"] == "dom_age_moderate"
    assert result[0]["severity"] == "low"


def test_fires_low_severity_when_age_90_days():
    result = match_age_indicators({**_FOUND_BASE, "age_days": 90})
    assert len(result) == 1
    assert result[0]["id"] == "dom_age_moderate"
    assert result[0]["severity"] == "low"


def test_does_not_fire_when_age_over_90_days():
    result = match_age_indicators({**_FOUND_BASE, "age_days": 91})
    assert result == []


def test_does_not_fire_when_age_365_days():
    result = match_age_indicators({**_FOUND_BASE, "age_days": 365})
    assert result == []


def test_does_not_fire_when_lookup_failed():
    failed = {"found": False, "created_at": "", "age_days": -1, "source": "", "error": "lookup failed"}
    result = match_age_indicators(failed)
    assert result == []


def test_does_not_fire_on_empty_dict():
    result = match_age_indicators({})
    assert result == []


def test_description_contains_age_and_date():
    result = match_age_indicators({**_FOUND_BASE, "age_days": 5})
    assert len(result) == 1
    desc = result[0]["description"]
    assert "5" in desc
    assert "2026-07-01" in desc


def test_description_singular_day():
    result = match_age_indicators({**_FOUND_BASE, "age_days": 1})
    desc = result[0]["description"]
    assert "1 day " in desc  # singular, not "1 days"


def test_indicator_has_all_required_keys():
    result = match_age_indicators({**_FOUND_BASE, "age_days": 3})
    assert len(result) == 1
    for key in ("id", "type", "pattern", "severity", "description", "category"):
        assert key in result[0], f"Missing key: {key}"


def test_category_is_ph_banking():
    for age in (3, 15, 60):
        result = match_age_indicators({**_FOUND_BASE, "age_days": age})
        assert result[0]["category"] == "ph_banking"
