"""Parser: WMN/Sherlock adapters, category/NSFW/priority tagging, cross-engine merge."""
import json
from pathlib import Path

from app.username import parser


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


WMN_FIXTURE = {
    "sites": [
        {"name": "GitHub (User)", "uri_check": "https://github.com/{account}",
         "e_code": 200, "e_string": "avatar", "m_code": 404, "m_string": "", "cat": "coding",
         "known": ["torvalds"]},
        {"name": "AdultSite", "uri_check": "https://adult.example/{account}",
         "e_code": 200, "e_string": "x", "m_code": 404, "cat": "xx NSFW xx"},
        {"name": "NoPlaceholder", "uri_check": "https://static.example/", "e_code": 200, "cat": "misc"},
        {"name": "Weibo", "uri_check": "https://weibo.com/{account}",
         "e_code": 200, "e_string": "profile", "m_code": 404, "cat": "misc"},
    ]
}

SHERLOCK_FIXTURE = {
    "$schema": "https://example/schema.json",
    "GitHub": {"url": "https://github.com/{}", "urlMain": "https://github.com",
               "errorType": "status_code", "username_claimed": "torvalds"},
    "OnlySherlock": {"url": "https://onlysherlock.example/{}", "urlMain": "https://onlysherlock.example",
                     "errorType": "message", "errorMsg": "not found", "isNSFW": False},
}


def test_load_wmn_counts_and_tagging(tmp_path):
    sites = parser.load_wmn(_write(tmp_path, "wmn.json", WMN_FIXTURE))
    # NoPlaceholder skipped (no {account})
    assert len(sites) == 3
    by_name = {s.name: s for s in sites}
    assert by_name["GitHub (User)"].category == "Developer"
    assert by_name["GitHub (User)"].priority == 3          # major → priority 3
    assert by_name["AdultSite"].is_nsfw is True
    assert by_name["AdultSite"].category == "Adult"
    assert by_name["Weibo"].category == "Regional"          # keyword categorization
    assert by_name["GitHub (User)"].sources == ["wmn"]


def test_load_sherlock_counts(tmp_path):
    sites = parser.load_sherlock(_write(tmp_path, "s.json", SHERLOCK_FIXTURE))
    assert len(sites) == 2  # $schema skipped
    assert {s.name for s in sites} == {"GitHub", "OnlySherlock"}


def test_merge_dedups_by_hostname(tmp_path):
    wmn = parser.load_wmn(_write(tmp_path, "wmn.json", WMN_FIXTURE))
    sher = parser.load_sherlock(_write(tmp_path, "s.json", SHERLOCK_FIXTURE))
    merged = parser.merge_sites(wmn, sher)
    # 3 WMN + 1 Sherlock-only (OnlySherlock); GitHub deduped into the WMN anchor
    assert len(merged) == 4
    gh = next(s for s in merged if s.name == "GitHub (User)")
    assert gh.sources == ["wmn", "sherlock"]                # cross-engine → dual
    assert any(s.name == "OnlySherlock" and s.sources == ["sherlock"] for s in merged)


def test_nsfw_tagging_excludes(tmp_path):
    wmn = parser.load_wmn(_write(tmp_path, "wmn.json", WMN_FIXTURE))
    without_nsfw = [s for s in wmn if not s.is_nsfw]
    assert "AdultSite" not in {s.name for s in without_nsfw}
    assert "AdultSite" in {s.name for s in wmn}


def test_malformed_returns_empty():
    assert parser.load_wmn(Path("/nonexistent/wmn.json")) == []
    assert parser.load_sherlock(Path("/nonexistent/s.json")) == []


def test_real_data_loads_and_is_sane():
    """The vendored files parse to a plausible dual-engine site list."""
    merged = parser.load_all()
    assert len(merged) > 800
    assert any(len(s.sources) > 1 for s in merged)          # dual-source present
    quick = parser.select_sites("quick", include_nsfw=False)
    full = parser.select_sites("full", include_nsfw=False)
    assert 0 < len(quick) < len(full)                       # quick is a strict subset size
    assert not any(s.is_nsfw for s in quick)                # NSFW excluded by default
    assert not any(s.is_nsfw for s in full)
    assert len(parser.select_sites("full", include_nsfw=True)) > len(full)
