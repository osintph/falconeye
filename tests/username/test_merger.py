"""Merger: category grouping, confidence tiers, stats, empty-category exclusion."""
from app.username.checker import CheckResult
from app.username.merger import build_result
from app.username.parser import Site


def _hit(name, category, sources):
    site = Site(name, f"https://{name}.example/{{}}", category, {"engine": "wmn"}, sources, False, 2)
    return CheckResult(site, True, f"https://{name}.example/u", 200, None, 10)


def _miss(name, category):
    site = Site(name, "x", category, {"engine": "wmn"}, ["wmn"], False, 1)
    return CheckResult(site, False, None, 404, None, 5)


def test_grouping_confidence_and_stats():
    results = [
        _hit("GitHub", "Developer", ["wmn", "sherlock"]),
        _hit("GitLab", "Developer", ["wmn"]),
        _hit("Twitter", "Social", ["wmn", "sherlock"]),
        _miss("Nowhere", "Gaming"),
    ]
    out = build_result(results, "bob", "quick", checked_count=4, unchecked_count=0, duration_ms=1234)

    assert out["hit_count"] == 3
    assert out["dual_source_count"] == 2
    assert out["checked_count"] == 4
    assert out["duration_ms"] == 1234

    cats = {c["name"]: c for c in out["categories"]}
    # Developer has 2 hits, Social 1 → Developer sorts first
    assert out["categories"][0]["name"] == "Developer"
    assert cats["Developer"]["count"] == 2
    # dual-source hit sorts before single-source within a category
    assert cats["Developer"]["hits"][0]["site"] == "GitHub"
    assert cats["Developer"]["hits"][0]["confidence"] == "high"
    assert cats["Developer"]["hits"][1]["confidence"] == "medium"
    # no category for the miss
    assert "Gaming" not in cats


def test_unchecked_adds_warning():
    out = build_result([], "bob", "full", checked_count=10, unchecked_count=5, duration_ms=100)
    assert any("not checked" in w for w in out["warnings"])
    assert out["hit_count"] == 0
    assert out["categories"] == []
