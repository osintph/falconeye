"""v3.39.0 items 11 and 12.

The privacy "updated" badge was a hard-coded date that expired on 2026-08-03 and
backed a promise the app did not keep; v3.38.29 removed the promise and the
badge element, and v3.39.0 removes the code. robots.txt named a /stats/ path
that no vhost serves.
"""
import pathlib

STATIC = pathlib.Path(__file__).resolve().parents[2] / "app" / "static"


def test_the_privacy_badge_code_and_element_are_gone():
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "privacyUpdatedBadge" not in js
    assert "privacy-updated-badge" not in js and "privacy-updated-badge" not in html


def test_robots_names_no_stats_path():
    assert "/stats" not in (STATIC / "robots.txt").read_text(encoding="utf-8")
