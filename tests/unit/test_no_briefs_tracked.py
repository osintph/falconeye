"""Briefs, review pages and screenshots never go into git.

That has been a standing order in CLAUDE.md, and it was still broken: v3.38.29
removed two release briefs (falconeye-v3.7.0-abuse-reporting.md,
falconeye-v3.8.0-username-enumeration.md), three security review documents and
an architecture review from the repository root and docs/, plus a screenshots
README for images that were never committed. .gitignore now keeps new ones out
of `git add`; this test catches one that was force-added or committed from a
checkout without the ignore file.

Removing a file here does not rewrite history: the old copies stay reachable
in earlier commits.
"""
import fnmatch
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]

# (pattern, what it catches). Root patterns have no slash; fnmatch is applied to
# the repo-relative path, so a root pattern only matches a file at the root.
FORBIDDEN = [
    ("falconeye-v*.md", "a release brief at the repo root"),
    ("*[Rr]eview*.md", "a review document at the repo root"),
    ("*REVIEW*.md", "a review document at the repo root"),
    ("SECURITY_ASSESSMENT*.md", "a security assessment at the repo root"),
    ("docs/*review*.md", "a review document in docs/"),
    ("*review*.html", "a review page"),
    ("*/screenshots/*", "a screenshot"),
    ("screenshots/*", "a screenshot"),
    ("*Screenshot*.png", "a screenshot"),
    ("*Screen Shot*.png", "a screenshot"),
]


def _tracked() -> list:
    try:
        out = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"],
                             capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [p for p in out.stdout.decode().split("\0") if p]


def _matches(path: str, pattern: str) -> bool:
    if "/" not in pattern and "/" in path:
        return False  # root-only pattern
    return fnmatch.fnmatchcase(path, pattern)


def test_no_brief_review_page_or_screenshot_is_tracked():
    offenders = [f"{p} ({why})" for p in _tracked()
                 for pattern, why in FORBIDDEN if _matches(p, pattern)]
    assert not offenders, (
        "these must not be in git (CLAUDE.md standing orders); git rm them: "
        f"{sorted(set(offenders))}"
    )


@pytest.mark.parametrize("path", [
    "falconeye-v3.7.0-abuse-reporting.md",
    "falconeye-v3.39.0-something.md",
    "SECURITY_REVIEW_FABLE.md",
    "security-review-bundle.md",
    "SECURITY_ASSESSMENT_2026-07-20.md",
    "docs/architecture-review-2026-07.md",
    "docs/screenshots/README.md",
    "review-v3.38.29.html",
])
def test_the_patterns_catch_the_files_v3_38_29_removed(path):
    assert any(_matches(path, p) for p, _ in FORBIDDEN), path


@pytest.mark.parametrize("path", [
    "README.md", "CHANGELOG.md", "docs/deploy-runbook.md", "docs/mcp.md",
    "app/static/index.html", "app/static/og-image.png",
    "tests/fixtures/station_qpon/body_browser.html",
])
def test_the_patterns_leave_real_files_alone(path):
    assert not any(_matches(path, p) for p, _ in FORBIDDEN), path


def test_gitignore_carries_the_brief_pattern():
    ignore = (REPO / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "/falconeye-v*.md" in ignore
