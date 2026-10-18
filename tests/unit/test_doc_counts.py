"""Every count and source list the docs publish is derived from the code.

v3.38.28 was cut because the published copy had drifted from the code for many
releases at once: the README opened with "Twenty focused modules" while the nav
had 19 investigative tabs, the meta and social tags still said "13 modules",
the README listed Censys in the IP Reputation consensus and said CLEAN needed
"all five keyed sources" although v3.34.0 made Censys enrichment only, the
runbook said the MCP server served seven tabs when it served ten, the username
count differed between the README and the tab, and the operator name was spelled
two ways.

Each check below reads the figure from the code that defines it and compares
every place the docs restate it, so the next drift fails here instead of being
found by a reader. The class, not the instance: any count claim of the same
shape is checked, not only the sentence that was wrong this time.
"""
import pathlib
import re
import subprocess

import pytest

from app.ip_sources import catalog, reputation
from app.username import parser as username_parser

REPO = pathlib.Path(__file__).resolve().parents[2]
README = REPO / "README.md"
INDEX = REPO / "app" / "static" / "index.html"
APP_JS = REPO / "app" / "static" / "app.js"
MCP_SERVER = REPO / "app" / "mcp_server.py"
MCP_DOC = REPO / "docs" / "mcp.md"
RUNBOOK = REPO / "docs" / "deploy-runbook.md"
USERNAME_DOC = REPO / "docs" / "username-enumeration.md"

# Tabs in VALID_TABS that are not investigative tools.
NON_INVESTIGATIVE_TABS = {"home", "contact"}

NUMBER_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
    "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17,
    "eighteen": 18, "nineteen": 19, "twenty": 20, "twenty-one": 21,
}
_NUM = r"\d+|" + "|".join(sorted(NUMBER_WORDS, key=len, reverse=True))

# "19 investigative tabs", "19-tab", "13 modules", "Twenty focused modules",
# "13 OSINT modules", "Eighteen tools". Any of these is a claim about the
# number of tabs.
TAB_COUNT_CLAIM = re.compile(
    rf"\b({_NUM})[- ](?:focused |investigative |OSINT |focused OSINT )?"
    r"(?:modules?|tabs?|tools)\b",
    re.I,
)


def _text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def _as_int(token: str) -> int:
    token = token.lower()
    return int(token) if token.isdigit() else NUMBER_WORDS[token]


# ---------- the figures, from the code ----------

def _valid_tabs() -> list:
    """VALID_TABS as app.js builds it: HOME_TAB, every NAV_GROUPS tab and the
    UNGROUPED_TABS, in the block that ALL_NAV_ENTRIES is assembled from."""
    src = _text(APP_JS)
    assert "const VALID_TABS = ALL_NAV_ENTRIES.map(t => t.id);" in src, (
        "VALID_TABS is no longer derived from ALL_NAV_ENTRIES; update this test "
        "to read the tab list from wherever it now lives"
    )
    block = src[src.index("const NAV_GROUPS"):src.index("const ALL_NAV_ENTRIES")]
    ids = re.findall(r"\{\s*id: '([a-z0-9-]+)'", block)
    assert ids and len(ids) == len(set(ids)), ids
    return ids


def investigative_tab_count() -> int:
    return len([t for t in _valid_tabs() if t not in NON_INVESTIGATIVE_TABS])


def mcp_tool_count() -> int:
    return len(re.findall(r"^\s+Tool\(\s*\n\s+name=\"[a-z_]+\"", _text(MCP_SERVER), re.M))


def username_platform_count() -> int:
    return len(username_parser.load_all())


def test_the_derived_figures_are_sane():
    tabs = _valid_tabs()
    assert "home" in tabs and "contact" in tabs
    assert investigative_tab_count() >= 15
    assert mcp_tool_count() >= 5
    assert username_platform_count() >= 500


# ---------- D1: the tab count ----------

def _readme_opening() -> str:
    for para in _text(README).split("\n\n"):
        if para.startswith("**Free, self-hosted"):
            return para
    raise AssertionError("README opening paragraph not found")


def _meta(name_attr: str) -> str:
    m = re.search(rf'<meta {name_attr} content="([^"]*)"', _text(INDEX))
    assert m, f"<meta {name_attr}> is missing from index.html"
    return m.group(1)


TAB_COUNT_SURFACES = {
    "README opening paragraph": _readme_opening,
    "meta description": lambda: _meta('name="description"'),
    "og:description": lambda: _meta('property="og:description"'),
    "twitter:description": lambda: _meta('name="twitter:description"'),
    "meta keywords": lambda: _meta('name="keywords"'),
}

# Where a count is expected, not just tolerated: the keywords carry none.
TAB_COUNT_REQUIRED = {"README opening paragraph", "meta description",
                      "og:description", "twitter:description"}


@pytest.mark.parametrize("surface", sorted(TAB_COUNT_SURFACES))
def test_every_tab_count_claim_matches_valid_tabs(surface):
    expected = investigative_tab_count()
    text = TAB_COUNT_SURFACES[surface]()
    claims = TAB_COUNT_CLAIM.findall(text)
    if surface in TAB_COUNT_REQUIRED:
        assert claims, f"{surface} no longer states the tab count ({expected})"
    for claim in claims:
        assert _as_int(claim) == expected, (
            f"{surface} says {claim!r} but VALID_TABS minus "
            f"{sorted(NON_INVESTIGATIVE_TABS)} has {expected} tabs"
        )


def test_no_count_claim_anywhere_in_the_page_head_disagrees():
    head = _text(INDEX).split("</head>", 1)[0]
    expected = investigative_tab_count()
    for claim in TAB_COUNT_CLAIM.findall(head):
        assert _as_int(claim) == expected, f"index.html <head> says {claim!r}, expected {expected}"


# ---------- the MCP tool count ----------

MCP_COUNT_SURFACES = {
    "README": (README, r"ships an \*\*MCP server\*\*, so ({n}) of the tabs"),
    "README opening paragraph": (README, r"({n}) of the tabs are also exposed as MCP tools"),
    "docs/mcp.md": (MCP_DOC, r"serves ({n}) FalconEye tools"),
    "docs/deploy-runbook.md": (RUNBOOK, r"serves ({n}) tabs as MCP tools"),
}


@pytest.mark.parametrize("surface", sorted(MCP_COUNT_SURFACES))
def test_the_mcp_tool_count_matches_the_server(surface):
    path, pattern = MCP_COUNT_SURFACES[surface]
    m = re.search(pattern.format(n=_NUM), _text(path), re.I)
    assert m, f"{surface}: the MCP tool count sentence is gone ({pattern})"
    assert _as_int(m.group(1)) == mcp_tool_count(), (
        f"{surface} says {m.group(1)!r} MCP tools, app/mcp_server.py declares "
        f"{mcp_tool_count()}"
    )


# ---------- D2: the consensus sources ----------

def test_the_catalog_is_what_compute_verdict_counts():
    """compute_verdict() counts reputation._NAMES; the catalog is the copy the
    page renders from. If these split, the docs check below is meaningless."""
    assert [s["key"] for s in catalog.REPUTATION_SOURCES] == list(reputation._NAMES)


def test_the_readme_ip_row_lists_exactly_the_verdict_sources():
    readme = _text(README)
    m = re.search(r"consensus verdict \(Clean/Suspicious/Malicious/Incomplete\) from (.+?), plus",
                  readme)
    assert m, "README IP Reputation row no longer names the consensus sources"
    assert m.group(1) == catalog.reputation_labels(), (
        f"README consensus list {m.group(1)!r} differs from the sources "
        f"compute_verdict() counts: {catalog.reputation_labels()!r}"
    )


def test_the_readme_coverage_section_states_the_real_number_and_list():
    readme = re.sub(r"\s+", " ", _text(README))
    m = re.search(rf"only `CLEAN` when all ({_NUM}) keyed sources \((.+?)\) actually answered",
                  readme, re.I)
    assert m, "README 'Reputation coverage is stated' no longer names the count and sources"
    assert _as_int(m.group(1)) == len(reputation._NAMES)
    assert m.group(2) == catalog.reputation_labels()


def test_enrichment_sources_are_never_named_as_voting():
    readme = _text(README)
    row = re.search(r"consensus verdict .+? from (.+?), plus", readme).group(1)
    for s in catalog.SUPPORTING_SOURCES:
        assert s["label"].split()[0] not in row, (
            f"{s['label']} is enrichment only but the README lists it as a verdict source"
        )


# ---------- the username platform count ----------

USERNAME_SURFACES = (README, INDEX, APP_JS, USERNAME_DOC)
PLATFORM_CLAIM = re.compile(r"~?(\d{3,}) (?:external )?platform")


@pytest.mark.parametrize("path", USERNAME_SURFACES, ids=lambda p: p.name)
def test_every_username_platform_count_matches_the_vendored_data(path):
    expected = username_platform_count()
    claims = PLATFORM_CLAIM.findall(_text(path))
    assert claims, f"{path.name} no longer states the platform count"
    for claim in claims:
        assert int(claim) == expected, (
            f"{path.name} says {claim} platforms, the vendored WhatsMyName + "
            f"Sherlock data merges to {expected}"
        )


# ---------- D3: one spelling of the operator name ----------

# Built so this file does not contain the string it bans.
HYPHENATED = "OSINT" + "-PH"
SPELLING_EXEMPT = {"CHANGELOG.md"}


def _tracked_files() -> list:
    try:
        out = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"],
                             capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [p for p in out.stdout.decode().split("\0") if p]


def test_no_hyphenated_operator_name_in_tracked_files():
    offenders = []
    for rel in _tracked_files():
        if rel in SPELLING_EXEMPT:
            continue
        path = REPO / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if HYPHENATED in line:
                offenders.append(f"{rel}:{n}")
    assert not offenders, f"{HYPHENATED} is spelled OSINTPH now: {offenders}"
