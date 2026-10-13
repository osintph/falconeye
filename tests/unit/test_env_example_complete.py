"""Every environment variable the app reads must be documented in .env.example.

The bug class, found in the v3.36.8 -> v3.38.25 audit: twenty-five variables the
app reads (the whole HUNT_NRD_* and HUNT_URLSCAN_* sets, the ASM verify-rate caps,
and more) had code defaults but were absent from .env.example, so a self-hoster had
no way to learn they existed or to tune them. A variable the code reads is part of
the contract; .env.example is where that contract is written down.

The rule, stated once: for every literal variable name the application reads
through getenv_clean(), os.getenv(), os.environ.get() or os.environ[...], there must
be a line in .env.example that declares it, whether active (`NAME=`) or commented
out (`# NAME=`). A variable read tomorrow without a matching line fails here.

Dynamically-read names (built from a variable, not a string literal) are out of
scope: this test cannot see them, and the reputation-source key names that are read
that way also appear as literals in their own modules, so they are still covered.
"""
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[2]
APP = REPO / "app"
ENV_EXAMPLE = REPO / ".env.example"

_READ_RE = re.compile(
    r'(?:getenv_clean|os\.getenv|os\.environ\.get)\(\s*["\']([A-Z][A-Z0-9_]*)["\']'
    r'|os\.environ\[\s*["\']([A-Z][A-Z0-9_]*)["\']\s*\]'
)
_DECL_RE = re.compile(r"^\s*#?\s*([A-Z][A-Z0-9_]*)=")

# Names the app reads that are intentionally NOT in .env.example. Empty today, on
# purpose: if something lands here it needs a reason in the comment beside it.
_ALLOWLIST: set = set()


def _vars_read_by_app() -> set:
    names = set()
    for path in APP.rglob("*.py"):
        for m in _READ_RE.finditer(path.read_text(encoding="utf-8", errors="ignore")):
            names.add(m.group(1) or m.group(2))
    return names


def _vars_declared_in_example() -> set:
    names = set()
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        m = _DECL_RE.match(line)
        if m:
            names.add(m.group(1))
    return names


def test_env_example_exists_and_has_entries():
    assert ENV_EXAMPLE.is_file()
    assert _vars_declared_in_example(), ".env.example declares no variables"


def test_every_env_var_the_app_reads_is_in_env_example():
    read = _vars_read_by_app()
    declared = _vars_declared_in_example()
    missing = sorted(read - declared - _ALLOWLIST)
    assert not missing, (
        "these variables are read by the app but are not in .env.example (add a "
        "commented or active line with a one-line comment above it, so a self-hoster "
        f"can find and tune them): {missing}"
    )


def test_no_inline_comments_on_value_lines():
    """getenv_clean strips a trailing ' # ...', but .env.example forbids inline
    comments anyway so a plain python-dotenv reader is safe too. Comments go above."""
    offenders = []
    for n, line in enumerate(ENV_EXAMPLE.read_text(encoding="utf-8").splitlines(), 1):
        if _DECL_RE.match(line) and not line.lstrip().startswith("#"):
            value = line.split("=", 1)[1]
            if re.search(r"\s#", value):
                offenders.append((n, line))
    assert not offenders, f"inline comments on value lines (move them above): {offenders}"
