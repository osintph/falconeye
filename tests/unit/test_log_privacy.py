"""User-supplied values must not be written to the log in the clear.

v3.33.3 gave the application its first working logging configuration. That was
the right fix, but it had a consequence nobody had signed off: a public,
unauthenticated OSINT tool started persisting a stream of visitor activity to
journald, which is retained, with nothing in the privacy policy saying so.

The values at issue are the ones a visitor supplies or asks about: IPs, domains,
hosts, Telegram handles, uploaded filenames, and LLM output derived from pasted
email headers and scripts. `app/utils/logsafe.tag()` replaces them with a short
salted hash, which keeps the operational value (correlating the lines of one
lookup, seeing which source was slow) without retaining the query.

This is a structural test rather than a list of known call sites, so a log line
added later cannot quietly reintroduce the problem.
"""
import pathlib
import re

APP = pathlib.Path(__file__).resolve().parents[2] / "app"

# Argument names that carry something a visitor supplied or asked about.
USER_VALUES = (
    "domain", "ip", "host", "identifier", "resource", "source_ip",
    "normalized", "raw_text", "pname", "jc", "extracted", "canonical",
    "kg_title", "file_path", "target",
    # v3.35.0, Route Map. A trace is a description of the visitor's own
    # network: the hostnames and addresses on their path, where they are, and
    # what they chose to trace to. The upload token is a credential.
    "hostname", "client_ip", "addr", "trace_text", "token", "poll_key",
    "origin", "origin_lat", "origin_lon", "city",
)

# Call sites where the name does not mean what it looks like.
ALLOW = {
    # "target" here is a source name ("abuseipdb"), not a user value. The real
    # target argument on the same line is tagged.
    ("app/ip_sources/reputation.py", "target"),
    # The ransomware collector runs from a cron timer over a fixed watchlist and
    # public feeds. Nothing in it comes from a visitor.
    ("app/collectors/ransomware_collect.py", "ip"),
    ("app/collectors/ransomware_collect.py", "domain"),
}


def _log_blocks(path):
    """Yield (line_number, source_text) for every log call in a file."""
    lines = path.read_text().split("\n")
    i = 0
    while i < len(lines):
        if re.search(r"\blog\.(info|warning|error|critical)\(", lines[i]):
            depth = lines[i].count("(") - lines[i].count(")")
            j, block = i + 1, [lines[i]]
            while j < len(lines) and depth > 0:
                block.append(lines[j])
                depth += lines[j].count("(") - lines[j].count(")")
                j += 1
            yield i + 1, "\n".join(block)
            i = max(j, i + 1)
        else:
            i += 1


def test_no_log_call_passes_a_user_value_in_the_clear():
    offenders = []
    for path in sorted(APP.rglob("*.py")):
        rel = str(path.relative_to(APP.parent))
        for lineno, block in _log_blocks(path):
            for name in USER_VALUES:
                if (rel, name) in ALLOW:
                    continue
                # the bare name used as an argument, in %-style or an f-string
                bare = re.search(rf"(?<![\w.(]){name}\s*[,)]", block)
                fstr = re.search(rf"\{{\s*{name}\s*[}}:!]", block)
                if not (bare or fstr):
                    continue
                if f"tag({name}" in block:
                    continue
                offenders.append(f"{rel}:{lineno} passes {name!r} unhashed")

    assert not offenders, (
        "log calls write user-supplied values in the clear:\n  "
        + "\n  ".join(offenders)
        + "\n\nWrap them with app.utils.logsafe.tag(), or add the call site to "
          "ALLOW in this test if the name does not mean what it looks like."
    )


def test_tag_is_not_reversible_by_shape():
    """The tag must not leak the value through length or prefix."""
    from app.utils.logsafe import tag

    for value in ("1.1.1.1", "203.0.113.255", "a-very-long-domain-name.example.com"):
        t = tag(value)
        assert t.startswith("h:")
        assert len(t) == len("h:") + 12, "tag length must not vary with the input"
        assert value not in t
    # Length is constant regardless of input length, so the tag leaks nothing
    # about the size of what was looked up.
    assert len({len(tag(v)) for v in ("a", "1.1.1.1", "x" * 200)}) == 1


def test_ip_source_line_shape_is_stable():
    """The operator-facing contract for the line, so a rename is caught."""
    from app.ip_sources import reputation
    src = (APP / "ip_sources" / "reputation.py").read_text()
    assert "event=ip_source source=%s target=%s status=%s latency_ms=%d cached=%s" in src
    assert "tag(target)" in src, "the target field must be hashed"
    assert callable(reputation.log_source_call)


# ---------- v3.35.0: the Route Map routes specifically ----------

ROUTEMAP = APP / "routemap"


def test_the_route_map_modules_are_covered_by_the_structural_rule():
    """A guard on the guard: if the package moves, the sweep above stops
    covering it and this file keeps passing for the wrong reason."""
    assert ROUTEMAP.is_dir(), "app/routemap/ has moved; update this test"
    modules = {p.name for p in ROUTEMAP.glob("*.py")}
    assert {"routes.py", "atlas.py", "geo.py", "hoiho.py", "tokens.py"} <= modules


def test_no_route_map_log_line_writes_a_trace_or_an_origin_in_the_clear():
    """The values a Route Map request carries that must never be retained.

    A trace says which routers are between the visitor and their target; the
    origin says where the visitor is. Neither belongs in journald, and the
    operator needs neither to debug this tab.
    """
    offenders = []
    for path in sorted(ROUTEMAP.glob("*.py")):
        rel = str(path.relative_to(APP.parent))
        for lineno, block in _log_blocks(path):
            for needle in ("trace_text", "origin_lat", "origin_lon", "poll_key"):
                if not re.search(rf"(?<![\w.]){re.escape(needle)}\s*[,)]", block):
                    continue
                # A tagged value is fine, and so is a measurement OF the value
                # that cannot reconstruct it: "bytes=%d", len(trace_text) tells
                # the operator how big an upload was and nothing about its
                # contents, which is exactly the trade this rule is drawing.
                if f"tag({needle}" in block or f"len({needle})" in block:
                    continue
                offenders.append(f"{rel}:{lineno} logs {needle!r} unhashed")
    assert not offenders, (
        "Route Map log calls retain the visitor's trace or location:\n  "
        + "\n  ".join(offenders))


def test_the_token_and_the_target_are_tagged_where_they_are_logged():
    """Positive assertion, so removing the tagging fails rather than passing."""
    tokens_src = (ROUTEMAP / "tokens.py").read_text()
    assert "tag(token)" in tokens_src, "the upload token is logged in the clear"
    assert "tag(target)" in tokens_src, "the traced target is logged in the clear"

    atlas_src = (ROUTEMAP / "atlas.py").read_text()
    assert "tag(target)" in atlas_src, "the Atlas target is logged in the clear"

    routes_src = (ROUTEMAP / "routes.py").read_text()
    assert "tag(client_ip)" in routes_src, "the visitor address is logged in the clear"


def test_the_origin_guess_does_not_log_the_resolved_city():
    """Knowing which city a tagged visitor is in is the thing being avoided."""
    routes_src = (ROUTEMAP / "routes.py").read_text()
    for lineno, block in _log_blocks(ROUTEMAP / "routes.py"):
        if "origin_guess" in block:
            assert "display" not in block and "city" not in block, (
                f"routes.py:{lineno} logs the resolved city of a visitor")
