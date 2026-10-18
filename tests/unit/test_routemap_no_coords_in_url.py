"""No request the Route Map tab makes carries coordinates in its URL.

v3.39.0: the poll used to append origin_lat/origin_lon to its query string, so
every poll wrote the visitor's rounded location into the nginx and gunicorn
access logs. Coordinates now travel only in JSON request bodies (and the
server-side token). This reads the Route Map code in app.js and fails if any
URL it builds could carry them, whatever the next change looks like: a query
parameter set by URLSearchParams, a literal "lat=" or "origin_" in a URL, or an
origin field read anywhere except inside a JSON.stringify body.
"""
import pathlib
import re

APP_JS = pathlib.Path(__file__).resolve().parents[2] / "app" / "static" / "app.js"
COORD = re.compile(r"origin_lat|origin_lon|_rmOrigin\.lat|_rmOrigin\.lon|\blat\b|\blon\b")


def _routemap_source() -> str:
    src = APP_JS.read_text(encoding="utf-8")
    start = src.index("async function rmApi(")
    return src[start:]


def test_no_url_built_by_the_route_map_tab_names_a_coordinate():
    src = _routemap_source()
    urls = re.findall(r"`(/api/routemap/[^`]*)`|'(/api/routemap/[^']*)'", src)
    assert urls, "no Route Map API URL found; the test is reading the wrong code"
    for groups in urls:
        url = next(g for g in groups if g)
        # "origin-guess" is an endpoint name; a coordinate would be lat/lon or an
        # origin_ field, or the page's _rmOrigin interpolated into the URL.
        assert not re.search(r"lat|lon|origin_|_rmOrigin", url), f"coordinate in a Route Map URL: {url}"


def test_no_query_parameter_carries_a_coordinate():
    src = _routemap_source()
    for m in re.finditer(r"\.set\(\s*'([^']+)'", src):
        assert not re.search(r"lat|lon|origin", m.group(1)), (
            f"URLSearchParams sets {m.group(1)!r}; coordinates go in a JSON body")
    for m in re.finditer(r"new URLSearchParams\(\{([^}]*)\}", src):
        assert not COORD.search(m.group(1)), f"URLSearchParams built with a coordinate: {m.group(0)}"


def test_every_origin_field_sits_inside_a_json_body():
    lines = _routemap_source().splitlines()
    for i, line in enumerate(lines):
        if "origin_lat" not in line and "origin_lon" not in line:
            continue
        window = "\n".join(lines[max(0, i - 8):i + 1])
        assert "JSON.stringify(" in window, (
            f"origin field outside a JSON body near: {line.strip()}")
