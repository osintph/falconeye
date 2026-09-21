"""
Structural guard against the v3.32.1 class of bug: the Ransomware Watch world
map silently stopped rendering ("Map library did not load.") because every
asset under /static/vendor/ was being challenged at the Cloudflare edge, a
custom WAF rule in the zone that filters WordPress scanner noise matches the
"vendor" path segment, and its /static/ exclusion did not take precedence over
the block. The origin was perfectly healthy: gunicorn served
topojson-client.min.js as a 200 with the right byte count the whole time, so
nothing server-side and no existing test noticed. The browser just got a 503
for the script tag and a 403 for the topojson, and window.topojson stayed
undefined.

Two things went uncaught and both are covered here:

  1. Nothing asserted that the local /static/* URLs index.html and app.js
     reference actually resolve to files in the repo, so a rename or a
     dropped file would only show up in production.
  2. Nothing stopped us from parking first-party assets under a URL segment
     that CDNs and WAFs habitually block on sight.

The live end-to-end check at the bottom is opt-in (it needs the network).
There is deliberately no Playwright here, the map's real precondition is
that its two hard dependencies are fetchable and the topojson carries country
geometry, which is exactly what the browser needs to draw the country paths,
and that is assertable over HTTP without a browser engine.

Run the live check from a workstation, NOT from the VPS. It asserts what a
user's browser sees, and Cloudflare bot management challenges datacenter
source IPs on the larger payloads, from the VPS the world topojson comes
back 403 even when the site is perfectly healthy. The assertion messages call
this out so a false failure is not mistaken for a regression.
"""
import json
import os
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR = REPO_ROOT / "app" / "static"
INDEX_HTML = STATIC_DIR / "index.html"
APP_JS = STATIC_DIR / "app.js"

LIVE_BASE = "https://falconeye.osintph.info"

# URL path segments that WAF rules commonly block outright, because scanners
# probe them constantly. First-party assets must never live under one of these:
# the origin will serve them fine and the edge will still refuse, which is
# invisible to every server-side test we have.
BLOCKED_SEGMENTS = {
    "vendor",      # WordPress/Composer scanner target, the v3.32.1 outage
    "node_modules",
    ".git",
    ".env",
    "wp-admin",
    "wp-includes",
}


def _local_static_refs():
    """Every first-party /static/* URL the frontend depends on at runtime:
    script/link tags in index.html plus fetch()es in app.js. Query strings
    (the ?v=<version> cache-buster) are stripped."""
    refs = set()
    html = INDEX_HTML.read_text()
    for m in re.finditer(r'(?:src|href)\s*=\s*["\'](/static/[^"\']+)["\']', html):
        refs.add(m.group(1))
    js = APP_JS.read_text()
    for m in re.finditer(r"""fetch\(\s*[`"'](/static/[^`"']+)""", js):
        refs.add(m.group(1))
    return {r.split("?", 1)[0] for r in refs}


def _to_disk_path(url_path):
    return STATIC_DIR / url_path[len("/static/"):]


def test_frontend_references_at_least_the_known_static_assets():
    """Guard the guard: if the regexes above stop matching, the two tests
    below would pass vacuously."""
    refs = _local_static_refs()
    assert len(refs) >= 3, f"expected several /static/* references, found {sorted(refs)}, did the parsing break?"
    assert any(r.endswith("topojson-client.min.js") for r in refs), \
        "index.html no longer references topojson-client, the Ransomware Watch map needs it"
    assert any(r.endswith("world-countries-50m.json") for r in refs), \
        "app.js no longer fetches the world topojson, the Ransomware Watch map needs it"
    assert any(r.endswith("jspdf.umd.min.js") for r in refs), \
        "index.html no longer references jsPDF, client-side PDF export needs it"


def test_every_local_static_reference_exists_on_disk():
    for url_path in sorted(_local_static_refs()):
        disk = _to_disk_path(url_path)
        assert disk.is_file(), (
            f"{url_path} is referenced by the frontend but {disk.relative_to(REPO_ROOT)} "
            f"does not exist. A renamed or dropped asset fails here instead of "
            f"silently breaking a panel in production."
        )


def test_no_static_asset_sits_under_a_waf_blocked_segment():
    for url_path in sorted(_local_static_refs()):
        segments = {s.lower() for s in url_path.strip("/").split("/")}
        bad = segments & BLOCKED_SEGMENTS
        assert not bad, (
            f"{url_path} sits under the URL segment {sorted(bad)!r}, which WAF rules "
            f"commonly block because scanners probe it constantly. The origin will "
            f"serve it and the edge will still return 403/503, which no server-side "
            f"test can see. "
            f"This is exactly how the Ransomware Watch map broke in v3.32.1, the "
            f"vendored JS was moved to /static/lib/ for this reason. Pick another path."
        )


# ---- Live smoke test (opt-in: needs network) ----

_LIVE = os.environ.get("FALCONEYE_LIVE_SMOKE") == "1"
_skip_live = pytest.mark.skipif(
    not _LIVE, reason="live smoke test, set FALCONEYE_LIVE_SMOKE=1 to run"
)


@_skip_live
def test_live_map_dependencies_are_fetchable_through_the_edge():
    """The #ransomware/overview map renders only if both of these are
    reachable *through Cloudflare*. Fetching them from the origin is not a
    substitute, that is precisely what passed while the map was broken.

    Run this from a workstation, not the VPS; see the module docstring."""
    import httpx

    browser_ua = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
    )
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        for url_path in sorted(_local_static_refs()):
            resp = client.get(LIVE_BASE + url_path, headers={"User-Agent": browser_ua})
            mitigated = resp.headers.get("cf-mitigated")
            assert resp.status_code == 200, (
                f"{url_path} returned {resp.status_code} through the edge "
                f"(cf-mitigated: {mitigated or 'none'}). The asset is unreachable "
                f"in a real browser even if the origin serves it."
                + (
                    "  NOTE: a 'challenge' here can also mean Cloudflare is "
                    "challenging *your* source IP, that happens from the VPS and "
                    "other datacenter addresses. Re-run from a client network "
                    "before treating this as a regression."
                    if mitigated
                    else ""
                )
            )


@_skip_live
def test_live_topojson_carries_country_geometry():
    """The country paths the map draws come from topo.objects.countries.
    Assert the live payload actually parses and carries them, so a truncated
    or challenge-page response fails here rather than rendering an empty SVG."""
    import httpx

    refs = [r for r in _local_static_refs() if r.endswith("world-countries-50m.json")]
    assert refs, "no world topojson reference found"
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        resp = client.get(LIVE_BASE + refs[0])
    assert resp.status_code == 200, (
        f"topojson returned {resp.status_code} through the edge "
        f"(cf-mitigated: {resp.headers.get('cf-mitigated', 'none')}). If this is a "
        f"challenge, check you are not running from the VPS, see the module docstring."
    )
    topo = json.loads(resp.text)
    geometries = topo.get("objects", {}).get("countries", {}).get("geometries", [])
    assert len(geometries) > 100, (
        f"world topojson carries only {len(geometries)} country geometries, the map "
        f"would render an SVG with (almost) no country paths."
    )
