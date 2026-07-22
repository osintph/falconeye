"""
Structural guard against the v3.15.3 class of bug: app.js's Breach Check
password lookup deliberately fetch()es https://api.pwnedpasswords.com
directly from the browser (never through our backend, so the password itself
never leaves the client — see app/static/app.js's "Section 2" comment), but
nginx's CSP connect-src still said 'self' only. The browser silently blocked
the request; nothing in the test suite caught it because the only prior
coverage was of the request's *shape* (right prefix, right endpoint), not
whether the browser would actually be allowed to send it.

This asserts every direct (non-relative, non-'/api/*') fetch() origin in
app.js is present in nginx/falconeye.conf's connect-src, so a future feature
that adds a direct third-party browser request without updating the CSP
fails here instead of in a user's console.
"""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
NGINX_CONF = REPO_ROOT / "nginx" / "falconeye.conf"
APP_JS = REPO_ROOT / "app" / "static" / "app.js"


def _csp_directive_values(name):
    conf = NGINX_CONF.read_text()
    csp = re.search(r'Content-Security-Policy\s+"([^"]+)"', conf)
    assert csp, "Content-Security-Policy header not found in nginx/falconeye.conf"
    directive = re.search(rf"{re.escape(name)}\s+([^;]+);", csp.group(1))
    assert directive, f"{name} directive not found in the CSP header"
    return set(directive.group(1).split())


def _direct_fetch_origins():
    js = APP_JS.read_text()
    return {
        f"https://{m.group(1)}"
        for m in re.finditer(r"fetch\(\s*[`\"']https://([^/`\"']+)", js)
    }


def test_every_direct_fetch_origin_is_allowed_by_connect_src():
    connect_src = _csp_directive_values("connect-src")
    origins = _direct_fetch_origins()
    assert origins, "expected at least one direct https:// fetch() in app.js (e.g. pwnedpasswords) — did it move or get removed?"
    for origin in origins:
        assert origin in connect_src, (
            f"app.js fetch()es {origin} directly but nginx's CSP connect-src "
            f"({sorted(connect_src)}) doesn't allow it — the browser will "
            f"silently block the request. Add it to connect-src in both "
            f"nginx/falconeye.conf and the live conf (/etc/nginx/sites-available/falconeye)."
        )


def test_pwnedpasswords_origin_specifically_covered():
    assert "https://api.pwnedpasswords.com" in _direct_fetch_origins()
    assert "https://api.pwnedpasswords.com" in _csp_directive_values("connect-src")
