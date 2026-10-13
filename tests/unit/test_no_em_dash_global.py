"""No em dashes (or en/figure/bar dashes, or their HTML entities) anywhere in the
FalconEye code, templates and UI, and none in a rendered PDF even when the source
data contains them.

This is the repo-wide guard the v3.38.2 review asked for, modelled on the Route
Map dash handling. It is deliberately general: it rejects the dash character class
and the entities wherever they appear in the authored Python, the HTML template,
the stylesheet and the frontend bundle, and it proves the PDF renderer normalises
dashes out of external data. The dash characters are referenced through chr() so
this test file itself contains none.
"""
import pathlib
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]

# U+2014 em, U+2013 en, U+2012 figure, U+2015 horizontal bar, and the entities.
_DASH_CHARS = (chr(0x2014), chr(0x2013), chr(0x2012), chr(0x2015))
_DASH_ENTITIES = ("&mdash;", "&ndash;", "&#8212;", "&#8211;", "&#x2014;", "&#x2013;")
_NEEDLES = _DASH_CHARS + _DASH_ENTITIES


def _authored_files():
    files = sorted(p for p in (REPO / "app").rglob("*.py") if "__pycache__" not in str(p))
    files += [REPO / "app" / "static" / "index.html",
              REPO / "app" / "static" / "app.js",
              REPO / "app" / "static" / "style.css",
              REPO / "CHANGELOG.md"]
    return files


@pytest.mark.parametrize("path", _authored_files(), ids=lambda p: str(p.relative_to(REPO)))
def test_no_em_dash_in_authored_files(path):
    text = path.read_text(encoding="utf-8")
    for needle in _NEEDLES:
        assert needle not in text, f"{path.relative_to(REPO)} contains {needle!r}"


def test_pdf_renderer_normalises_dashes_from_data():
    try:
        import pypdf
    except Exception:  # noqa: BLE001
        pytest.skip("pypdf not installed")
    from app.pdf import report as pdfr
    em = chr(0x2014)
    payload = {
        "kind": "asm", "title": f"ex{em}ample.com", "generated_ts": time.time(),
        "mode": "On-demand", "engagement": "", "incomplete": False, "source_status": [],
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0},
        "summary_line": "s",
        "findings": [{"severity": "low", "kind": "headers", "title": f"Missing header{em}HSTS",
                      "host": "a.example.com", "detail": f"evidence{em}with a dash",
                      "remediation": f"fix{em}it"}],
        "hosts": [{"host": "a.example.com", "kind": "own", "resolved_ips": ["192.0.2.1"],
                   "ports": [443], "server": f"nginx{em}1.25", "tls": None}],
        "posture": {}, "methodology": f"method{em}ology", "attribution": [f"src{em}one"],
    }
    out = str(pathlib.Path(__file__).resolve().parent / "_tmp_dash_data.pdf")
    try:
        pdfr.render_report(payload, out)
        text = "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(out).pages)
        for ch in _DASH_CHARS:
            assert ch not in text, "a rendered PDF contains a dash drawn from source data"
    finally:
        try:
            pathlib.Path(out).unlink()
        except OSError:
            pass
