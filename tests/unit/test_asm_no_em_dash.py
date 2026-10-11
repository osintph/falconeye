"""No em dashes (or en dashes, or their HTML entities) anywhere in ASM.

The brief for Attack Surface Management forbids em dashes in code, UI copy, docs
and exports. This guard fails if one appears in any ASM Python module, in the
ASM tab markup, or in the ASM frontend code. It is deliberately general: it does
not look for one known string, it rejects the character class wherever ASM
authors text.
"""
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]

# U+2014 em dash, U+2013 en dash, and the HTML entities that render as them.
_DASH_CHARS = ("—", "–")
_DASH_ENTITIES = ("&mdash;", "&ndash;", "&#8212;", "&#8211;")


def _asm_python_files():
    files = sorted((REPO / "app" / "asm").rglob("*.py"))
    files += sorted((REPO / "app" / "pdf").rglob("*.py"))
    files += sorted((REPO / "app" / "hunt").rglob("*.py"))
    files.append(REPO / "app" / "routers" / "asm.py")
    files.append(REPO / "app" / "routers" / "hunt.py")
    return files


@pytest.mark.parametrize("path", _asm_python_files(), ids=lambda p: str(p.relative_to(REPO)))
def test_no_em_dash_in_asm_python(path):
    text = path.read_text(encoding="utf-8")
    for ch in _DASH_CHARS:
        assert ch not in text, f"{path} contains an em/en dash ({ch!r})"


def _region(path, start, end):
    text = path.read_text(encoding="utf-8")
    i, j = text.find(start), text.find(end)
    assert i != -1 and j != -1 and j > i, f"ASM region markers not found in {path.name}"
    return text[i:j]


def test_no_em_dash_in_asm_tab_markup():
    region = _region(REPO / "app" / "static" / "index.html",
                     "<!--ASM_TAB_START-->", "<!--ASM_TAB_END-->")
    for needle in _DASH_CHARS + _DASH_ENTITIES:
        assert needle not in region, f"the ASM tab markup contains {needle!r}"


def test_no_em_dash_in_asm_frontend_code():
    region = _region(REPO / "app" / "static" / "app.js",
                     "// ===ASM_START===", "// ===ASM_END===")
    for needle in _DASH_CHARS + _DASH_ENTITIES:
        assert needle not in region, f"the ASM frontend code contains {needle!r}"


def test_no_em_dash_in_hunt_tab_markup():
    region = _region(REPO / "app" / "static" / "index.html",
                     "<!--HUNT_TAB_START-->", "<!--HUNT_TAB_END-->")
    for needle in _DASH_CHARS + _DASH_ENTITIES:
        assert needle not in region, f"the Hunt tab markup contains {needle!r}"


def test_no_em_dash_in_hunt_frontend_code():
    region = _region(REPO / "app" / "static" / "app.js",
                     "// ===HUNT_START===", "// ===HUNT_END===")
    for needle in _DASH_CHARS + _DASH_ENTITIES:
        assert needle not in region, f"the Hunt frontend code contains {needle!r}"


def test_no_em_dash_in_a_rendered_pdf():
    # The brief extends the em-dash rule to the PDFs themselves.
    try:
        import pypdf
    except Exception:  # noqa: BLE001
        import pytest
        pytest.skip("pypdf not installed")
    import time
    from app.pdf import report as pdfr
    payload = {"kind": "asm", "title": "example.com", "generated_ts": time.time(),
               "mode": "On-demand", "incomplete": False, "source_status": [],
               "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
               "summary_line": "s", "findings": [], "hosts": [], "posture": {},
               "methodology": "m", "attribution": ["a"]}
    out = str(pathlib.Path(__file__).resolve().parent / "_tmp_dash.pdf")
    try:
        pdfr.render_report(payload, out)
        text = "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(out).pages)
        for ch in _DASH_CHARS:
            assert ch not in text, "a rendered PDF contains an em or en dash"
    finally:
        try:
            pathlib.Path(out).unlink()
        except OSError:
            pass
