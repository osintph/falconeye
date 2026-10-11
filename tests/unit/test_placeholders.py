"""Input placeholders and examples must use RFC 2606 reserved names, never a real
brand, agency or company. A placeholder like "philhealth" leaks a real agency into
the greyed example text; this guard fails if one reappears."""
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[2]
INDEX = REPO / "app" / "static" / "index.html"

# Real brands, agencies and companies that must not appear in example text.
_REAL_NAMES = ("mmda", "philhealth", "gcash", "maya", "landbank", "metrobank",
               "pag-ibig", "pagibig", "gsis", "philsys", "stripe", "acme",
               " sss", " bir", " lto", " dfa", " bdo", " bpi")

# The Hunt and ASM input placeholders must be exactly these reserved examples.
_EXPECTED = {
    "hunt-keyword": "e.g. examplebrand",
    "hunt-legit": "e.g. example.com",
    "asm-input": "e.g. example.com",
}


def _placeholders():
    html = INDEX.read_text(encoding="utf-8")
    return re.findall(r'id="([^"]+)"[^>]*placeholder="([^"]*)"', html) + \
        re.findall(r'placeholder="([^"]*)"[^>]*id="([^"]+)"', html)


def test_hunt_and_asm_placeholders_use_reserved_names():
    html = INDEX.read_text(encoding="utf-8")
    for el_id, expected in _EXPECTED.items():
        m = re.search(r'id="' + re.escape(el_id) + r'"[^>]*placeholder="([^"]*)"', html)
        assert m, f"input {el_id} not found"
        assert m.group(1) == expected, f"{el_id} placeholder is {m.group(1)!r}, expected {expected!r}"


def test_no_placeholder_names_a_real_brand():
    for a, b in _placeholders():
        text = (a + " " + b).lower()
        for name in _REAL_NAMES:
            assert name not in text, f"a placeholder names a real brand: {name!r} in {b or a!r}"
