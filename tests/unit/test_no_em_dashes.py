"""Guard: no literal em dash (U+2014) in our code, templates, UI strings or docs.

The two text normalisers (app/routers/sockpuppet.py and app/static/app.js) are
allowed to reference the character, but they do so with the "\\u2014" escape, not a
literal, so they pass this check without a special case. Vendored third-party data
under app/data/ is input, not our generated output, so it is excluded.
"""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
EM_DASH = "—"
EXTS = {".py", ".js", ".css", ".html", ".md", ".txt", ".json"}
# Prefixes (repo-relative, posix) that are not our generated output / templates /
# UI strings / docs: vendored data and environment directories.
SKIP_PREFIXES = ("app/data/", "node_modules/", ".venv", ".git/")


def _offenders():
    bad = []
    for base in ("app", "docs"):
        root = ROOT / base
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file() or p.suffix not in EXTS:
                continue
            rel = p.relative_to(ROOT).as_posix()
            if any(rel.startswith(s) for s in SKIP_PREFIXES):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:  # noqa: BLE001
                continue
            n = text.count(EM_DASH)
            if n:
                bad.append(f"{rel} x{n}")
    return bad


def test_no_literal_em_dashes_in_output_or_docs():
    bad = _offenders()
    assert not bad, ("literal em dash (U+2014) must not appear in code, templates, UI "
                     "strings or docs; found in: " + ", ".join(bad))
