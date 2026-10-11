"""PDF golden test: a rendered report has the required sections, no em dash,
an embedded font, and a sane page count."""
import time

import pytest

from app.pdf import report as pdfr

try:
    import pypdf
    _HAVE_PYPDF = True
except Exception:  # noqa: BLE001
    _HAVE_PYPDF = False


def _asm_payload():
    return {"kind": "asm", "title": "example.com", "generated_ts": time.time(),
            "mode": "On-demand", "engagement": "", "incomplete": True,
            "source_status": [{"source": "crt.sh", "role": "CT", "status": "failed"},
                              {"source": "Mnemonic", "role": "pDNS", "status": "answered"}],
            "severity_counts": {"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 0},
            "summary_line": "A short summary line.",
            "findings": [{"severity": "critical", "kind": "takeover", "title": "Takeover",
                          "host": "a.example.com", "detail": "evidence text"}],
            "hosts": [{"host": "a.example.com", "kind": "own",
                       "resolved_ips": ["192.0.2.1", "198.51.100.7"],
                       "ports": [443], "server": "nginx", "tls": None}],
            "posture": {"spf": True, "dmarc": True, "dmarc_policy": "reject", "mta_sts": True, "tls_rpt": True},
            "references_note": "none", "methodology": "Methodology text.",
            "attribution": ["Source: RIPEstat (RIPE NCC)."]}


def test_pdf_is_valid_and_embeds_the_font(tmp_path):
    out = str(tmp_path / "r.pdf")
    pdfr.render_report(_asm_payload(), out)
    raw = open(out, "rb").read()
    assert raw[:5] == b"%PDF-"
    assert b"%%EOF" in raw[-1024:]
    assert b"DejaVu" in raw, "the DejaVu font must be embedded"


@pytest.mark.skipif(not _HAVE_PYPDF, reason="pypdf not installed")
def test_pdf_sections_present_and_no_em_dash(tmp_path):
    out = str(tmp_path / "r.pdf")
    pdfr.render_report(_asm_payload(), out)
    reader = pypdf.PdfReader(out)
    assert 1 <= len(reader.pages) <= 20
    text = "\n".join(p.extract_text() or "" for p in reader.pages)
    for heading in ("Executive summary", "Findings", "Hosts", "Source status",
                    "Methodology", "Sources and attribution"):
        assert heading in text, f"missing section: {heading}"
    assert "INCOMPLETE" in text  # the incomplete banner is rendered
    assert "—" not in text and "–" not in text, "no em or en dash in the PDF text"


@pytest.mark.skipif(not _HAVE_PYPDF, reason="pypdf not installed")
def test_watermark_does_not_overlap_and_ips_are_intact(tmp_path):
    out = str(tmp_path / "wm.pdf")
    pdfr.render_report(_asm_payload(), out)
    text = "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(out).pages)
    # The watermark is a single string, not letter-spaced across the page: its
    # subject must never appear spaced out character by character.
    spaced = " ".join("example.com")
    assert spaced not in text, "the watermark is letter-spaced and overlaps the text layer"
    # Every address appears intact, never wrapped mid-value.
    for ip in ("192.0.2.1", "198.51.100.7"):
        assert ip in text, f"IP {ip} is not intact in the PDF text"


@pytest.mark.skipif(not _HAVE_PYPDF, reason="pypdf not installed")
def test_hunt_pdf_renders_candidates(tmp_path):
    payload = {"kind": "hunt", "title": "philhealth", "legit_domain": "philhealth.gov.ph",
               "generated_ts": time.time(), "mode": "Public", "incomplete": False, "nrd_off": True,
               "source_status": [{"source": "crt.sh", "role": "CT", "status": "answered"}],
               "severity_counts": {"likely phishing": 1, "suspicious": 0, "parked": 0,
                                   "unknown": 0, "unrelated": 0},
               "pipeline": {"generated": 80, "resolved": 12, "fetched": 10, "not_fetched": 2,
                            "not_registered": 68, "keyword_hits": 1},
               "summary_line": "candidates", "candidates": [
                   {"domain": "philhealth-refund.ph", "verdict": "likely phishing", "score": 90,
                    "source": "crt.sh", "age_days": 3, "registered": "2026-10-08",
                    "evidence": ["fresh cert", "login form"]}],
               "methodology": "method", "attribution": ["crt.sh"]}
    out = str(tmp_path / "h.pdf")
    pdfr.render_report(payload, out)
    text = "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(out).pages)
    assert "philhealth-refund.ph" in text
    assert "Lookalike candidates" in text
    assert "Not registered" in text  # the pipeline summary block
    assert "Not fetched" in text
