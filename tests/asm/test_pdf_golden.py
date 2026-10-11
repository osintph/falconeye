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
def test_hunt_pdf_renders_candidates_campaign_and_long_domain(tmp_path):
    long_domain = "mmda-ncap-lto-violation-fine-portal-xy.sbs"  # 42 chars, must stay intact
    assert len(long_domain) >= 40
    payload = {"kind": "hunt", "title": "mmda", "legit_domain": "mmda.gov.ph",
               "generated_ts": time.time(), "mode": "Public", "incomplete": False, "nrd_off": True,
               "source_status": [{"source": "urlscan.io", "role": "primary", "status": "answered"}],
               "severity_counts": {"likely phishing": 2, "suspicious": 0, "brand-referencing": 1,
                                   "parked": 0, "unknown": 0, "unrelated": 0},
               "pipeline": {"discovered": 120, "considered": 80, "resolved": 12, "fetched": 10,
                            "not_fetched": 2, "wildcard": 6, "taken_down": 1, "irrelevant": 9,
                            "not_registered": 62, "keyword_hits": 5},
               "campaigns": [{"id": 1, "theme": "lto, ncap", "count": 2,
                              "members": ["mmda-ltoncap.net", long_domain],
                              "window": {"first": "2026-08-10", "last": "2026-10-01"},
                              "corroboration": ["registered within 52 days", "cheap-TLD family"],
                              "registrars": ["NameSilo"], "asns": ["AS1 Host"],
                              "tlds": ["net", "sbs"]}],
               "related_groups": [{"theme": "portal", "count": 3,
                                   "members": ["philhealthguide.com", "aboutphilhealth.org",
                                               "philhealthhub.com"],
                                   "window": {"first": "2025-11-07", "last": "2026-10-01"},
                                   "corroboration": [], "registrars": [], "asns": [],
                                   "tlds": ["com", "org"]}],
               "summary_line": "candidates", "candidates": [
                   {"domain": long_domain, "verdict": "likely phishing", "score": 92,
                    "source": "urlscan.io", "age_days": 20, "registered": "2026-09-20",
                    "campaign_id": 1, "urlscan_first_seen": "2026-09-21",
                    "urlscan_result": "https://urlscan.io/result/abc/",
                    "evidence": ["member of a detected campaign cluster"]},
                   {"domain": "mmda-ltoncap.net", "verdict": "likely phishing", "score": 90,
                    "source": "urlscan.io", "age_days": 22, "registered": "2026-09-18",
                    "campaign_id": 1, "evidence": ["cheap, abuse-heavy TLD"]}],
               "methodology": "method", "attribution": ["urlscan.io"]}
    out = str(tmp_path / "h.pdf")
    pdfr.render_report(payload, out)
    text = "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(out).pages)
    assert "Lookalike candidates" in text
    assert "Detected campaigns" in text
    assert "Related brand-themed domains" in text  # uncorroborated group section
    assert "Irrelevant keyword matches" in text and "Possibly taken down" in text
    assert "not determinations" in text  # the Hunt footer disclaimer
    # A 40-plus character domain must render intact (wrapping is fine, truncation
    # is not), so it survives once whitespace from any wrap is removed.
    squashed = "".join(text.split())
    assert long_domain in squashed, "the long domain was truncated or altered"
