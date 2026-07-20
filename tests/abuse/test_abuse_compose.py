"""Tests for report composition (pure function) and the compose endpoint."""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.abuse import compose
from app.abuse import routes as abuse_routes


def _client():
    app = FastAPI()
    app.state.limiter = abuse_routes.limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(abuse_routes.router)
    return TestClient(app)


# ---------- pure compose_report ----------

def test_every_category_renders():
    for cat in compose.VALID_CATEGORIES:
        r = compose.compose_report("1.2.3.4", "ip", cat, "evidence", "2026-07-19T00:00:00Z", "Name", "n@e.com")
        assert r["category"] == cat
        assert r["subject"].startswith("Abuse Report:")
        assert r["reporter_email"] == "n@e.com"
        assert r["warnings"] == []


def test_crlf_in_evidence_stripped_with_warning():
    r = compose.compose_report("1.2.3.4", "ip", "spam", "line1\r\nBcc: evil@x.com", "2026", "N", "n@e.com")
    assert "\r" not in r["body_text"]
    assert any("evidence" in w for w in r["warnings"])


def test_crlf_in_target_no_header_line_survives():
    r = compose.compose_report("1.2.3.4\r\nBCC: evil@attacker.com", "ip", "spam", "e", "2026", "N", "n@e.com")
    # subject is a single line; no injected header line survives in subject or body
    assert "\n" not in r["subject"] and "\r" not in r["subject"]
    for line in r["body_text"].splitlines():
        assert not line.strip().lower().startswith("bcc:")
    assert any("target" in w for w in r["warnings"])


def test_evidence_under_cap_not_truncated():
    # 9000 chars is now under the v3.8.3 cap (20000) — no truncation.
    r = compose.compose_report("x", "ip", "other", "A" * 9000, "2026", "N", "n@e.com")
    assert not any("truncated" in w for w in r["warnings"])
    assert "A" * 9000 in r["body_text"]


def test_unknown_category_becomes_other():
    r = compose.compose_report("x", "ip", "banana", "e", "2026", "N", "n@e.com")
    assert r["category"] == "other"
    assert any("unknown category" in w for w in r["warnings"])


def test_braces_in_evidence_safe():
    r = compose.compose_report("x", "domain", "phishing", 'json {"a": 1}', "2026", "N", "n@e.com")
    assert 'json {"a": 1}' in r["body_text"]


def test_compose_carries_rich_email_evidence():
    """v3.8.3: the client builds rich evidence (real headers, verbatim Received
    chain, body excerpt, URLs); compose must carry it through intact."""
    evidence = (
        "Subject: You have won\n"
        "From: scammer@evil.example\n"
        "Message-ID: <abc123@evil.example>\n"
        "Date: Mon, 20 Jul 2026 00:00:00 +0000\n"
        "Return-Path: bounce@evil.example\n"
        "Authentication-Results: SPF=fail DKIM=none DMARC=fail\n\n"
        "Received chain (verbatim, oldest first):\n"
        "  from mail.evil.example ([203.0.113.9]) by mx.victim.example\n\n"
        "URLs found in the message:\n"
        "  http://evil.example/login\n\n"
        "Attachments referenced (filenames only, content omitted): invoice.exe"
    )
    r = compose.compose_report("evil.example", "domain", "phishing", evidence,
                               "2026-07-20T00:00:00Z", "Reporter", "r@osintph.info")
    body = r["body_text"]
    assert "Message-ID: <abc123@evil.example>" in body
    assert "Subject: You have won" in body
    assert "Received chain (verbatim" in body and "203.0.113.9" in body
    assert "http://evil.example/login" in body
    assert "invoice.exe" in body           # filename present...
    # ...but this is a name-only reference; no attachment content is present
    assert r["warnings"] == []


def test_compose_evidence_cap_raised_for_full_body():
    r = compose.compose_report("x", "ip", "other", "A" * 25000, "2026", "N", "n@e.com")
    assert "A" * 20000 in r["body_text"]
    assert "A" * 20001 not in r["body_text"]
    assert any("truncated" in w for w in r["warnings"])


# ---------- compose endpoint ----------

def test_compose_endpoint_requires_reporter_identity(monkeypatch):
    monkeypatch.delenv("FALCONEYE_REPORTER_NAME", raising=False)
    monkeypatch.delenv("FALCONEYE_REPORTER_EMAIL", raising=False)
    c = _client()
    r = c.post("/api/abuse/compose", json={
        "target": "1.2.3.4", "target_type": "ip", "category": "spam",
        "evidence_text": "x", "observed_at_utc": "",
    })
    assert r.status_code == 503
    assert "FALCONEYE_REPORTER_NAME" in r.json()["detail"]


def test_compose_endpoint_success(monkeypatch):
    monkeypatch.setenv("FALCONEYE_REPORTER_NAME", "Test Reporter")
    monkeypatch.setenv("FALCONEYE_REPORTER_EMAIL", "test@example.com")
    c = _client()
    r = c.post("/api/abuse/compose", json={
        "target": "1.2.3.4", "target_type": "ip", "category": "bruteforce",
        "evidence_text": "SSH brute-force attempts", "observed_at_utc": "2026-07-19T04:22:00Z",
    })
    assert r.status_code == 200
    d = r.json()
    assert d["subject"].startswith("Abuse Report: Brute-Force")
    assert "SSH brute-force attempts" in d["body_text"]
