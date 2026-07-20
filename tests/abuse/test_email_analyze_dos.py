"""M-2 (v3.12.0): /api/email-header/analyze must not be DoS-able by a deeply
nested multipart message. A crafted nested multipart (~85 bytes/level, so depth
~2000 fits the 200KB header cap) overflows Python's recursion limit during parse.
Before the fix that was an unhandled RecursionError -> HTTP 500; now it is a clean
400, and a depth/part-count cap rejects excessive structures that parse without
overflowing. Legitimate multipart email still analyzes normally.

analyze() is exercised directly (as in test_email_privacy) with a minimal fake
request; the SQLite path comes from the abuse conftest's FALCONEYE_DB.
"""
import asyncio

import pytest
from fastapi import HTTPException

from app.routers import email_header as eh


class _Req:
    headers: dict = {}
    client = None


def _nested_multipart(depth: int) -> str:
    """A `depth`-level nested multipart/mixed message."""
    msg = "This is the innermost body.\n"
    for i in range(depth):
        b = f"BND{i}"
        msg = (
            f'Content-Type: multipart/mixed; boundary="{b}"\n\n'
            f"--{b}\n{msg}\n--{b}--\n"
        )
    return "From: a@b.example\nSubject: t\n" + msg


def test_deeply_nested_multipart_returns_400_not_500():
    raw = _nested_multipart(1500)  # > recursion limit, < 200KB header cap
    assert len(raw) < 200000, "payload must fit the header cap to exercise the parse path"
    req = eh.HeaderAnalyzeRequest(raw_header=raw, raw_body="")
    with pytest.raises(HTTPException) as ei:
        asyncio.run(eh.analyze(req, _Req()))
    assert ei.value.status_code == 400  # clean 400, not an unhandled 500


def test_nested_multipart_rejected_by_depth_cap():
    # A depth that parses without overflowing but exceeds MAX_MIME_DEPTH -> 400.
    raw = _nested_multipart(eh.MAX_MIME_DEPTH + 25)
    req = eh.HeaderAnalyzeRequest(raw_header=raw, raw_body="")
    with pytest.raises(HTTPException) as ei:
        asyncio.run(eh.analyze(req, _Req()))
    assert ei.value.status_code == 400


def test_mime_within_limits_accepts_normal_and_rejects_excess():
    from email import message_from_string
    normal = message_from_string(
        'Content-Type: multipart/alternative; boundary="X"\n\n'
        "--X\nContent-Type: text/plain\n\nhi\n--X\n"
        "Content-Type: text/html\n\n<p>hi</p>\n--X--\n"
    )
    assert eh._mime_within_limits(normal) is True
    deep = message_from_string(_nested_multipart(eh.MAX_MIME_DEPTH + 5).split("\n", 2)[2])
    assert eh._mime_within_limits(deep) is False


def test_normal_multipart_email_still_analyzes(monkeypatch):
    async def _spf(domain):
        return {"found": False, "record": None}

    async def _dmarc(domain):
        return {"found": False, "record": None, "policy": None}

    monkeypatch.setattr(eh, "_lookup_spf", _spf)
    monkeypatch.setattr(eh, "_lookup_dmarc", _dmarc)

    raw = (
        "From: sender@example.com\r\n"
        "To: victim@example.com\r\n"
        "Subject: Legit multipart\r\n"
        "Date: Mon, 20 Jul 2026 00:00:00 +0000\r\n"
        'Content-Type: multipart/alternative; boundary="XYZ"\r\n'
        "\r\n"
        "--XYZ\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "Hello, this is a normal message.\r\n"
        "--XYZ\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<p>Hello, this is a normal message.</p>\r\n"
        "--XYZ--\r\n"
    )
    req = eh.HeaderAnalyzeRequest(raw_header=raw, raw_body="")
    result = asyncio.run(eh.analyze(req, _Req()))
    assert result["subject"] == "Legit multipart"
    assert result["from"][0]["email"] == "sender@example.com"
