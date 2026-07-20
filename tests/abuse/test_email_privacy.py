"""
Privacy lock (v3.8.3): the Email Header tab promises the raw email is "never
written to disk" — only the derived analysis is cached. Since the abuse report
body now flows CLIENT-SIDE, analyze()'s response/cache must still contain no raw
body content. This test fails loudly if a future change starts leaking the body
into the parsed/cached object.
"""
import asyncio
import json
import sqlite3

from app.routers import email_header as eh
from app.abuse import store

# A benign body marker that matches no scam pattern and is not a URL, so it could
# only appear in the output if the RAW body were retained.
BODY_MARKER = "UNIQUEBODYMARKER_zzq9_lorem_ipsum_dolor_home_address_line"
RAW_BODY = f"{BODY_MARKER} sit amet consectetur adipiscing elit sed do eiusmod."
RAW_HEADER = (
    "From: scammer@evil.example\r\n"
    "To: victim@example.com\r\n"
    "Subject: Prize\r\n"
    "Message-ID: <m1@evil.example>\r\n"
    "Date: Mon, 20 Jul 2026 00:00:00 +0000\r\n"
)


class _Req:
    headers: dict = {}
    client = None


def _run_analyze(monkeypatch):
    async def _spf(domain):
        return {"found": False, "record": None}

    async def _dmarc(domain):
        return {"found": False, "record": None, "policy": None}

    monkeypatch.setattr(eh, "_lookup_spf", _spf)
    monkeypatch.setattr(eh, "_lookup_dmarc", _dmarc)
    # no public Received hops in the fixture, so _enrich_ip isn't called; no
    # DKIM-Signature, so no selector lookup; ANTHROPIC key is unset, so no LLM.
    req = eh.HeaderAnalyzeRequest(raw_header=RAW_HEADER, raw_body=RAW_BODY)
    return asyncio.run(eh.analyze(req, _Req()))


def test_analyze_response_has_no_raw_body(monkeypatch):
    result = _run_analyze(monkeypatch)
    blob = json.dumps(result)
    # derived analysis is present (proves it ran)...
    assert result["message_id"] == "<m1@evil.example>"
    assert result["subject"] == "Prize"
    # ...but the raw body is NOT anywhere in the response
    assert BODY_MARKER not in blob


def test_email_cache_stores_no_raw_body(monkeypatch):
    _run_analyze(monkeypatch)
    conn = sqlite3.connect(store._db_path())
    rows = conn.execute("SELECT response_json FROM email_header_cache").fetchall()
    conn.close()
    assert rows, "expected the analysis to be cached"
    assert all(BODY_MARKER not in r[0] for r in rows)
