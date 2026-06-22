from __future__ import annotations

import json
from unittest.mock import patch

import pytest
import requests

from falconeye.db import get_connection
from falconeye.ingest.urlhaus import _split_tags, ingest, parse_records

_SAMPLE_CSV = """\
# abuse.ch URLhaus Database Dump
# Fetched from the URLhaus API
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
1001,"2026-06-20 10:00:00 UTC","http://evil.ph/malware.exe","online","","malware_download","exe,ph","https://urlhaus.abuse.ch/url/1001/","tester"
1002,"2026-06-21 11:00:00 UTC","http://example.com/bot","offline","2026-06-21 12:00:00 UTC","botnet_cc","","https://urlhaus.abuse.ch/url/1002/","tester"
"""


# --- parse_records ---

def test_parse_records_strips_comments():
    assert len(parse_records(_SAMPLE_CSV)) == 2


def test_parse_records_fields():
    r = parse_records(_SAMPLE_CSV)[0]
    assert r["id"] == "1001"
    assert r["url"] == "http://evil.ph/malware.exe"
    assert r["threat"] == "malware_download"
    assert r["tags"] == "exe,ph"
    assert r["urlhaus_link"] == "https://urlhaus.abuse.ch/url/1001/"


def test_parse_records_empty():
    assert parse_records("") == []
    assert parse_records("# only comments\n") == []


# --- _split_tags ---

def test_split_tags_basic():
    assert _split_tags("exe,ph") == ["exe", "ph"]


def test_split_tags_empty():
    assert _split_tags("") == []


def test_split_tags_strips_whitespace():
    assert _split_tags("win32, trojan") == ["win32", "trojan"]


# --- ingest ---

@pytest.fixture
def db(tmp_path):
    return tmp_path / "test.db"


def test_ingest_upserts_records(db):
    with patch("falconeye.ingest.urlhaus.fetch_csv", return_value=_SAMPLE_CSV):
        upserted, errors = ingest(db)
    assert upserted == 2
    assert errors == 0

    conn = get_connection(db)
    rows = conn.execute(
        "SELECT ioc_value, source_id, threat_type FROM iocs ORDER BY source_id"
    ).fetchall()
    conn.close()

    assert len(rows) == 2
    assert rows[0]["ioc_value"] == "http://evil.ph/malware.exe"
    assert rows[0]["source_id"] == "uh-1001"
    assert rows[0]["threat_type"] == "malware_download"
    assert rows[1]["source_id"] == "uh-1002"


def test_ingest_tags_stored_as_json(db):
    with patch("falconeye.ingest.urlhaus.fetch_csv", return_value=_SAMPLE_CSV):
        ingest(db)
    conn = get_connection(db)
    row = conn.execute("SELECT tags FROM iocs WHERE source_id='uh-1001'").fetchone()
    conn.close()
    assert json.loads(row["tags"]) == ["exe", "ph"]


def test_ingest_empty_tags_stored_as_empty_list(db):
    with patch("falconeye.ingest.urlhaus.fetch_csv", return_value=_SAMPLE_CSV):
        ingest(db)
    conn = get_connection(db)
    row = conn.execute("SELECT tags FROM iocs WHERE source_id='uh-1002'").fetchone()
    conn.close()
    assert json.loads(row["tags"]) == []


def test_ingest_idempotent(db):
    with patch("falconeye.ingest.urlhaus.fetch_csv", return_value=_SAMPLE_CSV):
        ingest(db)
        ingest(db)
    conn = get_connection(db)
    count = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    conn.close()
    assert count == 2  # no duplicates across two runs


def test_ingest_handles_fetch_error(db):
    with patch(
        "falconeye.ingest.urlhaus.fetch_csv",
        side_effect=requests.RequestException("timeout"),
    ):
        upserted, errors = ingest(db)
    assert upserted == 0
    assert errors == 0


def test_ingest_handles_html_error_page(db):
    with patch(
        "falconeye.ingest.urlhaus.fetch_csv",
        side_effect=ValueError("URLhaus returned unexpected HTML"),
    ):
        upserted, errors = ingest(db)
    assert upserted == 0
    assert errors == 0


def test_ingest_skips_row_missing_url(db):
    csv_missing_url = (
        "# comment\n"
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        '1003,"2026-06-22 00:00:00 UTC","","online","","malware_download","",'
        '"https://urlhaus.abuse.ch/url/1003/","tester"\n'
    )
    with patch("falconeye.ingest.urlhaus.fetch_csv", return_value=csv_missing_url):
        upserted, errors = ingest(db)
    assert upserted == 0
    assert errors == 1
