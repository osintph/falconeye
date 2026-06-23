from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import jwt
import pytest

from falconeye.config import ConfigError, get_digest_mode
from falconeye.db import get_connection, init_db
from falconeye.digest import GhostClient, _build_digest_html, run_digest


# ---------------------------------------------------------------------------
# GhostClient — JWT generation
# ---------------------------------------------------------------------------

def _make_client(api_url="https://blog.example.com",
                 key="deadbeef:0102030405060708090a0b0c0d0e0f10") -> GhostClient:
    return GhostClient(api_url, key)


def test_ghost_client_jwt_format():
    client = _make_client()
    token = client._jwt()
    # Decode without verification to inspect structure
    decoded = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
    assert "iat" in decoded
    assert "exp" in decoded
    assert decoded["aud"] == "/admin/"


def test_ghost_client_jwt_expiry():
    client = _make_client()
    token = client._jwt()
    decoded = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
    assert decoded["exp"] - decoded["iat"] == 300


def test_ghost_client_jwt_kid_in_header():
    client = _make_client()
    token = client._jwt()
    headers = jwt.get_unverified_header(token)
    assert headers["kid"] == "deadbeef"


def test_ghost_client_headers_include_auth():
    client = _make_client()
    headers = client._headers()
    assert headers["Authorization"].startswith("Ghost ")
    assert "Content-Type" in headers


# ---------------------------------------------------------------------------
# GhostClient — API calls (mocked)
# ---------------------------------------------------------------------------

def _mock_response(status_code: int, body: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        import requests
        resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
    return resp


def test_find_post_by_slug_found():
    client = _make_client()
    post = {"id": "abc", "slug": "test-slug", "updated_at": "2026-06-23T00:00:00Z"}
    with patch("falconeye.digest.requests.get",
               return_value=_mock_response(200, {"posts": [post]})):
        result = client.find_post_by_slug("test-slug")
    assert result == post


def test_find_post_by_slug_not_found():
    client = _make_client()
    with patch("falconeye.digest.requests.get",
               return_value=_mock_response(200, {"posts": []})):
        result = client.find_post_by_slug("missing-slug")
    assert result is None


def test_create_post_sends_correct_payload():
    client = _make_client()
    created = {"id": "new-id", "slug": "test"}
    mock_resp = _mock_response(201, {"posts": [created]})
    mock_resp.raise_for_status = MagicMock()
    with patch("falconeye.digest.requests.post", return_value=mock_resp) as mock_post:
        result = client.create_post(
            "Title", "<p>Body</p>", ["tag1"], "draft", "author"
        )
    assert result == created
    call_json = mock_post.call_args.kwargs["json"]
    post_payload = call_json["posts"][0]
    assert post_payload["title"] == "Title"
    assert post_payload["html"] == "<p>Body</p>"
    assert post_payload["status"] == "draft"


def test_update_post_sends_correct_payload():
    client = _make_client()
    updated = {"id": "abc", "slug": "test"}
    mock_resp = _mock_response(200, {"posts": [updated]})
    mock_resp.raise_for_status = MagicMock()
    with patch("falconeye.digest.requests.put", return_value=mock_resp) as mock_put:
        result = client.update_post("abc", "2026-06-23T00:00:00Z", "<p>New</p>", "draft")
    assert result == updated
    put_json = mock_put.call_args.kwargs["json"]
    assert put_json["posts"][0]["html"] == "<p>New</p>"


# ---------------------------------------------------------------------------
# _build_digest_html
# ---------------------------------------------------------------------------

@pytest.fixture
def digest_db(tmp_path):
    db = tmp_path / "test.db"
    init_db(db)
    conn = get_connection(db)
    conn.execute(
        "INSERT INTO iocs (ioc_type, ioc_value, threat_type, source, source_id, fetched_at) "
        "VALUES ('url', 'http://evil.ph/malware', 'phishing', 'urlhaus', 'u1', '2026-06-22T12:00:00Z')"
    )
    ioc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO sieve_matches (record_type, record_id, match_criterion, matched_value, matched_at) "
        "VALUES ('ioc', ?, 'tld', '.ph', '2026-06-22T12:00:00Z')", (ioc_id,)
    )
    conn.execute(
        "INSERT INTO cves (cve_id, description, cvss_v3_score, cvss_v3_severity, "
        "source, fetched_at) VALUES ('CVE-2024-9999', 'Test CVE', 9.8, 'CRITICAL', "
        "'kev', '2026-06-22T12:00:00Z')"
    )
    cve_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute(
        "INSERT INTO sieve_matches (record_type, record_id, match_criterion, matched_value, matched_at) "
        "VALUES ('cve', ?, 'cpe', 'cpe:2.3:o:cisco:ios', '2026-06-22T12:00:00Z')", (cve_id,)
    )
    conn.commit()
    conn.close()
    return db


def test_build_digest_html_title(digest_db):
    title, excerpt, html = _build_digest_html(digest_db, "2026-06-22")
    assert "2026-06-22" in title
    assert "FalconEye" in title


def test_build_digest_html_excerpt_counts(digest_db):
    title, excerpt, html = _build_digest_html(digest_db, "2026-06-22")
    assert "1 new PH-matched IOCs" in excerpt
    assert "1 new CVE alerts" in excerpt


def test_build_digest_html_contains_ioc(digest_db):
    _, _, html = _build_digest_html(digest_db, "2026-06-22")
    assert "evil.ph" in html


def test_build_digest_html_contains_cve(digest_db):
    _, _, html = _build_digest_html(digest_db, "2026-06-22")
    assert "CVE-2024-9999" in html


def test_build_digest_html_boilerplate(digest_db):
    _, _, html = _build_digest_html(digest_db, "2026-06-22")
    assert "falconeye.osintph.info" in html


def test_build_digest_html_no_data_for_other_day(digest_db):
    title, excerpt, html = _build_digest_html(digest_db, "2026-06-01")
    assert "0 new PH-matched IOCs" in excerpt


# ---------------------------------------------------------------------------
# get_digest_mode default
# ---------------------------------------------------------------------------

def test_get_digest_mode_default(monkeypatch):
    monkeypatch.delenv("FALCONEYE_DIGEST_MODE", raising=False)
    assert get_digest_mode() == "draft"


def test_get_digest_mode_published(monkeypatch):
    monkeypatch.setenv("FALCONEYE_DIGEST_MODE", "published")
    assert get_digest_mode() == "published"


# ---------------------------------------------------------------------------
# run_digest — integration (mocked Ghost)
# ---------------------------------------------------------------------------

def test_run_digest_creates_post_when_none_exists(digest_db, monkeypatch):
    monkeypatch.setenv("GHOST_API_URL", "https://blog.example.com")
    monkeypatch.setenv("GHOST_ADMIN_KEY", "deadbeef:0102030405060708090a0b0c0d0e0f10")
    monkeypatch.setenv("GHOST_AUTHOR_SLUG", "sigmund")
    monkeypatch.setenv("FALCONEYE_DIGEST_MODE", "draft")

    created_post = {"id": "new-id", "slug": "falconeye-digest-2026-06-22"}
    with patch("falconeye.digest.GhostClient.find_post_by_slug", return_value=None), \
         patch("falconeye.digest.GhostClient.create_post", return_value=created_post) as mock_create:
        result = run_digest(digest_db)

    assert result == 0
    mock_create.assert_called_once()
    args = mock_create.call_args
    assert "FalconEye PH Daily Threat Brief" in args.args[0]


def test_run_digest_updates_existing_post(digest_db, monkeypatch):
    monkeypatch.setenv("GHOST_API_URL", "https://blog.example.com")
    monkeypatch.setenv("GHOST_ADMIN_KEY", "deadbeef:0102030405060708090a0b0c0d0e0f10")
    monkeypatch.setenv("GHOST_AUTHOR_SLUG", "sigmund")

    existing = {"id": "abc", "updated_at": "2026-06-22T00:00:00Z"}
    with patch("falconeye.digest.GhostClient.find_post_by_slug", return_value=existing), \
         patch("falconeye.digest.GhostClient.update_post",
               return_value=existing) as mock_update:
        result = run_digest(digest_db)

    assert result == 0
    mock_update.assert_called_once()


def test_run_digest_ghost_api_error_returns_zero(digest_db, monkeypatch):
    monkeypatch.setenv("GHOST_API_URL", "https://blog.example.com")
    monkeypatch.setenv("GHOST_ADMIN_KEY", "deadbeef:0102030405060708090a0b0c0d0e0f10")
    monkeypatch.setenv("GHOST_AUTHOR_SLUG", "sigmund")

    with patch("falconeye.digest.GhostClient.find_post_by_slug",
               side_effect=Exception("network error")):
        result = run_digest(digest_db)

    assert result == 0  # never raises, always returns 0


def test_run_digest_missing_config_returns_zero(digest_db, monkeypatch):
    monkeypatch.delenv("GHOST_API_URL", raising=False)
    monkeypatch.delenv("GHOST_ADMIN_KEY", raising=False)
    monkeypatch.delenv("GHOST_AUTHOR_SLUG", raising=False)

    result = run_digest(digest_db)
    assert result == 0
