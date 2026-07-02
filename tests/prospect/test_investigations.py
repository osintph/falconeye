"""
Tests for write_investigation().
SQLite and filesystem IO are mocked to keep tests fast and isolated.
Uses conftest.py FALCONEYE_DB=/tmp/falconeye_test.db.
"""
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, call, patch

# DB path used by the module (must match conftest.py)
_TEST_DB = "/tmp/falconeye_test.db"


def _run_write(**kwargs):
    """Call write_investigation with sensible defaults and return (investigation_id, conn_mock, written_json)."""
    defaults = dict(
        domain="stripe.com",
        generated_at="2026-01-01T00:00:00+00:00",
        dossier={"domain": "stripe.com", "sections": {}, "errors": []},
        client_ip="1.2.3.4",
    )
    defaults.update(kwargs)

    written = []

    def fake_write_text(content, encoding=None):
        written.append(content)

    mock_path_instance = MagicMock()
    mock_path_instance.write_text = fake_write_text
    mock_path_instance.__truediv__ = lambda self, other: mock_path_instance

    conn_mock = MagicMock(spec=sqlite3.Connection)

    with patch("app.prospect.investigations._PROSPECT_DIR") as mock_dir, \
         patch("app.prospect.investigations._DATA_DIR") as mock_data_dir, \
         patch("sqlite3.connect", return_value=conn_mock):
        mock_dir.mkdir = MagicMock()
        mock_data_dir.__truediv__ = lambda self, other: mock_path_instance

        from app.prospect.investigations import write_investigation
        inv_id = write_investigation(**defaults)

    return inv_id, conn_mock, written


def test_write_investigation_returns_uuid():
    inv_id, _, _ = _run_write()
    import re
    assert re.match(r"^[0-9a-f-]{36}$", inv_id), f"Expected UUID4 format, got: {inv_id}"


def test_write_investigation_ip_is_hashed():
    """The raw client IP must never appear in the DB row; only its SHA-256 hash."""
    client_ip = "192.168.1.1"
    expected_hash = hashlib.sha256(client_ip.encode()).hexdigest()

    _, conn_mock, _ = _run_write(client_ip=client_ip)

    conn_mock.execute.assert_called_once()
    call_args = conn_mock.execute.call_args[0]
    row = call_args[1]  # positional tuple passed to execute
    # ip_hash is the last element
    assert row[-1] == expected_hash
    # raw IP not present anywhere in the row
    assert client_ip not in str(row)


def test_write_investigation_dossier_json_written():
    """The full dossier dict is serialised to JSON and written to disk."""
    dossier = {"domain": "test.com", "sections": {"about_domain": {"title": "Test"}}, "errors": []}
    _, _, written = _run_write(dossier=dossier)

    assert len(written) == 1
    parsed = json.loads(written[0])
    assert parsed == dossier


def test_write_investigation_db_row_contains_correct_fields():
    """The SQLite INSERT includes investigation_id, domain, generated_at, rel_path, ip_hash."""
    inv_id, conn_mock, _ = _run_write(
        domain="example.com",
        generated_at="2026-06-01T12:00:00+00:00",
        client_ip="10.0.0.1",
    )
    conn_mock.execute.assert_called_once()
    row = conn_mock.execute.call_args[0][1]
    assert row[0] == inv_id                         # investigation_id
    assert row[1] == "example.com"                 # domain
    assert row[2] == "2026-06-01T12:00:00+00:00"  # generated_at
    assert row[3].startswith("prospect/")          # relative path
    assert row[3].endswith(".json")
    expected_hash = hashlib.sha256(b"10.0.0.1").hexdigest()
    assert row[4] == expected_hash                 # ip_hash


def test_write_investigation_silently_survives_db_error():
    """A DB write failure must not raise; the function returns the UUID."""
    conn_mock = MagicMock(spec=sqlite3.Connection)
    conn_mock.execute.side_effect = sqlite3.OperationalError("disk full")

    written = []

    def fake_write_text(content, encoding=None):
        written.append(content)

    mock_path_instance = MagicMock()
    mock_path_instance.write_text = fake_write_text
    mock_path_instance.__truediv__ = lambda self, other: mock_path_instance

    with patch("app.prospect.investigations._PROSPECT_DIR") as mock_dir, \
         patch("app.prospect.investigations._DATA_DIR") as mock_data_dir, \
         patch("sqlite3.connect", return_value=conn_mock):
        mock_dir.mkdir = MagicMock()
        mock_data_dir.__truediv__ = lambda self, other: mock_path_instance

        from app.prospect.investigations import write_investigation
        inv_id = write_investigation(
            domain="crash.com",
            generated_at="2026-01-01T00:00:00+00:00",
            dossier={},
            client_ip="1.1.1.1",
        )

    # JSON was written before the DB error
    assert len(written) == 1
    # UUID returned despite DB failure
    import re
    assert re.match(r"^[0-9a-f-]{36}$", inv_id)


def test_write_investigation_silently_survives_io_error():
    """A filesystem write failure must not raise; returns UUID without a DB row."""
    conn_mock = MagicMock(spec=sqlite3.Connection)

    mock_path_instance = MagicMock()
    mock_path_instance.write_text = MagicMock(side_effect=OSError("no space"))
    mock_path_instance.__truediv__ = lambda self, other: mock_path_instance

    with patch("app.prospect.investigations._PROSPECT_DIR") as mock_dir, \
         patch("app.prospect.investigations._DATA_DIR") as mock_data_dir, \
         patch("sqlite3.connect", return_value=conn_mock):
        mock_dir.mkdir = MagicMock()
        mock_data_dir.__truediv__ = lambda self, other: mock_path_instance

        from app.prospect.investigations import write_investigation
        inv_id = write_investigation(
            domain="nospace.com",
            generated_at="2026-01-01T00:00:00+00:00",
            dossier={},
            client_ip="2.2.2.2",
        )

    # DB must NOT be written when file IO failed
    conn_mock.execute.assert_not_called()
    import re
    assert re.match(r"^[0-9a-f-]{36}$", inv_id)
