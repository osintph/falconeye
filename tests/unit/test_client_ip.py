"""Unit tests for app.utils.client_ip."""
from typing import Optional
from unittest.mock import MagicMock

import pytest

from app.utils.client_ip import get_client_ip


def _make_request(headers: dict, client_host: Optional[str] = "10.0.0.1") -> MagicMock:
    req = MagicMock()
    req.headers = headers
    if client_host is not None:
        req.client = MagicMock()
        req.client.host = client_host
    else:
        req.client = None
    return req


def test_returns_cf_connecting_ip_when_present():
    req = _make_request({"CF-Connecting-IP": "203.0.113.42"}, client_host="104.16.1.1")
    assert get_client_ip(req) == "203.0.113.42"


def test_falls_back_to_request_client_host_when_header_missing():
    req = _make_request({}, client_host="198.51.100.7")
    assert get_client_ip(req) == "198.51.100.7"


def test_ignores_x_forwarded_for():
    # XFF must NOT be used — only CF-Connecting-IP or client.host
    req = _make_request(
        {"X-Forwarded-For": "1.2.3.4, 5.6.7.8"},
        client_host="198.51.100.7",
    )
    assert get_client_ip(req) == "198.51.100.7"
