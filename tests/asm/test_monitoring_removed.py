"""Monitoring is removed from the public product: unreachable via UI, API and MCP
with the flag off."""
from fastapi.testclient import TestClient

from app import main


def _client():
    return TestClient(main.app, base_url="https://testserver", client=("203.0.113.9", 1))


def test_monitor_endpoint_is_gone():
    r = _client().post("/api/asm/monitor", json={"domain": "example.com", "enabled": True})
    assert r.status_code in (404, 405), "the monitoring endpoint must not exist"


def test_session_view_has_no_monitoring_state():
    out = _client().get("/api/asm/session").json()
    assert "monitoring_enabled" not in out
    assert "monitor" not in out


def test_rotate_and_delete_management_endpoints_are_gone():
    for action in ("rotate", "delete"):
        r = _client().post(f"/api/asm/manage/{action}", json={"domain": "example.com"})
        assert r.status_code in (404, 405), f"/manage/{action} must not exist"


def test_mcp_exposes_no_monitoring_tool():
    from app import mcp_server
    names = " ".join(t.name for t in mcp_server.TOOLS)
    assert "monitor" not in names
