"""No ASM output for an unverified or blocked domain; the verified path works."""
import pytest
from fastapi.testclient import TestClient

from app import config, main
from app.asm import jobs, store, verify


def _client(ip="203.0.113.11"):
    return TestClient(main.app, base_url="https://testserver", client=(ip, 5000))


def test_scan_refused_without_a_grant():
    r = _client().post("/api/asm/scan", json={"domain": "example.com"})
    assert r.status_code == 403
    body = r.json()
    assert body.get("needs_verification") is True
    assert "hosts" not in body and "findings" not in body


def test_blocked_domain_returns_the_single_message():
    r = _client().post("/api/asm/scan", json={"domain": "gmail.com"})
    assert r.json().get("message") == "This domain cannot be assessed here."
    assert "hosts" not in r.json()


def test_session_reports_unverified_without_a_cookie():
    r = _client().get("/api/asm/session", params={"domain": "example.com"})
    assert r.status_code == 200
    assert r.json().get("verified") is False


def test_export_of_a_foreign_scan_is_404():
    store.create_scan("foreign1", "someoneelse.com", "on_demand", operator=0, grant_id="x")
    store.finish_scan("foreign1", {"domain": "someoneelse.com"})
    r = _client().get("/api/asm/scan/foreign1/export.json")
    assert r.status_code == 404


def test_mcp_discover_is_404_unless_operator_env_is_set():
    r = _client().post("/api/asm/mcp/discover",
                       json={"domain": "example.com", "engagement_reference": "E"})
    assert r.status_code == 404


def test_verified_dns_flow_issues_a_grant_and_accepts_a_scan(monkeypatch):
    monkeypatch.setattr(jobs, "submit", lambda scan_id: True)
    published = {}

    def fake_txt(name):
        return published.get(name, [])
    monkeypatch.setattr(verify, "_txt_values_sync", fake_txt)

    c = _client()
    start = c.post("/api/asm/verify/start", json={"domain": "example.com", "method": "dns"})
    token_value = start.json()["apex_record"]["value"]
    assert token_value.startswith("falconeye-verify=")
    published["example.com"] = [token_value]

    check = c.post("/api/asm/verify/check-dns", json={"domain": "example.com"})
    assert check.json()["verified"] is True

    scan = c.post("/api/asm/scan", json={"domain": "example.com"})
    assert scan.status_code == 200
    assert scan.json()["state"] == "queued" and scan.json()["scan_id"]


def test_a_grant_for_a_subdomain_does_not_authorize_the_parent(monkeypatch):
    monkeypatch.setattr(jobs, "submit", lambda scan_id: True)
    published = {}
    monkeypatch.setattr(verify, "_txt_values_sync", lambda name: published.get(name, []))

    c = _client()
    start = c.post("/api/asm/verify/start", json={"domain": "sub.example.com", "method": "dns"})
    published["sub.example.com"] = [start.json()["apex_record"]["value"]]
    c.post("/api/asm/verify/check-dns", json={"domain": "sub.example.com"})

    # The grant is bound to sub.example.com; scanning the parent is refused.
    r = c.post("/api/asm/scan", json={"domain": "example.com"})
    assert r.status_code == 403
