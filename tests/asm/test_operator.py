"""Operator mode: off without config, key+TOTP, lockout, CIDR, the block override."""
import pyotp
import pytest
from fastapi.testclient import TestClient

from app import main
from app.asm import jobs, operator, store


@pytest.fixture
def op_env(monkeypatch):
    secret = pyotp.random_base32()
    monkeypatch.setenv("ASM_OPERATOR_KEY_HASH", operator.hash_key("super-secret-key"))
    monkeypatch.setenv("ASM_OPERATOR_TOTP_SECRET", secret)
    return secret


@pytest.fixture
def client(monkeypatch):
    # Never let an operator scan actually start a background run in a test.
    monkeypatch.setattr(jobs, "submit", lambda scan_id: True)
    return TestClient(main.app, base_url="https://testserver", client=("203.0.113.9", 4321))


def test_operator_is_off_without_config():
    assert operator.configured() is False


def test_configured_when_both_set(op_env):
    assert operator.configured() is True


def test_credentials_require_both_key_and_code(op_env):
    good = pyotp.TOTP(op_env).now()
    assert operator.verify_credentials("super-secret-key", good) is True
    assert operator.verify_credentials("wrong-key", good) is False
    assert operator.verify_credentials("super-secret-key", "000000") is False


def test_cidr_restriction(monkeypatch):
    monkeypatch.setenv("ASM_OPERATOR_ALLOWED_CIDRS", "100.64.0.0/10")
    assert operator.cidr_ok("100.64.1.2") is True
    assert operator.cidr_ok("203.0.113.9") is False
    # Empty allowlist means any source.
    monkeypatch.setenv("ASM_OPERATOR_ALLOWED_CIDRS", "")
    assert operator.cidr_ok("203.0.113.9") is True


def test_lockout_grows_after_repeated_failures():
    ip = "198.51.100.7"
    for _ in range(operator.FAIL_FREE + 1):
        operator.record_fail(ip)
    assert operator.lockout_remaining(ip) > 0


def test_unlock_route_is_404_when_unconfigured(client):
    r = client.post("/api/asm/operator/unlock", json={"key": "x", "code": "000000"})
    assert r.status_code == 404


def test_unlock_wrong_credentials_fails(client, op_env, monkeypatch):
    monkeypatch.setattr("app.asm.mailer.send_operator_notice", _fake_async)
    r = client.post("/api/asm/operator/unlock", json={"key": "nope", "code": "000000"})
    assert r.status_code == 401


def test_unlock_then_operator_scan_requires_engagement(client, op_env, monkeypatch):
    monkeypatch.setattr("app.asm.mailer.send_operator_notice", _fake_async)
    code = pyotp.TOTP(op_env).now()
    r = client.post("/api/asm/operator/unlock", json={"key": "super-secret-key", "code": code})
    assert r.status_code == 200 and r.json()["unlocked"] is True
    # No engagement reference -> refused.
    r = client.post("/api/asm/scan", json={"domain": "client-under-test.ph"})
    assert r.status_code == 400
    # With an engagement reference and a non-blocked domain -> accepted (queued).
    r = client.post("/api/asm/scan", json={"domain": "client-under-test.ph", "engagement": "ENG-1"})
    assert r.status_code == 200 and r.json()["state"] == "queued"


def test_blocked_domain_needs_retype_confirmation(client, op_env, monkeypatch):
    monkeypatch.setattr("app.asm.mailer.send_operator_notice", _fake_async)
    code = pyotp.TOTP(op_env).now()
    client.post("/api/asm/operator/unlock", json={"key": "super-secret-key", "code": code})
    # github.io is a platform apex: overridable, but only after a retype.
    r = client.post("/api/asm/scan", json={"domain": "github.io", "engagement": "ENG-2"})
    assert r.status_code == 409 and r.json()["needs_confirmation"] is True
    r = client.post("/api/asm/scan", json={"domain": "github.io", "engagement": "ENG-2",
                                           "confirm_domain": "github.io"})
    assert r.status_code == 200


def test_public_suffix_refused_even_in_operator_mode(client, op_env, monkeypatch):
    monkeypatch.setattr("app.asm.mailer.send_operator_notice", _fake_async)
    code = pyotp.TOTP(op_env).now()
    client.post("/api/asm/operator/unlock", json={"key": "super-secret-key", "code": code})
    r = client.post("/api/asm/scan", json={"domain": "com.ph", "engagement": "ENG-3",
                                           "confirm_domain": "com.ph"})
    assert r.status_code == 400


def test_operator_results_are_not_served_to_a_normal_session(client, op_env):
    # An operator scan, finished.
    store.create_scan("opscan1", "client.ph", "on_demand", operator=1, engagement="ENG-9")
    store.finish_scan("opscan1", {"domain": "client.ph"})
    # A normal session (no operator cookie) must get 404, not the result.
    plain = TestClient(main.app, base_url="https://testserver", client=("203.0.113.50", 9))
    r = plain.get("/api/asm/scan/opscan1")
    assert r.status_code == 404


async def _fake_async(*args, **kwargs):
    return {"sent": True, "error": None}
