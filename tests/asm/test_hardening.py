"""v3.37.1 hardening: ASM_SIGNING_KEY required, and the cap/queue are DB-backed.

The concurrency cap and the queue must hold across all gunicorn workers, so they
are enforced through the shared scan table, not per-process state. These tests
exercise the shared primitive directly.
"""
import pytest
from fastapi.testclient import TestClient

from app import config, main
from app.asm import jobs, signing, store


# ---------------------------------------------------------- signing key gate ----

def test_signing_configured_tracks_the_env(monkeypatch):
    monkeypatch.setenv("ASM_SIGNING_KEY", "something")
    assert signing.configured() is True
    monkeypatch.delenv("ASM_SIGNING_KEY", raising=False)
    assert signing.configured() is False


def test_no_per_process_key_fallback(monkeypatch):
    monkeypatch.delenv("ASM_SIGNING_KEY", raising=False)
    # There is no ephemeral fallback: signing refuses rather than minting a key.
    with pytest.raises(RuntimeError):
        signing.sign({"x": 1}, signing.GRANT_SALT)


def test_asm_endpoints_are_503_without_a_signing_key(monkeypatch):
    monkeypatch.delenv("ASM_SIGNING_KEY", raising=False)
    c = TestClient(main.app, base_url="https://testserver", client=("203.0.113.9", 4000))
    r = c.post("/api/asm/verify/start", json={"domain": "example.com", "method": "dns"})
    assert r.status_code == 503
    r = c.get("/asm/confirm", params={"t": "x"})
    assert r.status_code == 503


# ------------------------------------------------- DB-backed cap and queue ----

def test_claim_slot_enforces_the_global_cap():
    maxc = config.ASM_MAX_CONCURRENT_SCANS
    slack = jobs._slack()
    # Fill every slot.
    for i in range(maxc):
        store.create_scan(f"run{i}", "a.test", "on_demand", grant_id="g")
        assert store.claim_scan_slot(f"run{i}", maxc, slack) is True
    assert store.count_running_scans(slack) == maxc

    # One more queued scan cannot claim a slot while the cap is full.
    store.create_scan("waiting", "a.test", "on_demand", grant_id="g")
    assert store.claim_scan_slot("waiting", maxc, slack) is False

    # Freeing a slot lets it through. This is the same table every worker reads,
    # so the cap is global rather than per worker.
    store.finish_scan("run0", {"domain": "a.test"})
    assert store.count_running_scans(slack) == maxc - 1
    assert store.claim_scan_slot("waiting", maxc, slack) is True


def test_can_accept_is_false_when_cap_plus_queue_is_full():
    maxc = config.ASM_MAX_CONCURRENT_SCANS
    qmax = config.ASM_SCAN_QUEUE_MAX
    slack = jobs._slack()
    for i in range(maxc):
        store.create_scan(f"r{i}", "a.test", "on_demand", grant_id="g")
        store.claim_scan_slot(f"r{i}", maxc, slack)
    for i in range(qmax):
        store.create_scan(f"q{i}", "a.test", "on_demand", grant_id="g")  # stays queued
    assert jobs.capacity()["active"] == maxc
    assert jobs.capacity()["queued"] == qmax
    assert jobs.can_accept() is False
