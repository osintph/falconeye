"""Monitoring: snapshot and diff logic, and the re-verify-or-pause behaviour."""
import asyncio

import pytest

from app.asm import monitor, report, store, verify


def test_snapshot_and_diff_detect_changes():
    old_hosts = [{"host": "a.test", "resolved_ips": ["192.0.2.1"], "cname": "", "open_ports_json": "[]",
                  "resolved_ips_json": '["192.0.2.1"]', "fingerprint_json": None, "tls_json": None}]
    # report.snapshot takes host views (store.get_hosts shape); build minimal rows.
    old = report.snapshot(_views([("a.test", [80])]), [])
    new = report.snapshot(_views([("a.test", [80, 22]), ("b.test", [443])]),
                          [{"kind": "takeover", "host": "b.test", "title": "Dangling CNAME"}])
    d = report.diff(old, new)
    assert d["changed"] is True
    joined = " ".join(d["lines"])
    assert "New host: b.test" in joined
    assert "new open ports 22" in joined
    assert "New finding on b.test" in joined


def test_diff_against_no_previous_snapshot_is_not_a_change():
    new = report.snapshot(_views([("a.test", [80])]), [])
    assert report.diff(None, new)["changed"] is False


def test_monitor_pauses_and_does_not_scan_when_dns_reverify_fails(monkeypatch):
    store.upsert_domain("drop.test", "verified", verify_method="dns")
    store.set_monitoring("drop.test", True, "weekly", "owner@drop.test")
    store.set_dns_token_hash("drop.test", verify.hash_token("tok"))

    async def no_record(domain, token_hash):
        return False  # the TXT record is gone
    monkeypatch.setattr(verify, "dns_token_present", no_record)

    sent = {}

    async def fake_mail(email, domain, text):
        sent["to"] = email
        return {"sent": True}
    monkeypatch.setattr("app.asm.mailer.send_monitor_diff", fake_mail)

    row = store.get_domain("drop.test")
    outcome = asyncio.run(monitor._run_one(row))
    assert outcome == "paused"
    assert store.get_domain("drop.test")["monitor_paused"] == 1
    assert sent.get("to") == "owner@drop.test"


def test_disabled_monitoring_runs_nothing(monkeypatch):
    monkeypatch.setattr("app.config.ASM_MONITORING_ENABLED", False)
    assert asyncio.run(monitor.run_due())["enabled"] is False


def _views(items):
    """Build host rows in the shape report.snapshot consumes (get_hosts output)."""
    out = []
    for host, ports in items:
        out.append({
            "host": host, "is_reference": 0, "cdn": "",
            "resolved_ips": [], "resolved_ips_json": "[]", "cname": "",
            "open_ports": [{"port": p} for p in ports],
            "open_ports_json": "[]", "http": None, "http_json": None,
            "tls": None, "tls_json": None, "fingerprint": None, "fingerprint_json": None,
        })
    return out
