"""v3.39.0: run records keep no plain text, revoke deletes everything, and the
3.39.0 release action converts what earlier versions stored.

Before v3.39.0:
  - asm_scans kept the Attack Surface domain, or the Hunt keyword and legitimate
    domain, in plain text forever, and asm_scan_audit kept an unsalted, truncated
    SHA-256 of the domain or keyword: a dictionary lookup for a brand keyword.
  - revoking a grant only stamped revoked_at; delete_domain() had no callers.
"""
import asyncio
import hashlib
import os
import sqlite3
import sys

import pytest

from app import config
from app.asm import jobs, mailer, store, verify
from app.utils import fehash

KEY = "test-fe-hash-key-not-a-secret"


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setattr(config, "FE_HASH_KEY", KEY)


def _rows(sql, params=()):
    conn = store._connect()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def _exec(sql, params=()):
    conn = store._connect()
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


# ---------- the HMAC ----------

def test_hmac_is_keyed_prefixed_normalised_and_idempotent(monkeypatch):
    a = fehash.hmac_value("Example.COM ")
    assert a.startswith("h1:") and len(a) == 3 + 64
    assert a == fehash.hmac_value("example.com")
    assert fehash.hmac_value(a) == a
    assert fehash.hmac_value("") == ""
    assert "example" not in a
    monkeypatch.setattr(config, "FE_HASH_KEY", "another-key")
    assert fehash.hmac_value("example.com") != a, "the hash does not depend on FE_HASH_KEY"


# ---------- run rows ----------

def test_a_finished_asm_run_keeps_only_the_hmac_of_its_domain():
    store.create_scan("s-asm", "example.com", "on_demand", operator=1, engagement="ENG-42")
    store.finish_scan("s-asm", {})
    (row,) = _rows("SELECT domain, engagement FROM asm_scans WHERE scan_id = 's-asm'")
    assert row["domain"] == fehash.hmac_value("example.com")
    assert row["engagement"] == "ENG-42", "an ASM engagement reference is the operator's own label"


def test_a_finished_hunt_hashes_keyword_and_legitimate_domain():
    store.create_scan("s-hunt", "gcash", "Public", kind="hunt", engagement="gcash.com")
    store.finish_scan("s-hunt", {})
    (row,) = _rows("SELECT domain, engagement FROM asm_scans WHERE scan_id = 's-hunt'")
    assert row["domain"] == fehash.hmac_value("gcash")
    assert row["engagement"] == fehash.hmac_value("gcash.com")


def test_a_failed_run_is_redacted_too():
    store.create_scan("s-err", "example.org", "on_demand")
    store.fail_scan("s-err", "boom")
    (row,) = _rows("SELECT domain FROM asm_scans WHERE scan_id = 's-err'")
    assert fehash.is_hashed(row["domain"])


def test_the_sweep_redacts_a_run_that_never_finished():
    store.create_scan("s-stuck", "stuck.example", "on_demand", state="running")
    _exec("UPDATE asm_scans SET created_at = ? WHERE scan_id = 's-stuck'", (store.now() - 7200,))
    store.create_scan("s-fresh", "fresh.example", "on_demand", state="running")
    assert store.redact_stale_scans(3600) == 1
    rows = {r["scan_id"]: r["domain"] for r in _rows("SELECT scan_id, domain FROM asm_scans")}
    assert fehash.is_hashed(rows["s-stuck"])
    assert rows["s-fresh"] == "fresh.example", "a run in flight still needs its target"


def test_the_audit_row_stores_the_hmac(monkeypatch, tmp_path):
    import app.pdf.report as pdf_report
    monkeypatch.setattr(pdf_report, "render_report", lambda payload, path: None)
    monkeypatch.setattr(config, "ASM_PDF_DIR", str(tmp_path))
    store.create_scan("s-aud", "brand", "Public", kind="hunt", engagement="brand.ph")
    scan = store.get_scan("s-aud")
    jobs._finalize(scan, {"kind": "hunt", "candidates": []})
    (aud,) = _rows("SELECT domain_hash, engagement FROM asm_scan_audit WHERE id = 's-aud'")
    assert aud["domain_hash"] == fehash.hmac_value("brand")
    assert aud["engagement"] == fehash.hmac_value("brand.ph")
    assert hashlib.sha256(b"brand").hexdigest()[:32] != aud["domain_hash"]


# ---------- revoke deletes everything ----------

def _seed_domain(domain="example.com"):
    cookie = verify.issue_grant(domain, "email", "admin@" + domain)
    store.upsert_domain(domain, "verified", source="email", notify_email="admin@" + domain)
    store.create_verification(domain, "email", "admin", "tokhash-" + domain, 24, "iphash")
    store.create_scan("r1-" + domain, domain, "on_demand")
    store.finish_scan("r1-" + domain, {})
    store.record_scan_audit("r1-" + domain, "asm", "on_demand", 0, "", fehash.hmac_value(domain), 3, {})
    store.rl_record("vstart_dom", domain)
    return cookie


def _count(domain):
    h = fehash.hmac_value(domain)
    return {
        "domains": len(_rows("SELECT 1 FROM asm_domains WHERE domain = ?", (domain,))),
        "verifications": len(_rows("SELECT 1 FROM asm_verifications WHERE domain = ?", (domain,))),
        "grants": len(_rows("SELECT 1 FROM asm_grants WHERE domain = ?", (domain,))),
        "scans": len(_rows("SELECT 1 FROM asm_scans WHERE domain IN (?, ?)", (domain, h))),
        "audit": len(_rows("SELECT 1 FROM asm_scan_audit WHERE domain_hash = ?", (h,))),
        "rate": len(_rows("SELECT 1 FROM asm_rate_limit WHERE key = ?", (domain,))),
    }


def test_delete_domain_removes_every_row_for_the_domain():
    _seed_domain("example.com")
    _seed_domain("other.example")
    assert all(_count("example.com").values())
    deleted = store.delete_domain("example.com")
    assert not any(_count("example.com").values()), _count("example.com")
    assert all(_count("other.example").values()), "another domain's rows were touched"
    assert deleted["asm_grants"] == 1 and deleted["asm_scans"] == 1


def test_the_revoke_route_deletes_every_record(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    cookie = _seed_domain("example.com")
    client = TestClient(app, base_url="https://testserver")
    client.cookies.set(verify.GRANT_COOKIE, cookie)
    resp = client.post("/api/asm/manage/revoke", json={"domain": "example.com"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["revoked"] == 1
    assert not any(_count("example.com").values())


def test_a_verified_owner_can_still_read_a_finished_runs_result():
    """A finished run holds only the HMAC, so the access check compares both."""
    from fastapi.testclient import TestClient
    from app.main import app
    from app.routers import asm as asm_routes
    cookie = verify.issue_grant("example.com", "dns", "")
    store.create_scan("view-1", "example.com", "on_demand")
    store.cache_result("view-1", "asm", {"title": "x"}, "")
    store.finish_scan("view-1", {})
    client = TestClient(app, base_url="https://testserver")
    client.cookies.set(verify.GRANT_COOKIE, cookie)
    assert client.get("/api/asm/scan/view-1").status_code == 200
    client.cookies.set(verify.GRANT_COOKIE, verify.issue_grant("other.example", "dns", ""))
    assert client.get("/api/asm/scan/view-1").status_code == 404
    assert asm_routes  # imported for its router


def test_the_management_email_says_exactly_what_revoke_deletes(monkeypatch):
    sent = {}

    async def fake_send(recipient, subject, body):
        sent["body"] = body
        return {"ok": True}

    monkeypatch.setattr(mailer, "_send", fake_send)
    asyncio.run(mailer.send_management_link("admin@example.com", "example.com", "https://x/manage"))
    body = sent["body"]
    assert "deletes every record" in body
    for part in ("access grants", "verification records", "record of each scan", "audit entry",
                 "rate-limit counters"):
        assert part in body, f"the email does not say revoke deletes the {part}"
    assert "rotate" not in body.lower(), "the link cannot rotate anything"


# ---------- the 3.39.0 release action ----------

def _migrate(tmp_path, monkeypatch):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
    import migrate_3_39_0
    from app.prospect import investigations
    monkeypatch.setattr(investigations, "_DB_PATH", store.DB_PATH)
    monkeypatch.setattr(investigations, "_DATA_DIR", tmp_path)
    monkeypatch.setattr(investigations, "_PROSPECT_DIR", tmp_path / "prospect")
    env = tmp_path / ".env"
    env.write_text(f"FE_HASH_KEY={KEY}\n")
    return migrate_3_39_0.main(str(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
                               str(env), store.DB_PATH)


def test_the_release_action_converts_deletes_and_is_idempotent(tmp_path, monkeypatch, capsys):
    from app.prospect import investigations
    # Old-style rows: plain run rows and weak audit hashes.
    _exec("INSERT INTO asm_scans (scan_id, domain, kind, mode, state, operator, engagement, grant_id, created_at) "
          "VALUES ('old-asm', 'plain.example', 'asm', 'on_demand', 'done', 0, '', '', ?)", (store.now() - 10,))
    _exec("INSERT INTO asm_scans (scan_id, domain, kind, mode, state, operator, engagement, grant_id, created_at) "
          "VALUES ('old-hunt', 'brandx', 'hunt', 'Public', 'done', 0, 'brandx.ph', '', ?)", (store.now() - 10,))
    _exec("INSERT INTO asm_scans (scan_id, domain, kind, mode, state, operator, engagement, grant_id, created_at) "
          "VALUES ('queued-now', 'queued.example', 'asm', 'on_demand', 'queued', 0, '', '', ?)", (store.now(),))
    weak = lambda v: hashlib.sha256(v.encode()).hexdigest()[:32]  # noqa: E731
    store.record_scan_audit("old-asm", "asm", "on_demand", 0, "", weak("plain.example"), 1, {})
    store.record_scan_audit("old-hunt", "hunt", "Public", 0, "brandx.ph", weak("brandx"), 1, {})
    store.record_scan_audit("orphan", "asm", "on_demand", 0, "", weak("gone.example"), 1, {})
    # A revoked domain, and one revoked then re-verified (must survive).
    _seed_domain("revoked.example")
    store.revoke_all_grants("revoked.example")
    _seed_domain("reverified.example")
    store.revoke_all_grants("reverified.example")
    verify.issue_grant("reverified.example", "dns", "")
    # Company: an old-schema table with an IP hash, one old and one new dossier.
    conn = sqlite3.connect(store.DB_PATH)
    conn.execute("DROP TABLE IF EXISTS prospect_investigations")
    conn.execute("CREATE TABLE prospect_investigations (investigation_id TEXT PRIMARY KEY, domain TEXT NOT NULL, "
                 "generated_at TEXT NOT NULL, dossier_json_path TEXT NOT NULL, ip_hash TEXT NOT NULL)")
    conn.execute("INSERT INTO prospect_investigations VALUES ('old', 'a.com', '2020-01-01T00:00:00+00:00', "
                 "'prospect/old.json', ?)", (hashlib.sha256(b"1.2.3.4").hexdigest(),))
    from datetime import datetime, timezone
    conn.execute("INSERT INTO prospect_investigations VALUES ('new', 'b.com', ?, 'prospect/new.json', 'x')",
                 (datetime.now(timezone.utc).isoformat(),))
    conn.commit()
    conn.close()
    (tmp_path / "prospect").mkdir()
    (tmp_path / "prospect" / "old.json").write_text("{}")
    (tmp_path / "prospect" / "new.json").write_text("{}")

    assert _migrate(tmp_path, monkeypatch) == 0
    first = capsys.readouterr().out

    scans = {r["scan_id"]: r for r in _rows("SELECT scan_id, domain, engagement FROM asm_scans")}
    assert scans["old-asm"]["domain"] == fehash.hmac_value("plain.example")
    assert scans["old-hunt"]["domain"] == fehash.hmac_value("brandx")
    assert scans["old-hunt"]["engagement"] == fehash.hmac_value("brandx.ph")
    assert scans["queued-now"]["domain"] == "queued.example", "a queued run was converted under the old process"
    audit = {r["id"]: r for r in _rows("SELECT id, domain_hash, engagement FROM asm_scan_audit")}
    assert audit["old-asm"]["domain_hash"] == fehash.hmac_value("plain.example")
    assert audit["old-hunt"]["engagement"] == fehash.hmac_value("brandx.ph")
    assert audit["orphan"]["domain_hash"] is None, "an unconvertible weak hash was kept"
    assert not any(_count("revoked.example").values())
    assert _count("reverified.example")["grants"] >= 1, "a re-verified domain lost its live grant"
    cols = [r["name"] for r in _rows("PRAGMA table_info(prospect_investigations)")]
    assert "ip_hash" not in cols
    assert [r["investigation_id"] for r in _rows("SELECT investigation_id FROM prospect_investigations")] == ["new"]
    assert not (tmp_path / "prospect" / "old.json").exists()
    assert "dossiers older than 30 days deleted: 1 rows" in first
    assert "revoked grants: 1 domains" in first

    # Idempotent: a second run changes nothing.
    assert _migrate(tmp_path, monkeypatch) == 0
    second = capsys.readouterr().out
    assert "deleted: 0 rows, 0 files" in second
    assert "revoked grants: 0 domains" in second
    assert "run rows converted to HMAC: 0; audit rows re-keyed: 0; unconvertible audit hashes dropped: 0" in second
    investigations._init_table()


def test_the_release_action_refuses_without_a_key(tmp_path, capsys):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
    import migrate_3_39_0
    env = tmp_path / ".env"
    env.write_text("OTHER=1\n")
    assert migrate_3_39_0.main(".", str(env), store.DB_PATH) == 1
    assert "refusing" in capsys.readouterr().out
