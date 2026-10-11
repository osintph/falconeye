"""v3.38.0 one-time model: result content is purged after delivery or TTL, only
metadata is kept, and the PDF is deleted only after a completed download."""
import os
import time
from unittest.mock import patch

from app.asm import discovery, jobs, probe, serve, store


def _rec(host, kind="own"):
    return {"host": host, "kind": kind,
            "resolved_ips": ["192.0.2.1"] if kind != "reference" else [],
            "cname": "", "cname_target": "", "cdn_provider": "Cloudflare" if kind == "cdn" else "",
            "is_reference": 1 if kind == "reference" else 0, "nxdomain": False,
            "dns": {"a": ["192.0.2.1"], "aaaa": [], "cname": []},
            "http": {"status": 200, "server": "nginx", "title": "", "sec": {}},
            "tls": None, "fingerprint": [], "open_ports": [{"port": 443}] if kind == "own" else [],
            "_body": ""}


def _run_asm(scan_id="s1", domain="example.com", tmp_pdf="/tmp/v38test_pdfs"):
    async def fdisc(d):
        return {"hosts": [d], "sources": {"ct": {"ok": True}, "passive_dns": {"ok": True},
                "wayback": {"ok": True}}, "asn": {"available": True, "asn": 1}, "registrable": d}

    async def fprobe(h, reg, **kw):
        return _rec(h)

    async def fpost(d):
        return {"spf": {"found": True}, "dmarc": {"found": True, "policy": "reject"},
                "mta_sts": True, "tls_rpt": True}

    store.create_scan(scan_id, domain, "On-demand", kind="asm", grant_id="g")
    import asyncio
    with patch("app.config.ASM_PDF_DIR", tmp_pdf), \
         patch.object(discovery, "discover", fdisc), \
         patch.object(probe, "probe_host", fprobe), \
         patch.object(probe, "apex_mail_posture", fpost):
        asyncio.run(jobs.run_scan(scan_id))


def test_result_cached_and_pdf_written():
    _run_asm("oc1")
    row = store.get_result("oc1")
    assert row and row["payload"]
    assert os.path.exists(row["pdf_path"])


def test_no_host_or_finding_rows_are_stored():
    _run_asm("oc2")
    conn = store._connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM asm_hosts WHERE scan_id='oc2'").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM asm_findings WHERE scan_id='oc2'").fetchone()[0] == 0
    finally:
        conn.close()


def test_audit_is_metadata_only_with_a_hashed_domain():
    _run_asm("oc3", domain="secret-domain.test")
    conn = store._connect()
    try:
        row = conn.execute("SELECT domain_hash, host_count, kind FROM asm_scan_audit WHERE id='oc3'").fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row["domain_hash"] and "secret-domain" not in row["domain_hash"]
    assert row["kind"] == "asm"


def test_completed_download_purges_the_result_and_file():
    _run_asm("oc4")
    pdf_path = store.get_result("oc4")["pdf_path"]
    # Consume the whole stream (a completed download).
    list(serve.pdf_stream("oc4", pdf_path))
    assert store.get_result("oc4") is None
    assert not os.path.exists(pdf_path)


def test_interrupted_download_leaves_the_result():
    _run_asm("oc5")
    pdf_path = store.get_result("oc5")["pdf_path"]
    gen = serve.pdf_stream("oc5", pdf_path)
    next(gen)           # start the stream
    gen.close()         # client disconnects before completion
    assert store.get_result("oc5") is not None  # still available until the TTL
    assert os.path.exists(pdf_path)


def test_sweep_purges_expired_results():
    _run_asm("oc6")
    # Age the row past the TTL.
    conn = store._connect()
    try:
        conn.execute("UPDATE asm_result_cache SET created_at = ? WHERE id='oc6'", (int(time.time()) - 10000,))
        conn.commit()
    finally:
        conn.close()
    store.sweep_results(3600)
    assert store.get_result("oc6") is None
