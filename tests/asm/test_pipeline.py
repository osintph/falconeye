"""The scan pipeline: discovery -> probe -> findings -> store -> report/export.

Discovery and the active probe are mocked so the pipeline runs offline; findings,
storage and the report shaping are the real code.
"""
import asyncio
import json

import pytest

from app.asm import discovery, jobs, probe, report, store


def _host(host, kind="own", ips=None, cname="", nxdomain=False, ports=None,
          status=200, server="nginx", sec=None):
    return {
        "host": host, "kind": kind, "resolved_ips": ips or (["192.0.2.10"] if kind != "reference" else []),
        "cname": cname, "cname_target": cname, "cdn_provider": "Fastly" if kind == "cdn" else "",
        "is_reference": 1 if kind == "reference" else 0, "nxdomain": nxdomain,
        "dns": {"a": ips or [], "aaaa": [], "cname": [cname] if cname else []},
        "http": {"status": status, "title": "", "server": server,
                 "sec": sec or {"strict-transport-security": True, "content-security-policy": True,
                                "x-content-type-options": True, "x-frame-options": True,
                                "referrer-policy": True}} if status else {},
        "tls": None, "fingerprint": [], "open_ports": ports or [], "_body": "",
    }


@pytest.fixture
def mocked(monkeypatch):
    hosts = ["acme.test", "www.acme.test", "db.acme.test", "cdn.acme.test", "gone.acme.test"]

    async def fake_discover(domain):
        return {"hosts": hosts, "sources": {"ct": {"ok": True, "count": 5}},
                "asn": {"available": False}, "registrable": "acme.test"}

    records = {
        "acme.test": _host("acme.test"),
        "www.acme.test": _host("www.acme.test"),
        "db.acme.test": _host("db.acme.test", ports=[{"port": 3306}]),
        "cdn.acme.test": _host("cdn.acme.test", kind="cdn", ips=["151.101.1.1"], ports=[]),
        "gone.acme.test": _host("gone.acme.test", kind="reference", ips=[],
                                cname="missing.example-cdn.test", nxdomain=True, status=0),
    }

    async def fake_probe(host, reg, **kwargs):
        return records[host]

    async def fake_posture(domain):
        return {"spf": {"found": True}, "dmarc": {"found": False, "policy": None},
                "mta_sts": False, "tls_rpt": False}

    monkeypatch.setattr(discovery, "discover", fake_discover)
    monkeypatch.setattr(probe, "probe_host", fake_probe)
    monkeypatch.setattr(probe, "apex_mail_posture", fake_posture)
    return hosts


def test_run_scan_returns_a_one_time_payload(mocked):
    # One-time model: run_scan returns the payload (and caches it), it does NOT
    # store hosts or findings in durable tables.
    store.create_scan("s1", "acme.test", "on_demand", operator=0, grant_id="g")
    payload = asyncio.run(jobs.run_scan("s1"))

    assert store.get_scan("s1")["state"] == "done"
    assert payload["hosts_probed"] == 5
    assert payload["behind_cdn"] == 1
    assert payload["references"] == 1
    assert len(payload["hosts"]) == 5

    kinds = {f["kind"] for f in payload["findings"]}
    assert "takeover" in kinds
    assert "open_service" in kinds
    assert "mail_posture" in kinds


def test_cdn_and_reference_hosts_are_not_port_scanned_in_the_payload(mocked):
    store.create_scan("s2", "acme.test", "on_demand", operator=0, grant_id="g")
    payload = asyncio.run(jobs.run_scan("s2"))
    csv = report.export_csv_payload(payload)
    assert "not scanned" in csv  # the CDN and reference rows
    cdn_row = next(h for h in payload["hosts"] if h["host"] == "cdn.acme.test")
    assert cdn_row["kind"] == "cdn" and cdn_row["ports"] == []


def test_payload_lists_findings_most_severe_first(mocked):
    store.create_scan("s3", "acme.test", "on_demand", operator=0, grant_id="g")
    payload = asyncio.run(jobs.run_scan("s3"))
    sevs = [f["severity"] for f in payload["findings"]]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    assert sevs == sorted(sevs, key=lambda s: order[s])
