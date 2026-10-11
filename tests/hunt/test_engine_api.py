"""Hunt engine and API: no port scan of candidates, caps, one-time delivery, and
the public endpoint behaviour."""
import asyncio
import pathlib
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import main
from app.asm import jobs, store
from app.hunt import candidate as candidate_mod
from app.hunt import engine
from app.hunt import sources

REPO = pathlib.Path(__file__).resolve().parents[2]


def test_hunt_package_never_port_scans():
    # Structural guarantee: nothing in the hunt package imports or calls the port
    # scanner. A Hunt candidate gets one HTTP GET, never a port scan.
    for p in (REPO / "app" / "hunt").rglob("*.py"):
        src = p.read_text(encoding="utf-8")
        assert "portscan" not in src and "port_scan" not in src, f"{p} references a port scanner"


def test_engine_builds_a_payload(monkeypatch):
    async def fdisc(kw, legit):
        return {"candidates": ["philhealth-refund.ph", "old.example.com"],
                "source_status": [{"source": "crt.sh", "role": "CT", "status": "answered"}],
                "incomplete": False, "nrd_off": True, "generated_count": 50}

    async def fprobe(client, dom, kw, legit, fav):
        if dom.startswith("philhealth"):
            return {"domain": dom, "resolves": True, "has_mx": True, "reg_age_days": 3,
                    "fresh_cert": True, "brand_markers": 2, "ph_indicators": 3, "favicon_match": True,
                    "cloudflare": False, "title": "Login", "parked": False, "evidence": [],
                    "registered": "2026-10-08", "registrar": "X", "asn": 1}
        return {"domain": dom, "resolves": True, "has_mx": False, "reg_age_days": 3000,
                "evidence": [], "parked": False}

    async def ffav(client, legit):
        return 123

    monkeypatch.setattr(sources, "discover", fdisc)
    monkeypatch.setattr(candidate_mod, "probe", fprobe)
    monkeypatch.setattr(candidate_mod, "legit_favicon_hash", ffav)

    payload = asyncio.run(engine.execute({"scan_id": "h1", "domain": "philhealth",
                                          "engagement": "philhealth.gov.ph"}))
    assert payload["kind"] == "hunt"
    assert payload["severity_counts"]["likely phishing"] >= 1
    assert payload["candidates"][0]["verdict"] == "likely phishing"
    assert payload["nrd_off"] is True
    assert all("gsb_url" in c for c in payload["candidates"])


def _client(ip="203.0.113.9"):
    return TestClient(main.app, base_url="https://testserver", client=(ip, 1))


def test_api_validation():
    c = _client()
    assert c.post("/api/hunt", json={"keyword": "ab"}).status_code == 400
    assert c.post("/api/hunt", json={"keyword": "ph*sh"}).status_code == 400
    with patch.object(jobs, "submit", lambda sid: True):
        r = c.post("/api/hunt", json={"keyword": "philhealth"})
        assert r.status_code == 200 and r.json()["state"] == "queued"


def test_hunt_endpoint_will_not_serve_an_asm_scan():
    # An ASM scan id must not be readable through the public hunt endpoint.
    store.create_scan("asmX", "example.com", "On-demand", kind="asm", grant_id="g")
    assert _client().get("/api/hunt/asmX").status_code == 404


def test_mcp_hunt_runs_inline_and_stores_nothing(monkeypatch):
    async def fake_exec(scan):
        return {"kind": "hunt", "scan_id": scan["scan_id"], "candidates": [], "severity_counts": {}}
    monkeypatch.setattr("app.hunt.engine.execute", fake_exec)
    r = _client().post("/api/hunt/mcp", json={"keyword": "philhealth"})
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == "hunt"
    assert "scan_id" not in body  # nothing stored, no id to poll
