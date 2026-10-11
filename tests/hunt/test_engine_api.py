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
        return {"candidates": [{"domain": "philhealth-refund.ph", "origins": ["crt.sh"],
                                "keyword_hit": True},
                               {"domain": "old.example.com", "origins": ["dnstwist"],
                                "keyword_hit": False}],
                "source_status": [{"source": "crt.sh", "role": "CT", "status": "answered"}],
                "incomplete": False, "nrd_off": True, "generated_count": 50,
                "keyword_hit_count": 1}

    async def fresolve(dom):
        # Control labels (random, "zq..." prefix) must NOT resolve, or every TLD
        # would look like a wildcard; real candidates resolve to their own IP.
        if dom.startswith("zq"):
            return {"domain": dom, "dns": {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
                    "ips": [], "cname": "", "resolves": False, "has_mx": False, "has_ns": False}
        return {"domain": dom, "dns": {"A": ["1.2.3.4"], "AAAA": [], "MX": [], "NS": [],
                "CNAME": []}, "ips": ["1.2.3.4"], "cname": "", "resolves": True,
                "has_mx": dom.startswith("philhealth"), "has_ns": True}

    async def fprobe(client, dom, kw, legit, legit_sig, dns_data=None):
        if dom.startswith("philhealth"):
            return {"domain": dom, "resolves": True, "has_mx": True, "fetched": True,
                    "reg_age_days": 3, "fresh_cert": True, "brand_markers": 2, "ph_indicators": 3,
                    "favicon_match": True, "cloudflare": False, "title": "Login", "parked": False,
                    "legit_title_sim": 95, "known_bad": False,
                    "evidence": [], "registered": "2026-10-08", "registrar": "X", "asn": 1}
        return {"domain": dom, "resolves": True, "has_mx": False, "fetched": True,
                "reg_age_days": 3000, "evidence": [], "parked": False}

    async def fsig(client, legit):
        return {"favicon": 123, "title": "PhilHealth"}

    monkeypatch.setattr(sources, "discover", fdisc)
    monkeypatch.setattr(candidate_mod, "resolve", fresolve)
    monkeypatch.setattr(candidate_mod, "probe", fprobe)
    monkeypatch.setattr(candidate_mod, "legit_signature", fsig)

    payload = asyncio.run(engine.execute({"scan_id": "h1", "domain": "philhealth",
                                          "engagement": "philhealth.gov.ph"}))
    assert payload["kind"] == "hunt"
    assert payload["severity_counts"]["likely phishing"] >= 1
    assert payload["candidates"][0]["verdict"] == "likely phishing"
    assert payload["candidates"][0]["source"] == "crt.sh"  # keyword hit, labelled, listed first
    assert payload["pipeline"]["fetched"] == 2
    assert payload["pipeline"]["wildcard"] == 0
    assert payload["nrd_off"] is True
    assert all("gsb_url" in c for c in payload["candidates"])


def test_engine_drops_wildcard_candidates(monkeypatch):
    # A TLD that answers every label with the same IP is a registry wildcard; a
    # candidate matching that control answer is not registered and is not a row.
    async def fdisc(kw, legit):
        return {"candidates": [{"domain": "mmdalogin.ph", "origins": ["dnstwist"],
                                "keyword_hit": False},
                               {"domain": "mmda-real.com", "origins": ["dnstwist"],
                                "keyword_hit": False}],
                "source_status": [], "incomplete": False, "nrd_off": True,
                "generated_count": 2, "keyword_hit_count": 0}

    async def fresolve(dom):
        # dot.ph wildcard IP for anything under .ph (controls included); the .com
        # resolves to its own address and .com controls do not resolve.
        if dom.endswith(".ph"):
            return {"domain": dom, "dns": {"A": ["45.79.222.138"], "AAAA": [], "MX": [],
                    "NS": [], "CNAME": []}, "ips": ["45.79.222.138"], "cname": "",
                    "resolves": True, "has_mx": False, "has_ns": False}
        if dom.startswith("zq"):
            return {"domain": dom, "dns": {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
                    "ips": [], "cname": "", "resolves": False, "has_mx": False, "has_ns": False}
        return {"domain": dom, "dns": {"A": ["203.0.113.5"], "AAAA": [], "MX": [], "NS": [],
                "CNAME": []}, "ips": ["203.0.113.5"], "cname": "", "resolves": True,
                "has_mx": False, "has_ns": True}

    async def fprobe(client, dom, kw, legit, legit_sig, dns_data=None):
        return {"domain": dom, "resolves": True, "fetched": True, "parked": False,
                "reg_age_days": 1000, "evidence": []}

    async def fsig(client, legit):
        return {"favicon": None, "title": ""}

    monkeypatch.setattr(sources, "discover", fdisc)
    monkeypatch.setattr(candidate_mod, "resolve", fresolve)
    monkeypatch.setattr(candidate_mod, "probe", fprobe)
    monkeypatch.setattr(candidate_mod, "legit_signature", fsig)

    payload = asyncio.run(engine.execute({"scan_id": "h2", "domain": "mmda",
                                          "engagement": "mmda.gov.ph"}))
    domains = [c["domain"] for c in payload["candidates"]]
    assert "mmdalogin.ph" not in domains  # wildcard, dropped
    assert "mmda-real.com" in domains
    assert payload["pipeline"]["wildcard"] == 1
    assert payload["pipeline"]["resolved"] == 1


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
