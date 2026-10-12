"""Hunt engine and API: no port scan of candidates, caps, one-time delivery, and
the public endpoint behaviour."""
import asyncio
import pathlib
from unittest.mock import patch

from fastapi.testclient import TestClient

from app import config
from app import main
from app.asm import jobs, store
from app.hunt import candidate as candidate_mod
from app.hunt import engine
from app.hunt import sources
from app.hunt import themes

REPO = pathlib.Path(__file__).resolve().parents[2]


def test_hunt_package_never_port_scans():
    # Structural guarantee: nothing in the hunt package imports or calls the port
    # scanner. A Hunt candidate gets one HTTP GET, never a port scan.
    for p in (REPO / "app" / "hunt").rglob("*.py"):
        src = p.read_text(encoding="utf-8")
        assert "portscan" not in src and "port_scan" not in src, f"{p} references a port scanner"


def test_engine_builds_a_payload(monkeypatch):
    async def fdisc(kw, legit, max_candidates=None, operator=False):
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
                    "legit_title_sim": 95, "known_bad": False, "has_cred_form": True,
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
    async def fdisc(kw, legit, max_candidates=None, operator=False):
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


_NCAP = ["mmda-ltoncap.net", "mmdaltoncaps.com", "mmdancap-ncr.icu", "ncapmmdar.com",
         "mmda-ncaplto.club"]


def test_engine_detects_ncap_campaign_and_drops_noise(monkeypatch):
    # The live LTO/NCAP fine-lure set must come out as one Likely Phishing cluster;
    # emmday.in (no theme, no campaign, no verdict) must not outrank it.
    async def fdisc(kw, legit, max_candidates=None, operator=False):
        cands = []
        for d in _NCAP:
            cands.append({"domain": d, "origins": ["urlscan.io"], "keyword_hit": True,
                          "observed": [d], "themes": themes.classify(d, "mmda")["themes"],
                          "relevant": True,
                          "urlscan": {"labels": [], "first_seen": "2026-09-15", "title": "",
                                      "age_days": 30, "asn": "AS1 Host",
                                      "result_url": "https://urlscan.io/result/x/"}})
        cands.append({"domain": "emmday.in", "origins": ["urlscan.io"], "keyword_hit": True,
                      "observed": ["emmday.in"], "themes": [], "relevant": True,
                      "urlscan": {"labels": [], "first_seen": "2026-10-01", "title": "",
                                  "age_days": 500, "asn": None, "result_url": ""}})
        return {"candidates": cands,
                "source_status": [{"source": "urlscan.io", "role": "x", "status": "answered"}],
                "incomplete": False, "nrd_off": True, "generated_count": 80,
                "keyword_hit_count": 6, "irrelevant_count": 7}

    async def fresolve(dom):
        if dom.startswith("zq"):
            return {"domain": dom, "dns": {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
                    "ips": [], "cname": "", "resolves": False, "has_mx": False, "has_ns": False}
        import hashlib
        ip = "203.0.113." + str(int(hashlib.sha1(dom.encode()).hexdigest(), 16) % 200 + 1)
        return {"domain": dom, "dns": {"A": [ip], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
                "ips": [ip], "cname": "", "resolves": True, "has_mx": False, "has_ns": True}

    ages = {d: 30 for d in _NCAP}
    ages["emmday.in"] = 500

    async def fprobe(client, dom, kw, legit, sig, dns_data=None):
        return {"domain": dom, "resolves": True, "fetched": True, "parked": False,
                "reg_age_days": ages.get(dom, 1000), "registrar": "NameSilo"}

    async def fsig(client, legit):
        return {}

    monkeypatch.setattr(sources, "discover", fdisc)
    monkeypatch.setattr(candidate_mod, "resolve", fresolve)
    monkeypatch.setattr(candidate_mod, "probe", fprobe)
    monkeypatch.setattr(candidate_mod, "legit_signature", fsig)

    payload = asyncio.run(engine.execute({"scan_id": "h3", "domain": "mmda",
                                          "engagement": "mmda.gov.ph"}))
    assert len(payload["campaigns"]) == 1
    assert payload["campaigns"][0]["count"] == 5
    rows = {r["domain"]: r for r in payload["candidates"]}
    for d in _NCAP:
        assert rows[d]["verdict"] == "likely phishing", d
    assert rows["emmday.in"]["verdict"] != "likely phishing"
    assert payload["candidates"][0]["domain"] in _NCAP  # a campaign member leads
    assert payload["pipeline"]["irrelevant"] == 7


def _client(ip="203.0.113.9"):
    return TestClient(main.app, base_url="https://testserver", client=(ip, 1))


def test_reg_date_comes_from_registration_not_age():
    # The shown registration date is the real RDAP or whois date, never synthesised
    # from an age. No date available means no shown date.
    assert engine._reg_date(None) is None
    assert engine._reg_date("2026-01-15T00:00:00Z") == "2026-01-15"
    assert engine._reg_date("2026-01-15") == "2026-01-15"


def test_age_is_computed_from_the_registration_date():
    import datetime as dt
    expected = (dt.datetime.now(dt.timezone.utc).date() - dt.date(2026, 1, 15)).days
    assert engine._age_from("2026-01-15") == expected
    assert engine._age_from(None) is None


def test_backfills_registrar_for_a_themed_probe_miss(monkeypatch):
    # The concurrent probe returns a themed candidate with no registrar (RDAP cut
    # off under load). The engine backfills it from the Hunt RDAP client before
    # clustering, so the campaign member is not left "unknown".
    async def fdisc(kw, legit, max_candidates=None, operator=False):
        return {"candidates": [{"domain": "mmdancap.icu", "origins": ["urlscan"],
                                "keyword_hit": True, "themes": ["ncap"]}],
                "source_status": [], "incomplete": False, "nrd_off": True,
                "generated_count": 1, "keyword_hit_count": 1}

    async def fresolve(dom):
        if dom.startswith("zq"):
            return {"domain": dom, "dns": {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
                    "ips": [], "cname": "", "resolves": False, "has_mx": False, "has_ns": False}
        return {"domain": dom, "dns": {"A": ["1.2.3.4"], "AAAA": [], "MX": [], "NS": [],
                "CNAME": []}, "ips": ["1.2.3.4"], "cname": "", "resolves": True,
                "has_mx": False, "has_ns": True}

    async def fprobe(client, dom, kw, legit, legit_sig, dns_data=None):
        return {"domain": dom, "resolves": True, "fetched": True, "evidence": [],
                "parked": False, "registrar": None, "reg_age_days": 5}

    async def fsig(client, legit):
        return {"favicon": None, "title": "MMDA"}

    async def fake_lookup(client, domain):
        return {"registrar": {"name": "NameMart Pte. Ltd."},
                "events": {"registration": "2026-09-01"},
                "abuse_contact": {"email": "abuse@namemart.com"}, "nameservers": []}

    monkeypatch.setattr(sources, "discover", fdisc)
    monkeypatch.setattr(candidate_mod, "resolve", fresolve)
    monkeypatch.setattr(candidate_mod, "probe", fprobe)
    monkeypatch.setattr(candidate_mod, "legit_signature", fsig)
    monkeypatch.setattr(engine.rdap_mod, "lookup", fake_lookup)
    payload = asyncio.run(engine.execute({"scan_id": "hbf", "domain": "mmda",
                                          "engagement": "mmda.gov.ph"}))
    row = next(r for r in payload["candidates"] if r["domain"] == "mmdancap.icu")
    assert row["registrar"] == "NameMart Pte. Ltd."


def test_shown_date_is_rdap_not_urlscan_when_they_differ(monkeypatch):
    # urlscan first-seen (recent) and RDAP registration (months earlier) differ; the
    # shown date is the RDAP date, the age is computed from it, and urlscan
    # first-seen is carried separately. Never today-minus-urlscan-age.
    import datetime as dt

    async def fdisc(kw, legit, max_candidates=None, operator=False):
        return {"candidates": [{"domain": "philhealth-login.com", "origins": ["urlscan"],
                                "keyword_hit": True,
                                "urlscan": {"first_seen": "2026-09-20T00:00:00Z", "age_days": 22}}],
                "source_status": [], "incomplete": False, "nrd_off": True,
                "generated_count": 1, "keyword_hit_count": 1}

    async def fresolve(dom):
        if dom.startswith("zq"):  # wildcard control labels must not resolve
            return {"domain": dom, "dns": {"A": [], "AAAA": [], "MX": [], "NS": [], "CNAME": []},
                    "ips": [], "cname": "", "resolves": False, "has_mx": False, "has_ns": False}
        return {"domain": dom, "dns": {"A": ["1.2.3.4"], "AAAA": [], "MX": [], "NS": [],
                "CNAME": []}, "ips": ["1.2.3.4"], "cname": "", "resolves": True,
                "has_mx": False, "has_ns": True}

    async def fprobe(client, dom, kw, legit, legit_sig, dns_data=None):
        return {"domain": dom, "resolves": True, "fetched": True, "evidence": [],
                "parked": False, "registered": "2026-01-15", "registrar": "NameSilo, LLC",
                "asn": 1}

    async def fsig(client, legit):
        return {"favicon": None, "title": "PhilHealth"}

    monkeypatch.setattr(sources, "discover", fdisc)
    monkeypatch.setattr(candidate_mod, "resolve", fresolve)
    monkeypatch.setattr(candidate_mod, "probe", fprobe)
    monkeypatch.setattr(candidate_mod, "legit_signature", fsig)
    payload = asyncio.run(engine.execute({"scan_id": "hd", "domain": "philhealth",
                                          "engagement": "philhealth.gov.ph"}))
    row = next(r for r in payload["candidates"] if r["domain"] == "philhealth-login.com")
    assert row["registered"] == "2026-01-15"
    assert row["urlscan_first_seen"] == "2026-09-20"
    assert row["age_days"] == (dt.datetime.now(dt.timezone.utc).date() - dt.date(2026, 1, 15)).days


def test_hunt_url_input_is_normalised():
    with patch.object(jobs, "submit", lambda sid: True):
        r = _client().post("/api/hunt",
                           json={"keyword": "DICT", "legit_domain": "https://www.dict.gov.ph/a?x=1"})
        assert r.status_code == 200
        n = r.json()["normalized"]
        assert n["keyword"] == "dict" and n["legit_domain"] == "dict.gov.ph"


def test_hunt_operator_bypasses_public_cap_and_shares_session(monkeypatch):
    from app.asm import operator
    ip = "203.0.113.77"
    monkeypatch.setattr(config, "HUNT_PER_DAY", 0)  # public cap exhausted
    with patch.object(jobs, "submit", lambda sid: True):
        pub = TestClient(main.app, base_url="https://testserver", client=(ip, 1)).post(
            "/api/hunt", json={"keyword": "mmda"})
        assert pub.status_code == 429 and "resets by" in pub.json()["error"]
    # An operator session (shared ASM cookie) bypasses the public cap.
    monkeypatch.setattr(operator, "configured", lambda: True)
    monkeypatch.setattr(operator, "session_from_cookie",
                        lambda cookie: {"sid": "s"} if cookie == "opc" else None)
    with patch.object(jobs, "submit", lambda sid: True):
        cl = TestClient(main.app, base_url="https://testserver", client=(ip, 1))
        cl.cookies.set("asm_operator", "opc")
        r = cl.post("/api/hunt", json={"keyword": "mmda", "engagement": "ENG-1"})
        assert r.status_code == 200 and r.json()["operator"] is True


def test_hunt_operator_inert_when_unconfigured(monkeypatch):
    from app.asm import operator
    monkeypatch.setattr(operator, "configured", lambda: False)
    monkeypatch.setattr(config, "HUNT_PER_DAY", 0)
    cl = TestClient(main.app, base_url="https://testserver", client=("203.0.113.78", 1))
    cl.cookies.set("asm_operator", "opc")
    r = cl.post("/api/hunt", json={"keyword": "mmda"})
    # Operator mode off: the cookie is ignored and the public cap still applies.
    assert r.status_code == 429


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
