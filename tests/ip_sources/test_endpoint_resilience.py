"""
CRITICAL regression guard: /api/ip/lookup/{ip} must return 200 with partial data
when reputation sources (or core fetchers) fail — one broken source must never
500 the endpoint or blank the result.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.routers import ip_intel


def _client():
    app = FastAPI()
    app.state.limiter = ip_intel.limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(ip_intel.router)
    return TestClient(app)


def _src(name, ok, state, **data):
    country = data.pop("_country", None)
    return {"source": name, "ok": ok, "state": state, "data": data, "error": data.pop("_err", None), "country": country}


def test_endpoint_all_sources_ok(monkeypatch):
    async def shodan(c, ip): return {"ports": [80], "vulns": []}
    async def gn(c, ip): return {"classification": "benign"}
    async def ripe(c, ip): return {"asn": 1, "asn_holder": "X", "country": "IR"}
    async def uh(c, ip): return None
    async def ptr(ip): return ["host.example"]

    async def repsrc(ip, client):
        return {
            "abuseipdb": _src("abuseipdb", True, "ok", confidence=100, total_reports=79, distinct_users=36, categories=[], _country="LT"),
            "virustotal": _src("virustotal", True, "ok", malicious=7, total_engines=91, _country="IR"),
            "otx": _src("otx", True, "ok", pulse_count=2, _country="US"),
            "censys": _src("censys", True, "ok", ports=[{"port": 22, "service": "SSH"}], asn_country="RS", _country="LT"),
            "threatfox": _src("threatfox", True, "not_found", matched=False, iocs=[]),
        }

    monkeypatch.setattr(ip_intel, "fetch_shodan_internetdb", shodan)
    monkeypatch.setattr(ip_intel, "fetch_greynoise", gn)
    monkeypatch.setattr(ip_intel, "fetch_ripestat", ripe)
    monkeypatch.setattr(ip_intel, "fetch_urlhaus_host", uh)
    monkeypatch.setattr(ip_intel, "fetch_reverse_dns", ptr)
    monkeypatch.setattr(ip_intel.reputation, "fetch_sources", repsrc)

    r = _client().get("/api/ip/lookup/62.60.130.193")
    assert r.status_code == 200
    rep = r.json()["reputation"]
    assert rep["verdict"]["verdict"] == "MALICIOUS"
    assert rep["ports"]["ports"][0]["port"] == 22        # Censys merged into ports
    assert rep["geo"]["agreement"] is False               # LT/IR/US/RS disagreement


def test_endpoint_200_when_sources_partially_fail(monkeypatch):
    async def boom(*a, **k): raise RuntimeError("down")
    async def ptr_boom(ip): raise RuntimeError("down")

    async def repsrc(ip, client):
        return {
            "abuseipdb": _src("abuseipdb", False, "error", _err="authentication failed"),
            "virustotal": _src("virustotal", True, "ok", malicious=7, total_engines=91, _country="IR"),
            "otx": _src("otx", False, "quota", _err="rate limit"),
            "censys": _src("censys", False, "no_key", _err="no PAT"),
            "threatfox": _src("threatfox", True, "not_found", matched=False),
        }

    for name in ("fetch_shodan_internetdb", "fetch_greynoise", "fetch_ripestat", "fetch_urlhaus_host"):
        monkeypatch.setattr(ip_intel, name, boom)
    monkeypatch.setattr(ip_intel, "fetch_reverse_dns", ptr_boom)
    monkeypatch.setattr(ip_intel.reputation, "fetch_sources", repsrc)

    r = _client().get("/api/ip/lookup/8.8.8.8")
    assert r.status_code == 200                            # never 500 on failure
    rep = r.json()["reputation"]
    assert rep["verdict"]["verdict"] == "MALICIOUS"        # VirusTotal alone still fires
    assert rep["sources"]["abuseipdb"]["state"] == "error"
    assert rep["sources"]["censys"]["state"] == "no_key"


def test_endpoint_200_when_reputation_fetch_raises(monkeypatch):
    async def none_fetch(*a, **k): return None
    async def ptr(ip): return []
    async def rep_boom(ip, client): raise RuntimeError("total reputation failure")

    for name in ("fetch_shodan_internetdb", "fetch_greynoise", "fetch_ripestat", "fetch_urlhaus_host"):
        monkeypatch.setattr(ip_intel, name, none_fetch)
    monkeypatch.setattr(ip_intel, "fetch_reverse_dns", ptr)
    monkeypatch.setattr(ip_intel.reputation, "fetch_sources", rep_boom)

    r = _client().get("/api/ip/lookup/8.8.8.8")
    assert r.status_code == 200                            # reputation blowing up must not 500
    assert r.json()["reputation"]["verdict"]["verdict"] == "CLEAN"  # no sources → clean
