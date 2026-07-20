"""Per-source parsing + failure-state tests (mocked httpx via a fake client)."""
import asyncio

from app.ip_sources import abuseipdb, virustotal, otx, censys, threatfox


class FakeResp:
    def __init__(self, status, json_data=None, text=""):
        self.status_code = status
        self._json = json_data
        self.text = text

    def json(self):
        if self._json is None:
            raise ValueError("no json body")
        return self._json


class FakeClient:
    """Returns a canned response, raises to simulate a timeout, or explodes if
    called at all (to prove no-key short-circuits before any network)."""
    def __init__(self, resp=None, exc=None, forbid=False):
        self._resp, self._exc, self._forbid = resp, exc, forbid
        self.called = 0

    async def get(self, url, **kw):
        self.called += 1
        if self._forbid:
            raise AssertionError("must not call the network")
        if self._exc:
            raise self._exc
        return self._resp

    async def post(self, url, **kw):
        return await self.get(url, **kw)


def run(coro):
    return asyncio.run(coro)


# ---------- AbuseIPDB ----------

def test_abuseipdb_success(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_KEY", "k")
    resp = FakeResp(200, {"data": {"abuseConfidenceScore": 100, "totalReports": 79,
                                   "numDistinctUsers": 36, "countryCode": "LT", "isp": "X",
                                   "reports": [{"categories": [18, 22]}]}})
    r = run(abuseipdb.fetch("1.2.3.4", FakeClient(resp)))
    assert r.ok and r.state == "ok"
    assert r.data["confidence"] == 100 and r.data["total_reports"] == 79
    assert r.country == "LT"
    assert "Brute-Force" in r.data["categories"] and "SSH" in r.data["categories"]


def test_abuseipdb_no_key_never_calls(monkeypatch):
    r = run(abuseipdb.fetch("1.2.3.4", FakeClient(forbid=True)))
    assert r.state == "no_key" and not r.ok


def test_abuseipdb_quota(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_KEY", "k")
    r = run(abuseipdb.fetch("1.2.3.4", FakeClient(FakeResp(429))))
    assert r.state == "quota" and not r.ok


def test_abuseipdb_auth_error(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_KEY", "k")
    r = run(abuseipdb.fetch("1.2.3.4", FakeClient(FakeResp(401))))
    assert r.state == "error" and "auth" in r.error.lower()


def test_abuseipdb_timeout_no_raise(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_KEY", "k")
    r = run(abuseipdb.fetch("1.2.3.4", FakeClient(exc=TimeoutError("slow"))))
    assert r.state == "error" and not r.ok


def test_abuseipdb_malformed_no_raise(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_KEY", "k")
    r = run(abuseipdb.fetch("1.2.3.4", FakeClient(FakeResp(200, None))))
    assert r.state == "error"


# ---------- VirusTotal ----------

def test_virustotal_success(monkeypatch):
    monkeypatch.setenv("VT_KEY", "k")
    resp = FakeResp(200, {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 7, "suspicious": 2, "harmless": 51, "undetected": 31},
        "last_analysis_results": {"E1": {"category": "malicious", "engine_name": "E1"},
                                  "E2": {"category": "harmless", "engine_name": "E2"}},
        "as_owner": "Cipher", "country": "IR"}}})
    r = run(virustotal.fetch("1.2.3.4", FakeClient(resp)))
    assert r.ok and r.data["malicious"] == 7 and r.data["total_engines"] == 91
    assert r.data["flagged_vendors"] == ["E1"] and r.country == "IR"


def test_virustotal_no_key(monkeypatch):
    assert run(virustotal.fetch("1.2.3.4", FakeClient(forbid=True))).state == "no_key"


def test_virustotal_quota(monkeypatch):
    monkeypatch.setenv("VT_KEY", "k")
    assert run(virustotal.fetch("1.2.3.4", FakeClient(FakeResp(429)))).state == "quota"


# ---------- OTX ----------

def test_otx_success(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "k")
    resp = FakeResp(200, {"country_code": "US", "pulse_info": {"count": 2, "pulses": [
        {"name": "Honeypot", "malware_families": ["Mirai"], "tags": ["botnet"]},
        {"name": "Botnet list", "malware_families": [], "tags": []}]}})
    r = run(otx.fetch("1.2.3.4", FakeClient(resp)))
    assert r.ok and r.data["pulse_count"] == 2 and "Honeypot" in r.data["pulse_names"]
    assert "Mirai" in r.data["malware_families"] and r.country == "US"


def test_otx_no_key(monkeypatch):
    assert run(otx.fetch("1.2.3.4", FakeClient(forbid=True))).state == "no_key"


# ---------- Censys ----------

def test_censys_success_pat_only(monkeypatch):
    monkeypatch.setenv("CENSYS_PAT", "pat")
    resp = FakeResp(200, {"result": {"resource": {
        "services": [{"port": 22, "protocol": "SSH", "transport_protocol": "tcp"}],
        "location": {"country_code": "LT"},
        "autonomous_system": {"asn": 215930, "name": "Cipher", "country_code": "RS"},
        "operating_system": {"vendor": "canonical", "product": "linux"}}}})
    r = run(censys.fetch("1.2.3.4", FakeClient(resp)))
    assert r.ok and r.data["ports"] == [{"port": 22, "service": "SSH", "transport": "tcp"}]
    assert r.data["asn_country"] == "RS" and r.country == "LT"


def test_censys_no_pat(monkeypatch):
    assert run(censys.fetch("1.2.3.4", FakeClient(forbid=True))).state == "no_key"


def test_censys_invalid_org_id_not_sent(monkeypatch):
    # A non-UUID org id must be dropped (it caused a 422 in production).
    monkeypatch.setenv("CENSYS_PAT", "pat")
    monkeypatch.setenv("CENSYS_ORG_ID", "not-a-uuid")
    captured = {}

    class Cap(FakeClient):
        async def get(self, url, **kw):
            captured["headers"] = kw.get("headers", {})
            return FakeResp(200, {"result": {"resource": {"services": [], "location": {}, "autonomous_system": {}}}})

    run(censys.fetch("1.2.3.4", Cap()))
    assert "X-Organization-ID" not in captured["headers"]


# ---------- ThreatFox ----------

def test_threatfox_match(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "k")
    resp = FakeResp(200, {"query_status": "ok", "data": [
        {"malware_printable": "Cobalt Strike", "threat_type": "botnet_cc", "confidence_level": 100,
         "first_seen": "2026-01-01", "last_seen": "2026-07-01"}]})
    r = run(threatfox.fetch("1.2.3.4", FakeClient(resp)))
    assert r.ok and r.data["matched"] and r.data["iocs"][0]["malware"] == "Cobalt Strike"


def test_threatfox_no_result(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "k")
    r = run(threatfox.fetch("1.2.3.4", FakeClient(FakeResp(200, {"query_status": "no_result"}))))
    assert r.ok and r.state == "not_found" and r.data["matched"] is False


def test_threatfox_no_key(monkeypatch):
    assert run(threatfox.fetch("1.2.3.4", FakeClient(forbid=True))).state == "no_key"
