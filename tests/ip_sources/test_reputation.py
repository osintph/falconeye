"""Consensus verdict thresholds, geo consensus, and port merge."""
from app.ip_sources import reputation as rep


def src(name, ok=True, **data):
    return {"source": name, "ok": ok, "state": "ok" if ok else "error",
            "data": data, "error": None, "country": data.pop("_country", None)}


# ---------- verdict thresholds ----------

def test_verdict_abuseipdb_boundaries():
    assert rep.compute_verdict({"abuseipdb": src("abuseipdb", confidence=75)})["verdict"] == "MALICIOUS"
    assert rep.compute_verdict({"abuseipdb": src("abuseipdb", confidence=74)})["verdict"] == "SUSPICIOUS"
    assert rep.compute_verdict({"abuseipdb": src("abuseipdb", confidence=25)})["verdict"] == "SUSPICIOUS"
    assert rep.compute_verdict({"abuseipdb": src("abuseipdb", confidence=24)})["verdict"] == "CLEAN"


def test_verdict_virustotal_boundaries():
    assert rep.compute_verdict({"virustotal": src("virustotal", malicious=3)})["verdict"] == "MALICIOUS"
    assert rep.compute_verdict({"virustotal": src("virustotal", malicious=2)})["verdict"] == "SUSPICIOUS"
    assert rep.compute_verdict({"virustotal": src("virustotal", malicious=1)})["verdict"] == "SUSPICIOUS"
    assert rep.compute_verdict({"virustotal": src("virustotal", malicious=0)})["verdict"] == "CLEAN"


def test_verdict_otx_and_threatfox_and_greynoise():
    assert rep.compute_verdict({"otx": src("otx", pulse_count=3)})["verdict"] == "MALICIOUS"
    assert rep.compute_verdict({"otx": src("otx", pulse_count=2)})["verdict"] == "SUSPICIOUS"
    assert rep.compute_verdict({"threatfox": src("threatfox", matched=True)})["verdict"] == "MALICIOUS"
    assert rep.compute_verdict({}, greynoise_malicious=True)["verdict"] == "SUSPICIOUS"


def test_verdict_clean_when_nothing_flags():
    v = rep.compute_verdict({"abuseipdb": src("abuseipdb", confidence=0),
                             "virustotal": src("virustotal", malicious=0)})
    assert v["verdict"] == "CLEAN"


def test_verdict_reasoning_lists_sources():
    v = rep.compute_verdict({"abuseipdb": src("abuseipdb", confidence=100),
                             "virustotal": src("virustotal", malicious=7)})
    assert v["verdict"] == "MALICIOUS"
    assert "AbuseIPDB 100%" in v["reasoning"] and "VirusTotal 7" in v["reasoning"]


def test_failed_source_ignored_in_verdict():
    # an errored source contributes nothing
    assert rep.compute_verdict({"abuseipdb": src("abuseipdb", ok=False, confidence=100)})["verdict"] == "CLEAN"


# ---------- geo consensus ----------

def _s(name, country):
    return {"source": name, "ok": True, "state": "ok", "data": {}, "error": None, "country": country}


def test_geo_agreement():
    g = rep.compute_geo({"abuseipdb": _s("abuseipdb", "US"), "virustotal": _s("virustotal", "US")},
                        existing_country="US", network_name="Comcast")
    assert g["agreement"] is True and list(g["countries"].keys()) == ["US"]


def test_geo_disagreement_and_hosting():
    sources = {"abuseipdb": _s("abuseipdb", "LT"), "virustotal": _s("virustotal", "IR"),
               "otx": _s("otx", "US")}
    g = rep.compute_geo(sources, existing_country="IR", network_name="Contabo GmbH hosting")
    assert g["agreement"] is False
    assert set(g["countries"].keys()) == {"LT", "IR", "US"}
    assert "virustotal" in g["countries"]["IR"] and "geolocation" in g["countries"]["IR"]
    assert g["is_hosting_asn"] is True


# ---------- port merge ----------

def _censys(ports):
    return {"source": "censys", "ok": True, "state": "ok",
            "data": {"ports": ports}, "error": None, "country": None}


def test_port_merge_dedup_and_tag():
    m = rep.merge_ports([22, 80], _censys([{"port": 22, "service": "SSH"}, {"port": 443, "service": "HTTPS"}]))
    by_port = {p["port"]: p for p in m["ports"]}
    assert by_port[22]["sources"] == ["shodan", "censys"]
    assert by_port[80]["sources"] == ["shodan"]
    assert by_port[443]["sources"] == ["censys"] and by_port[443]["service"] == "HTTPS"
    assert set(m["consulted"]) == {"Shodan InternetDB", "Censys"} and m["empty"] is False


def test_port_merge_empty_only_when_both_empty():
    m = rep.merge_ports([], _censys([]))
    assert m["empty"] is True and set(m["consulted"]) == {"Shodan InternetDB", "Censys"}


def test_port_merge_shodan_failed_not_consulted():
    m = rep.merge_ports(None, _censys([{"port": 22, "service": "SSH"}]))
    assert m["consulted"] == ["Censys"] and [p["port"] for p in m["ports"]] == [22]
