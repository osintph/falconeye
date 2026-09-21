"""Consensus verdict thresholds, geo consensus, and port merge."""
from app.ip_sources import reputation as rep

ALL = ("abuseipdb", "virustotal", "otx", "censys", "threatfox")


def src(name, ok=True, **data):
    return {"source": name, "ok": ok, "state": "ok" if ok else "error",
            "data": data, "error": None, "country": data.pop("_country", None)}


def full(**overrides):
    """All five sources present and quiet, with the named ones overridden.

    Threshold tests need complete coverage, because since v3.33.2 a source that
    is absent or errored makes the verdict INCOMPLETE rather than CLEAN. These
    tests are about where the thresholds sit, so they supply full coverage and
    let test_coverage below own the unavailable cases.
    """
    sources = {
        "abuseipdb": src("abuseipdb", confidence=0, total_reports=0),
        "virustotal": src("virustotal", malicious=0),
        "otx": src("otx", pulse_count=0),
        "censys": src("censys", ports=[]),
        "threatfox": src("threatfox", matched=False),
    }
    sources.update(overrides)
    return sources


# ---------- verdict thresholds ----------

def test_verdict_abuseipdb_boundaries():
    def v(c):
        return rep.compute_verdict(full(abuseipdb=src("abuseipdb", confidence=c)))["verdict"]
    assert v(75) == "MALICIOUS"
    assert v(74) == "SUSPICIOUS"
    assert v(25) == "SUSPICIOUS"
    assert v(24) == "CLEAN"


def test_verdict_virustotal_boundaries():
    def v(m):
        return rep.compute_verdict(full(virustotal=src("virustotal", malicious=m)))["verdict"]
    assert v(3) == "MALICIOUS"
    assert v(2) == "SUSPICIOUS"
    assert v(1) == "SUSPICIOUS"
    assert v(0) == "CLEAN"


def test_verdict_otx_and_threatfox_and_greynoise():
    assert rep.compute_verdict(full(otx=src("otx", pulse_count=3)))["verdict"] == "MALICIOUS"
    assert rep.compute_verdict(full(otx=src("otx", pulse_count=2)))["verdict"] == "SUSPICIOUS"
    assert rep.compute_verdict(full(threatfox=src("threatfox", matched=True)))["verdict"] == "MALICIOUS"
    # GreyNoise is not one of the five keyed sources, so it can raise a verdict
    # off an otherwise complete set.
    assert rep.compute_verdict(full(), greynoise_malicious=True)["verdict"] == "SUSPICIOUS"


def test_verdict_clean_when_nothing_flags():
    v = rep.compute_verdict(full())
    assert v["verdict"] == "CLEAN"
    assert v["sources_responded"] == 5


def test_verdict_reasoning_lists_sources():
    v = rep.compute_verdict(full(abuseipdb=src("abuseipdb", confidence=100),
                                 virustotal=src("virustotal", malicious=7)))
    assert v["verdict"] == "MALICIOUS"
    assert "AbuseIPDB 100%" in v["reasoning"] and "VirusTotal 7" in v["reasoning"]


def test_failed_source_contributes_no_signal_but_is_not_treated_as_clean():
    """Rewritten in v3.33.2. This test used to assert the bug.

    It asserted that an errored AbuseIPDB carrying confidence=100 produced
    "CLEAN", on the reasoning that a failed source "contributes nothing". The
    first half is right, a failed source must not contribute its payload as a
    signal. The second half was the defect: contributing no signal is not the
    same as confirming the IP is clean, and the card said "No source flagged
    this IP" when the source had in fact never answered.
    """
    v = rep.compute_verdict(full(abuseipdb=src("abuseipdb", ok=False, confidence=100)))
    # The failed source's payload is still ignored: no MALICIOUS off a 100 it
    # never successfully returned.
    assert v["verdict"] != "MALICIOUS"
    # But its absence is reported, not silently counted as a clean bill.
    assert v["verdict"] == "INCOMPLETE"
    assert v["sources_responded"] == 4
    assert [u["source"] for u in v["sources_unavailable"]] == ["abuseipdb"]


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
