"""An unavailable reputation source is not a clean one.

Origin: an IP with an AbuseIPDB confidence of 24 over 8 reports rendered as
CLEAN, "No source flagged this IP". The threshold was one part of that; the
other, and the more dangerous one, is that `compute_verdict` read a source's
value only when `ok` was true, and every threshold test was `if x is not None`.
A source with no key, an error, a timeout or an exhausted quota therefore
produced `None` and was indistinguishable from a source that answered and found
nothing. The verdict then asserted that nothing had flagged the IP, when in
truth nothing had been asked.

All five keys happen to be set on the production instance, so this only bit on
a quota exhaustion or an outage, silently, in the direction of "looks clean".

The tests below cover the three states named in the brief: nothing configured,
one source down, everything up. Plus the case that must NOT change: a positive
hit still stands on its own even when another source is missing.
"""
import logging

import pytest

from app.ip_sources import reputation
from app.ip_sources.base import ERROR, NO_KEY, OK, QUOTA, SourceResult


def _src(name, *, ok=True, state=OK, data=None, error=None):
    return SourceResult(name, ok, state, data or {}, error).as_dict()


def _all_quiet():
    """Every source answered, none of them flagged anything."""
    return {
        "abuseipdb": _src("abuseipdb", data={"confidence": 0, "total_reports": 0}),
        "virustotal": _src("virustotal", data={"malicious": 0}),
        "otx": _src("otx", data={"pulse_count": 0}),
        "censys": _src("censys", data={"ports": []}),
        "threatfox": _src("threatfox", data={"matched": False}),
    }


# ---------- all up ----------

def test_all_sources_up_and_quiet_is_clean():
    v = reputation.compute_verdict(_all_quiet())
    assert v["verdict"] == reputation.CLEAN
    assert v["sources_responded"] == 5
    assert v["sources_total"] == 5
    assert v["sources_unavailable"] == []
    assert "5 of 5" in v["coverage_note"]
    # The wording must say the coverage was complete, not merely that nothing fired.
    assert "All 5 sources responded" in v["reasoning"]


# ---------- one source down ----------

@pytest.mark.parametrize("state,error", [
    (ERROR, "ConnectTimeout"),
    (QUOTA, "daily quota reached"),
    (NO_KEY, "no API key configured"),
    (ERROR, "HTTP 503"),
])
def test_one_source_down_is_never_clean(state, error):
    sources = _all_quiet()
    sources["virustotal"] = _src("virustotal", ok=False, state=state, error=error)

    v = reputation.compute_verdict(sources)
    assert v["verdict"] != reputation.CLEAN, (
        f"a source in state {state!r} was counted as 'did not flag'. An "
        "unavailable source is not a clean one."
    )
    assert v["verdict"] == reputation.INCOMPLETE
    assert v["sources_responded"] == 4
    assert "4 of 5" in v["coverage_note"]
    # The missing source has to be named, not just counted.
    names = [u["source"] for u in v["sources_unavailable"]]
    assert names == ["virustotal"]
    assert "VirusTotal" in v["reasoning"]
    assert state in v["reasoning"]


def test_incomplete_still_reports_that_nothing_responding_flagged_it():
    sources = _all_quiet()
    sources["otx"] = _src("otx", ok=False, state=ERROR, error="boom")
    v = reputation.compute_verdict(sources)
    assert "Nothing that did respond flagged this IP" in v["reasoning"]


# ---------- nothing configured ----------

def test_no_sources_configured_is_incomplete_not_clean():
    sources = {n: _src(n, ok=False, state=NO_KEY, error="no API key configured")
               for n in ("abuseipdb", "virustotal", "otx", "censys", "threatfox")}
    v = reputation.compute_verdict(sources)
    assert v["verdict"] == reputation.INCOMPLETE
    assert v["sources_responded"] == 0
    assert "0 of 5" in v["coverage_note"]
    assert len(v["sources_unavailable"]) == 5


def test_configured_sources_reports_what_is_missing(monkeypatch):
    for env in ("ABUSEIPDB_KEY", "VT_KEY", "OTX_API_KEY", "CENSYS_PAT", "ABUSECH_AUTH_KEY"):
        monkeypatch.delenv(env, raising=False)
    cfg = reputation.configured_sources()
    assert cfg["none_configured"] is True
    assert cfg["configured"] == 0 and cfg["total"] == 5
    # Each entry names the env var an operator has to set, for the .env pointer.
    assert {m["env"] for m in cfg["missing"]} == {
        "ABUSEIPDB_KEY", "VT_KEY", "OTX_API_KEY", "CENSYS_PAT", "ABUSECH_AUTH_KEY"}


def test_configured_sources_sees_a_configured_key(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_KEY", "test-key-not-real")
    for env in ("VT_KEY", "OTX_API_KEY", "CENSYS_PAT", "ABUSECH_AUTH_KEY"):
        monkeypatch.delenv(env, raising=False)
    cfg = reputation.configured_sources()
    assert cfg["configured"] == 1
    assert cfg["none_configured"] is False
    assert "abuseipdb" not in {m["source"] for m in cfg["missing"]}


# ---------- a positive hit is not masked by a missing source ----------

def test_a_real_hit_still_wins_when_another_source_is_down():
    sources = _all_quiet()
    sources["censys"] = _src("censys", ok=False, state=ERROR, error="timeout")
    sources["abuseipdb"] = _src("abuseipdb", data={"confidence": 90, "total_reports": 40})
    v = reputation.compute_verdict(sources)
    assert v["verdict"] == reputation.MALICIOUS
    # Coverage is still reported, so the operator knows it is 4 of 5.
    assert v["sources_responded"] == 4
    assert v["sources_unavailable"][0]["source"] == "censys"


# ---------- the structured log line ----------

def test_source_call_logs_one_structured_line(caplog):
    with caplog.at_level(logging.INFO, logger="falconeye.ip_sources"):
        reputation.log_source_call("abuseipdb", "203.0.113.5", "ok", 142, False)
    assert len(caplog.records) == 1
    msg = caplog.records[0].getMessage()
    for field in ("event=ip_source", "source=abuseipdb", "target=203.0.113.5",
                  "status=ok", "latency_ms=142", "cached=false"):
        assert field in msg, f"{field!r} missing from the log line: {msg}"


def test_cache_hit_replays_a_line_per_source(caplog):
    """A cached answer must not be a silent one: it is most lookups."""
    with caplog.at_level(logging.INFO, logger="falconeye.ip_sources"):
        reputation.log_cached_sources("203.0.113.5", _all_quiet())
    assert len(caplog.records) == 5
    for rec in caplog.records:
        assert "cached=true" in rec.getMessage()
    sources = {r.getMessage().split("source=")[1].split(" ")[0] for r in caplog.records}
    assert sources == {"abuseipdb", "virustotal", "otx", "censys", "threatfox"}


def test_an_unavailable_source_still_logs_its_state(caplog):
    sources = _all_quiet()
    sources["otx"] = _src("otx", ok=False, state=QUOTA, error="daily quota reached")
    with caplog.at_level(logging.INFO, logger="falconeye.ip_sources"):
        reputation.log_cached_sources("203.0.113.5", sources)
    otx = [r.getMessage() for r in caplog.records if "source=otx" in r.getMessage()][0]
    assert f"status={QUOTA}" in otx
