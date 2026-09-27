"""A failure is not an answer, so it does not get a six hour cache entry.

Origin: every tab that caches stores one blob per target, and a source that
timed out, hit a quota, returned a 5xx or had no key yet was stored inside that
blob exactly like a source that answered. The row then satisfied the next
lookup, so the failure was served for the rest of the TTL: six hours on the IP
and Domain tabs, six on the email analysis, thirty minutes on Threat Pulse.

The consequences were not subtle. An operator who added an API key was served
the keyless answer for hours (the reported case that produced Refresh in
v3.33.0). An upstream that had a two minute blip pinned "unavailable" on the
card until the afternoon. A failed LLM call was cached without spending the
daily cap, so the retry that would have worked was never made.

The rule now: a result with ok=false is never written to the long cache. It is
written with a stamp instead, and once that stamp is older than
NEGATIVE_TTL_SECONDS the reader drops it and the caller re-attempts. The short
window exists only so that a hammered tab does not hammer a down upstream, and
it is bounded at a minute.

These tests cover the mechanism and the four caches that store per-source
results. They are deliberately written against the bug class, "a failure gets
the long TTL", rather than against the one source that prompted it.
"""
import json
import os
import sqlite3
import time

os.environ.setdefault("FALCONEYE_DB", "/tmp/falconeye_test.db")

import pytest

from app.utils import cache


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "negcache.db")
    monkeypatch.setattr(cache, "DB_PATH", path)
    return path


# ---------------- the mechanism ----------------

def test_the_negative_window_is_at_most_a_minute():
    assert 0 < cache.NEGATIVE_TTL_SECONDS <= 60


def test_failures_are_stamped_and_taken_off_the_response():
    response = {"sources": {"otx": {"ok": False}}, "verdict": "INCOMPLETE"}
    cache.note_failures(response, ["otx"])
    assert cache.FAILURES_KEY in response

    failures = cache.take_failures(response)
    assert set(failures) == {"otx"}
    assert isinstance(failures["otx"], (int, float))
    # Bookkeeping is ours, not the API's: it must not reach a caller.
    assert cache.FAILURES_KEY not in response


def test_take_failures_on_a_response_without_any_is_empty():
    response = {"sources": {}}
    assert cache.take_failures(response) == {}
    assert response == {"sources": {}}


def test_a_fresh_failure_is_not_retried_yet():
    """The negative window is the only thing standing between a hammered tab
    and a hammered upstream."""
    failures = {"otx": time.time()}
    assert cache.stale_failures(failures) == []


def test_a_failure_older_than_the_window_is_retried():
    failures = {"otx": time.time() - cache.NEGATIVE_TTL_SECONDS - 1}
    assert cache.stale_failures(failures) == ["otx"]


def test_every_failure_older_than_the_window_is_named():
    now = time.time()
    failures = {
        "otx": now - 600,
        "virustotal": now,
        "abuseipdb": now - cache.NEGATIVE_TTL_SECONDS - 0.5,
    }
    assert sorted(cache.stale_failures(failures, now=now)) == ["abuseipdb", "otx"]


@pytest.mark.parametrize("stamp", [None, "yesterday", float("nan"), [], {}])
def test_an_unreadable_stamp_is_treated_as_stale(stamp):
    """A row written by an older version has no stamp at all. Retrying is the
    safe direction: the alternative is serving a failure forever."""
    assert cache.stale_failures({"otx": stamp}) == ["otx"]


def test_note_failures_is_additive_and_replaces_its_own_names():
    response = {}
    cache.note_failures(response, ["otx"], now=100.0)
    cache.note_failures(response, ["virustotal"], now=200.0)
    assert response[cache.FAILURES_KEY] == {"otx": 100.0, "virustotal": 200.0}
    cache.note_failures(response, ["otx"], now=300.0)
    assert response[cache.FAILURES_KEY]["otx"] == 300.0


def test_note_failures_with_nothing_failed_writes_no_key():
    response = {"a": 1}
    cache.note_failures(response, [])
    assert cache.FAILURES_KEY not in response


# ---------------- update_blob keeps the long TTL honest ----------------

def test_update_blob_replaces_the_payload_but_not_the_age(db):
    cache.init_table("t_cache", key_col="id")
    cache.set("t_cache", "k", {"v": 1}, key_col="id")

    conn = sqlite3.connect(db)
    conn.execute("UPDATE t_cache SET fetched_at = datetime('now', '-5 hours') WHERE id = 'k'")
    conn.commit()
    before = conn.execute("SELECT fetched_at FROM t_cache WHERE id = 'k'").fetchone()[0]
    conn.close()

    cache.update_blob("t_cache", "k", {"v": 2}, key_col="id")

    conn = sqlite3.connect(db)
    row = conn.execute("SELECT response_json, fetched_at FROM t_cache WHERE id = 'k'").fetchone()
    conn.close()
    assert json.loads(row[0])["v"] == 2
    assert row[1] == before, (
        "a partial retry reset the row's age, so a source that keeps failing "
        "would extend the six hour cache forever"
    )


def test_update_blob_on_a_missing_row_does_nothing(db):
    cache.init_table("t_cache", key_col="id")
    cache.update_blob("t_cache", "absent", {"v": 1}, key_col="id")
    assert cache.get("t_cache", "absent", 6, key_col="id") is None


def test_a_row_whose_failures_keep_being_retried_still_expires(db):
    """The whole point of preserving fetched_at."""
    cache.init_table("t_cache", key_col="id")
    response = {"v": 1}
    cache.note_failures(response, ["otx"])
    cache.set("t_cache", "k", response, key_col="id")

    conn = sqlite3.connect(db)
    conn.execute("UPDATE t_cache SET fetched_at = datetime('now', '-7 hours') WHERE id = 'k'")
    conn.commit()
    conn.close()

    cache.update_blob("t_cache", "k", {"v": 2}, key_col="id")
    assert cache.get("t_cache", "k", 6, key_col="id") is None   # still expired


# ---------------- Threat Pulse: a failed feed is not pinned for the TTL ----------------

def _pulse_row(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT response_json FROM threat_pulse_cache WHERE id = 'ph'").fetchone()
    conn.close()
    return json.loads(row["response_json"]) if row else None


def test_threat_pulse_does_not_hammer_a_down_feed(monkeypatch, tmp_path):
    """The one tab that already avoided caching a failure, and paid for it by
    re-querying a dead feed on every single request (30/minute per IP)."""
    import asyncio
    import sqlite3 as _sq

    from app.routers import threat_pulse as tp
    tp.limiter.enabled = False

    path = str(tmp_path / "pulse.db")
    monkeypatch.setattr(cache, "DB_PATH", path)
    cache.init_table("threat_pulse_cache", key_col="id")

    calls = []

    async def failing_feed():
        calls.append("fail")
        return []

    monkeypatch.setattr(tp, "fetch_urlhaus_ph_feed", failing_feed)

    conn = _sq.connect(path)
    conn.row_factory = _sq.Row

    first = asyncio.run(tp.threat_pulse(_FakeRequest(), db=conn))
    assert len(calls) == 1
    assert first.get("error")
    # A failure is still never written into the answer row.
    assert _pulse_row(path) is None
    assert cache.FAILURES_KEY not in first, "bookkeeping leaked into the API response"

    # Inside the window the feed is left alone.
    second = asyncio.run(tp.threat_pulse(_FakeRequest(), db=conn))
    assert len(calls) == 1, "a down feed was re-queried inside the negative window"
    assert second.get("error")

    # Past the window it is re-attempted.
    monkeypatch.setattr(cache, "NEGATIVE_TTL_SECONDS", 0)
    asyncio.run(tp.threat_pulse(_FakeRequest(), db=conn))
    assert len(calls) == 2
    conn.close()


def test_threat_pulse_success_clears_the_negative_window(monkeypatch, tmp_path):
    import asyncio
    import sqlite3 as _sq

    from app.routers import threat_pulse as tp
    tp.limiter.enabled = False

    path = str(tmp_path / "pulse2.db")
    monkeypatch.setattr(cache, "DB_PATH", path)
    cache.init_table("threat_pulse_cache", key_col="id")

    state = {"fail": True}

    async def feed():
        if state["fail"]:
            return []
        return [{"url": "http://x.example/a", "url_status": "online",
                 "dateadded": "2026-01-01 00:00:00", "threat": "malware_download",
                 "urlhaus_link": ""}]

    monkeypatch.setattr(tp, "fetch_urlhaus_ph_feed", feed)
    monkeypatch.setattr(cache, "NEGATIVE_TTL_SECONDS", 0)

    conn = _sq.connect(path)
    conn.row_factory = _sq.Row
    asyncio.run(tp.threat_pulse(_FakeRequest(), db=conn))
    state["fail"] = False
    good = asyncio.run(tp.threat_pulse(_FakeRequest(), db=conn))
    assert good["total_tracked"] == 1
    assert not good.get("error")
    conn.close()


class _FakeRequest:
    headers: dict = {}
    client = None


# ---------------- Domain Intel: per-component retry ----------------

def test_domain_intel_retries_only_the_failed_component(monkeypatch, tmp_path):
    import asyncio
    import sqlite3 as _sq

    from app.routers import domain_intel as di
    di.limiter.enabled = False

    path = str(tmp_path / "domain.db")
    monkeypatch.setattr(di, "DB_PATH", path)
    monkeypatch.setattr(cache, "DB_PATH", path)
    di._init_cache()

    conn = _sq.connect(path)
    conn.row_factory = _sq.Row

    calls = {"rdap": 0, "ct": 0, "dns": 0}

    async def rdap(client, domain):
        calls["rdap"] += 1
        return None if calls["rdap"] == 1 else {"handle": "H", "ldhName": domain}

    async def ct(client, domain):
        calls["ct"] += 1
        return {"certificates": [], "subdomains": [], "source": "crt.sh", "error": None}

    async def dns(domain):
        calls["dns"] += 1
        return {rt: [] for rt in di.DNS_RECORD_TYPES} | {"resolved_ips": [], "ptr_records": {}}

    async def whois(domain):
        return None

    monkeypatch.setattr(di, "fetch_rdap", rdap)
    monkeypatch.setattr(di, "fetch_ct", ct)
    monkeypatch.setattr(di, "fetch_dns", dns)
    monkeypatch.setattr(di, "fetch_whois", whois)
    monkeypatch.setattr(di.hudsonrock, "lookup_domain", _none)

    first = asyncio.run(di.lookup_domain(_FakeRequest(), "example.com", db=conn))
    assert first["rdap"] is None
    assert calls == {"rdap": 1, "ct": 1, "dns": 1}

    # Inside the negative window the failure is served from cache.
    asyncio.run(di.lookup_domain(_FakeRequest(), "example.com", db=conn))
    assert calls == {"rdap": 1, "ct": 1, "dns": 1}

    # Past it, RDAP alone is re-attempted; CT and DNS are not re-queried.
    monkeypatch.setattr(cache, "NEGATIVE_TTL_SECONDS", 0)
    second = asyncio.run(di.lookup_domain(_FakeRequest(), "example.com", db=conn))
    assert calls == {"rdap": 2, "ct": 1, "dns": 1}, (
        "a partial retry re-queried components that had already answered"
    )
    assert second["rdap"]["handle"] == "H"
    assert second["cache_hit"] is True
    assert cache.FAILURES_KEY not in second
    conn.close()


async def _none(*a, **k):
    return None


# ---------------- Email analysis: a failed LLM call is free to retry ----------------

_HEADER = (
    "From: Finance <billing@vendor.example>\n"
    "To: ap@company.example\n"
    "Subject: Updated bank details\n"
    "Date: Mon, 1 Sep 2026 09:00:00 +0800\n"
)
_BODY = (
    "Please note our bank account has changed. Wire the outstanding invoice to "
    "the new account today and confirm by reply. This is urgent and confidential."
)


def _email_case(monkeypatch, tmp_path, name):
    from app.routers import email_header as eh

    path = str(tmp_path / f"{name}.db")
    monkeypatch.setattr(cache, "DB_PATH", path)
    monkeypatch.setattr(eh, "DB_PATH", path)
    eh._init_cache()

    monkeypatch.setattr(eh, "LLM_ANALYSIS_ENABLED", True)
    monkeypatch.setattr(eh, "ANTHROPIC_API_KEY", "key-not-real")
    monkeypatch.setattr(eh, "_check_llm_rate_limit", lambda ip: (True, 0))
    monkeypatch.setattr(eh, "_record_llm_call", lambda ip: None)
    monkeypatch.setattr(eh.hudsonrock, "lookup_email", _none)
    # No DNS from a unit test.
    monkeypatch.setattr(eh, "_resolve_txt", _empty_list)
    monkeypatch.setattr(eh, "_lookup_reverse_dns", _none)
    monkeypatch.setattr(eh, "_enrich_ip", _empty_dict)
    return eh


async def _empty_list(*a, **k):
    return []


async def _empty_dict(*a, **k):
    return {}


def test_a_failed_llm_call_is_not_pinned_for_the_cache_ttl(monkeypatch, tmp_path):
    """It was cached without spending the daily cap, so the retry that would
    have worked was never made."""
    import asyncio

    eh = _email_case(monkeypatch, tmp_path, "email_llm")
    calls = []

    async def llm(body, sender_email=""):
        calls.append(sender_email)
        return None if len(calls) == 1 else {"scam_score": 80, "verdict": "scam",
                                            "scam_type": "bec", "summary": "s",
                                            "findings": []}

    monkeypatch.setattr(eh, "_llm_analyze_body", llm)
    req = eh.HeaderAnalyzeRequest(raw_header=_HEADER, raw_body=_BODY)

    first = asyncio.run(eh.analyze(req, _FakeRequest()))
    assert first["llm_analysis"] is None
    assert len(calls) == 1
    assert cache.FAILURES_KEY not in first

    # Inside the negative window the cached answer stands, no second LLM call.
    second = asyncio.run(eh.analyze(req, _FakeRequest()))
    assert second["cache_hit"] is True
    assert len(calls) == 1

    # Past it, the analysis is re-run and the LLM verdict finally lands.
    monkeypatch.setattr(cache, "NEGATIVE_TTL_SECONDS", 0)
    third = asyncio.run(eh.analyze(req, _FakeRequest()))
    assert len(calls) == 2
    assert third["llm_analysis"]["verdict"] == "scam"
    assert third["bec_assessment"]["llm_contributed"] is True
    assert cache.FAILURES_KEY not in third


def test_a_successful_analysis_is_cached_for_the_full_ttl(monkeypatch, tmp_path):
    """The negative window must not turn every cache into a one minute cache."""
    import asyncio

    eh = _email_case(monkeypatch, tmp_path, "email_ok")
    calls = []

    async def llm(body, sender_email=""):
        calls.append(sender_email)
        return {"scam_score": 10, "verdict": "unclear", "scam_type": "",
                "summary": "", "findings": []}

    monkeypatch.setattr(eh, "_llm_analyze_body", llm)
    monkeypatch.setattr(cache, "NEGATIVE_TTL_SECONDS", 0)
    req = eh.HeaderAnalyzeRequest(raw_header=_HEADER, raw_body=_BODY)

    asyncio.run(eh.analyze(req, _FakeRequest()))
    again = asyncio.run(eh.analyze(req, _FakeRequest()))
    assert again["cache_hit"] is True
    assert len(calls) == 1, "a successful analysis was re-run from the cache"


def test_a_rate_limited_llm_call_is_not_treated_as_a_failure(monkeypatch, tmp_path):
    """Being over the daily cap is a decision, not an outage: retrying in a
    minute would spend nothing and change nothing."""
    import asyncio

    eh = _email_case(monkeypatch, tmp_path, "email_rl")
    monkeypatch.setattr(eh, "_check_llm_rate_limit", lambda ip: (False, 10))
    calls = []

    async def llm(body, sender_email=""):
        calls.append(sender_email)
        return None

    monkeypatch.setattr(eh, "_llm_analyze_body", llm)
    monkeypatch.setattr(cache, "NEGATIVE_TTL_SECONDS", 0)
    req = eh.HeaderAnalyzeRequest(raw_header=_HEADER, raw_body=_BODY)

    first = asyncio.run(eh.analyze(req, _FakeRequest()))
    assert first["llm_analysis"]["rate_limited"] is True
    again = asyncio.run(eh.analyze(req, _FakeRequest()))
    assert again["cache_hit"] is True, "an over-cap analysis was re-run"
    assert calls == []
