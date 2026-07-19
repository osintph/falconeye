"""Checker: detection per engine/type, URL encoding, graceful failure, concurrency cap."""
import asyncio

from app.username import checker
from app.username.checker import CheckResult, build_url, _wmn_hit, _sherlock_hit
from app.username.parser import Site


def _wmn_site(**det):
    d = {"engine": "wmn", "e_code": 200, "e_string": "", "m_code": 404, "m_string": ""}
    d.update(det)
    return Site("W", "https://w.example/{account}", "Developer", d, ["wmn"], False, 2)


def _sher_site(**det):
    d = {"engine": "sherlock", "errorType": "status_code",
         "errorMsg": None, "errorCode": None, "errorUrl": None, "regexCheck": None}
    d.update(det)
    return Site("S", "https://s.example/{}", "Other", d, ["sherlock"], False, 1)


# ---- detection: WMN ----

def test_wmn_e_code_and_e_string():
    det = _wmn_site(e_code=200, e_string="avatar").detection
    assert _wmn_hit(det, 200, "...avatar...") is True
    assert _wmn_hit(det, 404, "...avatar...") is False      # wrong status
    assert _wmn_hit(det, 200, "nothing here") is False      # string absent


def test_wmn_m_string_negates():
    det = _wmn_site(e_code=200, e_string="", m_string="No such user").detection
    assert _wmn_hit(det, 200, "profile page") is True
    assert _wmn_hit(det, 200, "No such user") is False


# ---- detection: Sherlock ----

def test_sherlock_status_code():
    det = _sher_site(errorType="status_code").detection
    assert _sherlock_hit(det, 200, "", "") is True
    assert _sherlock_hit(det, 404, "", "") is False


def test_sherlock_status_code_with_errorcode():
    det = _sher_site(errorType="status_code", errorCode=404).detection
    assert _sherlock_hit(det, 200, "", "") is True
    assert _sherlock_hit(det, 404, "", "") is False


def test_sherlock_message_str_and_list():
    det = _sher_site(errorType="message", errorMsg="Not Found").detection
    assert _sherlock_hit(det, 200, "welcome", "") is True
    assert _sherlock_hit(det, 200, "Not Found", "") is False
    det2 = _sher_site(errorType="message", errorMsg=["404", "gone"]).detection
    assert _sherlock_hit(det2, 200, "here is the profile", "") is True
    assert _sherlock_hit(det2, 200, "it is gone", "") is False


def test_sherlock_response_url():
    det = _sher_site(errorType="response_url", errorUrl="https://s.example/").detection
    assert _sherlock_hit(det, 200, "", "") is True                                  # 200, not redirected
    assert _sherlock_hit(det, 302, "", "https://s.example/") is False               # redirected to error page
    assert _sherlock_hit(det, 302, "", "https://s.example/realprofile") is True     # redirected elsewhere


# ---- URL construction / encoding ----

def test_build_url_substitutes_verbatim():
    assert build_url(_wmn_site(), "a.b_c-d") == "https://w.example/a.b_c-d"
    assert build_url(_sher_site(), "a%20b") == "https://s.example/a%20b"


def test_check_one_url_encodes_defensively():
    # A space never passes router validation, but check_one still quote()s the
    # username before substitution — belt and braces.
    site = _wmn_site(e_code=200, e_string="")
    client = _FakeClient(_FakeResp(200, ""))
    r = asyncio.run(checker.check_one(client, site, "a b", {"w.example": (True, None)}))
    assert r.profile_url == "https://w.example/a%20b"


# ---- check_one graceful behavior ----

class _FakeResp:
    def __init__(self, status, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}


class _FakeClient:
    def __init__(self, resp=None, raise_exc=None):
        self._resp = resp
        self._raise = raise_exc
    async def get(self, url):
        if self._raise:
            raise self._raise
        return self._resp


def test_check_one_hit_and_profile_url():
    site = _wmn_site(e_code=200, e_string="avatar")
    client = _FakeClient(_FakeResp(200, "the avatar div"))
    r = asyncio.run(checker.check_one(client, site, "torvalds", {"w.example": (True, None)}))
    assert r.hit is True
    assert r.profile_url == "https://w.example/torvalds"


def test_check_one_blocked_host_no_fetch():
    site = _wmn_site()
    client = _FakeClient(raise_exc=AssertionError("must not fetch a blocked host"))
    r = asyncio.run(checker.check_one(client, site, "x", {"w.example": (False, "private")}))
    assert r.hit is False and "blocked" in r.error


def test_check_one_network_error_no_raise():
    site = _wmn_site(e_code=200, e_string="avatar")
    client = _FakeClient(raise_exc=RuntimeError("boom"))
    r = asyncio.run(checker.check_one(client, site, "x", {"w.example": (True, None)}))
    assert r.hit is False and r.error == "RuntimeError"


def test_sweep_respects_concurrency_cap(monkeypatch):
    # No DNS, no HTTP — just observe how many check_one run at once.
    monkeypatch.setattr(checker, "resolve_and_check", lambda host: [])
    state = {"cur": 0, "max": 0}

    async def fake_check_one(client, site, username, host_ok):
        state["cur"] += 1
        state["max"] = max(state["max"], state["cur"])
        await asyncio.sleep(0.01)
        state["cur"] -= 1
        return CheckResult(site, False, None, 200, None, 1)

    monkeypatch.setattr(checker, "check_one", fake_check_one)
    sites = [_wmn_site() for _ in range(60)]
    results, unchecked = asyncio.run(checker.sweep(sites, "user", concurrency=5, deadline_s=10))
    assert state["max"] <= 5
    assert len(results) == 60 and unchecked == 0
