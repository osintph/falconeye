"""Tests for the Mailgun send service (mocked) and the send endpoint auth."""
import asyncio

import bcrypt
import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.abuse import routes as abuse_routes
from app.abuse import send
from app.abuse import store


# ---------- fake httpx ----------

class _FakeResp:
    def __init__(self, status, payload=None, text=""):
        self.status_code = status
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, resp=None, raise_exc=None, calls=None):
        self._resp = resp
        self._raise = raise_exc
        self._calls = calls if calls is not None else []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, auth=None, data=None):
        self._calls.append({"url": url, "auth": auth, "data": data})
        if self._raise is not None:
            raise self._raise
        return self._resp


def _mailgun_env(monkeypatch, key="test-key"):
    monkeypatch.setenv("MAILGUN_API_KEY", key)
    monkeypatch.setenv("MAILGUN_DOMAIN", "email.example.com")
    monkeypatch.setenv("MAILGUN_FROM", "reports@email.example.com")
    monkeypatch.setenv("MAILGUN_REGION", "eu")


def _seed_recipient(email="abuse@prov.example"):
    store.store_cached_contact("1.2.3.4", "ip", email, "PROV-NET", {"abuse_email": email})


_COMPOSED = {
    "subject": "Abuse Report: Spam from 1.2.3.4",
    "body_text": "report body",
    "reporter_email": "reporter@osintph.info",
    "category": "spam",
    "target": "1.2.3.4",
    "target_type": "ip",
}


def test_region_normalization_handles_inline_comment():
    assert send._norm_region("eu   # or us") == "eu"
    assert send._norm_region("us") == "us"
    assert send._norm_region("") == "us"
    assert send._norm_region("garbage") == "us"


def test_send_success_inserts_audit(monkeypatch):
    _mailgun_env(monkeypatch)
    _seed_recipient()
    calls = []
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda *a, **k: _FakeClient(resp=_FakeResp(200, {"id": "<msg-1@mg>"}), calls=calls),
    )
    res = asyncio.run(send.send_via_mailgun(_COMPOSED, "abuse@prov.example", "9.9.9.9"))
    assert res["sent"] is True
    assert res["mailgun_message_id"] == "<msg-1@mg>"
    assert len(calls) == 1
    # EU region endpoint selected
    assert calls[0]["url"].startswith("https://api.eu.mailgun.net/v3/email.example.com/messages")
    # audit row written
    conn = store._connect()
    n = conn.execute("SELECT COUNT(*) FROM abuse_send_audit WHERE success = 1").fetchone()[0]
    conn.close()
    assert n == 1


def test_send_is_not_rate_limited(monkeypatch):
    """v3.8.3: send is admin-only + single-user, so it is NOT rate-limited.
    Repeated sends to the same recipient all succeed and never set rate_limited,
    and nothing is written to abuse_send_rate_limit."""
    _mailgun_env(monkeypatch)
    _seed_recipient()
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda *a, **k: _FakeClient(resp=_FakeResp(200, {"id": "<m@mg>"})),
    )
    for _ in range(5):
        r = asyncio.run(send.send_via_mailgun(_COMPOSED, "abuse@prov.example", "1.1.1.1"))
        assert r["sent"] is True
        assert r["rate_limited"] is False
    # the rate-limit table is left in place but must not be written to
    conn = store._connect()
    rows = conn.execute("SELECT COUNT(*) FROM abuse_send_rate_limit").fetchone()[0]
    conn.close()
    assert rows == 0


def test_send_rejects_recipient_not_in_cache(monkeypatch):
    _mailgun_env(monkeypatch)
    # deliberately do NOT seed the recipient
    called = {"n": 0}

    def _factory(*a, **k):
        called["n"] += 1
        return _FakeClient(resp=_FakeResp(200, {"id": "x"}))

    monkeypatch.setattr(httpx, "AsyncClient", _factory)
    res = asyncio.run(send.send_via_mailgun(_COMPOSED, "stranger@nowhere.example", "1.1.1.1"))
    assert res["sent"] is False
    assert "RDAP" in (res["error"] or "")
    assert called["n"] == 0  # never contacted Mailgun


def test_api_key_never_leaks_on_error(monkeypatch):
    secret = "supersecret-key-abc123"
    _mailgun_env(monkeypatch, key=secret)
    _seed_recipient()
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda *a, **k: _FakeClient(raise_exc=RuntimeError(f"boom {secret}")),
    )
    res = asyncio.run(send.send_via_mailgun(_COMPOSED, "abuse@prov.example", "1.1.1.1"))
    assert res["sent"] is False
    assert secret not in (res["error"] or "")
    # a failed attempt is still audited
    conn = store._connect()
    n = conn.execute("SELECT COUNT(*) FROM abuse_send_audit WHERE success = 0").fetchone()[0]
    conn.close()
    assert n == 1


# ---------- send endpoint auth ----------

def _client():
    app = FastAPI()
    app.state.limiter = abuse_routes.limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(abuse_routes.router)
    return TestClient(app)


def test_send_endpoint_never_returns_401(monkeypatch):
    """v3.8.1 regression: /api/abuse/send must never return HTTP 401 or emit
    WWW-Authenticate — that pops the browser's Basic Auth dialog, which races the
    in-page credential form and rejects correct passwords."""
    monkeypatch.setenv("FALCONEYE_ABUSE_ADMIN_USER", "admin")
    monkeypatch.setenv("FALCONEYE_ABUSE_ADMIN_PASS_HASH",
                       bcrypt.hashpw(b"correct horse", bcrypt.gensalt()).decode())
    c = _client()

    def _no_basic_auth(r):
        assert r.status_code != 401
        assert "www-authenticate" not in {k.lower() for k in r.headers.keys()}

    # No credentials at all
    r = c.post("/api/abuse/send", json={"composed": _COMPOSED, "recipient_email": "abuse@prov.example"})
    _no_basic_auth(r)
    assert r.json()["sent"] is False and "invalid" in r.json()["error"].lower()

    # Wrong password in the body
    r = c.post("/api/abuse/send", json={
        "composed": _COMPOSED, "recipient_email": "abuse@prov.example",
        "admin_user": "admin", "admin_password": "wrong-password",
    })
    _no_basic_auth(r)
    assert r.json()["sent"] is False and "invalid" in r.json()["error"].lower()

    # Wrong username in the body
    r = c.post("/api/abuse/send", json={
        "composed": _COMPOSED, "recipient_email": "abuse@prov.example",
        "admin_user": "nope", "admin_password": "correct horse",
    })
    _no_basic_auth(r)
    assert r.json()["sent"] is False and "invalid" in r.json()["error"].lower()


def test_send_endpoint_unconfigured_returns_200_not_503(monkeypatch):
    monkeypatch.delenv("FALCONEYE_ABUSE_ADMIN_USER", raising=False)
    monkeypatch.delenv("FALCONEYE_ABUSE_ADMIN_PASS_HASH", raising=False)
    c = _client()
    r = c.post("/api/abuse/send", json={
        "composed": _COMPOSED, "recipient_email": "abuse@prov.example",
        "admin_user": "admin", "admin_password": "whatever",
    })
    assert r.status_code == 200
    assert r.json()["sent"] is False and "not configured" in r.json()["error"].lower()


def test_send_endpoint_valid_creds_reach_send_service(monkeypatch):
    """Correct body creds pass the gate and reach the send service; wrong ones don't."""
    monkeypatch.setenv("FALCONEYE_ABUSE_ADMIN_USER", "admin")
    monkeypatch.setenv("FALCONEYE_ABUSE_ADMIN_PASS_HASH",
                       bcrypt.hashpw(b"s3cret-pw", bcrypt.gensalt()).decode())
    called = {"n": 0}

    async def fake_send(composed, recipient, client_ip):
        called["n"] += 1
        return {"sent": True, "mailgun_message_id": "<m@mg>", "error": None, "rate_limited": False}

    monkeypatch.setattr(abuse_routes.send_mod, "send_via_mailgun", fake_send)
    c = _client()

    r = c.post("/api/abuse/send", json={
        "composed": _COMPOSED, "recipient_email": "a@b.com",
        "admin_user": "admin", "admin_password": "nope",
    })
    assert r.json()["sent"] is False and called["n"] == 0

    r = c.post("/api/abuse/send", json={
        "composed": _COMPOSED, "recipient_email": "a@b.com",
        "admin_user": "admin", "admin_password": "s3cret-pw",
    })
    assert r.status_code == 200 and r.json()["sent"] is True and called["n"] == 1
