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


def test_send_rate_limit_same_recipient(monkeypatch):
    _mailgun_env(monkeypatch)
    _seed_recipient()
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda *a, **k: _FakeClient(resp=_FakeResp(200, {"id": "<m@mg>"})),
    )
    r1 = asyncio.run(send.send_via_mailgun(_COMPOSED, "abuse@prov.example", "1.1.1.1"))
    assert r1["sent"] is True
    # different client IP so the per-IP limit isn't the cause — recipient 1/hour must block
    r2 = asyncio.run(send.send_via_mailgun(_COMPOSED, "abuse@prov.example", "2.2.2.2"))
    assert r2["sent"] is False
    assert r2["rate_limited"] is True


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


def test_send_endpoint_401_without_and_with_wrong_auth(monkeypatch):
    monkeypatch.setenv("FALCONEYE_ABUSE_ADMIN_USER", "admin")
    monkeypatch.setenv("FALCONEYE_ABUSE_ADMIN_PASS_HASH",
                       bcrypt.hashpw(b"correct horse", bcrypt.gensalt()).decode())
    c = _client()
    body = {"composed": _COMPOSED, "recipient_email": "abuse@prov.example"}

    r = c.post("/api/abuse/send", json=body)
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate", "").startswith("Basic")

    r = c.post("/api/abuse/send", json=body, auth=("admin", "wrong-password"))
    assert r.status_code == 401


def test_send_endpoint_503_when_unconfigured(monkeypatch):
    monkeypatch.delenv("FALCONEYE_ABUSE_ADMIN_USER", raising=False)
    monkeypatch.delenv("FALCONEYE_ABUSE_ADMIN_PASS_HASH", raising=False)
    c = _client()
    r = c.post("/api/abuse/send", json={"composed": _COMPOSED, "recipient_email": "abuse@prov.example"},
               auth=("admin", "whatever"))
    assert r.status_code == 503
