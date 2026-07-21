"""Proves the app-wide global exception handler, not just that the code compiles.

Forces an unhandled exception deep in the scan path (bypassing the endpoint's
own explicit error handling) and confirms app.main's global handler converts it
to a JSON 500 — never Starlette's default PlainTextResponse.
"""
from fastapi.testclient import TestClient

from app.main import app as main_app
from app.username import routes as username_routes
from app.username import store


def test_unhandled_exception_returns_json_not_plaintext(monkeypatch):
    async def boom(*args, **kwargs):
        raise RuntimeError("simulated unhandled failure")

    monkeypatch.setattr(username_routes.checker, "sweep", boom)

    client = TestClient(main_app, raise_server_exceptions=False)
    r = client.post("/api/username/scan", json={"username": "torvalds", "scope": "quick"})

    assert r.status_code == 500
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()  # raises if the body isn't valid JSON
    assert body == {"detail": "Internal Server Error"}


def test_count_recent_fails_closed_on_db_error(monkeypatch):
    def broken_connect():
        raise RuntimeError("simulated DB failure")

    monkeypatch.setattr(store, "_connect", broken_connect)

    assert store.count_recent("ip:1.2.3.4", 3600) == store._FAIL_CLOSED_COUNT
