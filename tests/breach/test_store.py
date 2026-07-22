"""
Privacy + correctness lock for the breach cache/rate-limit store: emails must
never be persisted in plaintext, cache TTLs must actually expire, and the
rate limiter must fail CLOSED (never silently let a caller through) on a
DB read error — the same contract app.username.store establishes.
"""
import sqlite3
import time

from app.breach import store


def test_email_cache_key_is_not_reversible_plaintext():
    key = store.email_cache_key("Victim@Example.com")
    assert "victim" not in key.lower()
    assert "example.com" not in key.lower()
    # same email (any casing/whitespace) -> same key, so caching still works
    assert key == store.email_cache_key(" victim@example.com ")


def test_cache_round_trip():
    store.store_cached("k1", {"a": 1, "b": [1, 2, 3]})
    assert store.get_cached("k1", None) == {"a": 1, "b": [1, 2, 3]}


def test_cache_respects_ttl():
    store.store_cached("k2", {"a": 1})
    assert store.get_cached("k2", 3600) == {"a": 1}
    assert store.get_cached("k2", 0) is None  # 0s TTL: anything cached "now" is already stale


def test_cache_miss_returns_none():
    assert store.get_cached("does-not-exist", None) is None


def test_rate_limit_counts_within_window_only():
    store.record_event("scope-a")
    assert store.count_recent("scope-a", 3600) == 1
    assert store.count_recent("scope-a", -1) == 0  # window closed before the event


def test_rate_limit_fails_closed_on_db_error(monkeypatch):
    def _boom():
        raise sqlite3.OperationalError("disk I/O error")
    monkeypatch.setattr(store, "_connect", _boom)
    assert store.count_recent("scope-b", 3600) >= store._FAIL_CLOSED_COUNT
