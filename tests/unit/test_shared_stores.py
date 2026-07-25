"""Unit tests for the shared cache + rate-limit stores (app/utils/cache.py,
app/utils/rate_limit.py) introduced in the P4 dedup pass."""
import sqlite3

import pytest

from app.utils import cache, rate_limit


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "shared.db")
    monkeypatch.setattr(cache, "DB_PATH", path)
    monkeypatch.setattr(rate_limit, "DB_PATH", path)
    return path


def _age_row(path, table, key_col, key, sql_modifier):
    """Backdate a cache row's fetched_at to simulate staleness."""
    conn = sqlite3.connect(path)
    conn.execute(f"UPDATE {table} SET fetched_at = datetime('now', ?) WHERE {key_col} = ?", (sql_modifier, key))
    conn.commit()
    conn.close()


# ---------------- cache ----------------

def test_cache_roundtrip_injects_cache_hit(db):
    cache.init_table("t_cache", key_col="id")
    cache.set("t_cache", "k1", {"value": 42}, key_col="id")
    got = cache.get("t_cache", "k1", ttl_hours=24, key_col="id")
    assert got["value"] == 42
    assert got["cache_hit"] is True
    assert "fetched_at" in got


def test_cache_miss_returns_none(db):
    cache.init_table("t_cache", key_col="id")
    assert cache.get("t_cache", "absent", ttl_hours=24, key_col="id") is None


def test_cache_respects_ttl(db):
    cache.init_table("t_cache", key_col="id")
    cache.set("t_cache", "k", {"v": 1}, key_col="id")
    _age_row(db, "t_cache", "id", "k", "-25 hours")
    assert cache.get("t_cache", "k", ttl_hours=24, key_col="id") is None   # stale -> miss
    # a fresh write is served again
    cache.set("t_cache", "k", {"v": 2}, key_col="id")
    assert cache.get("t_cache", "k", ttl_hours=24, key_col="id")["v"] == 2


def test_cache_fractional_ttl_hours(db):
    """threat_pulse uses a 60-minute (1.0h) TTL — fractional/small windows must work."""
    cache.init_table("t_cache", key_col="id")
    cache.set("t_cache", "ph", {"v": 1}, key_col="id")
    _age_row(db, "t_cache", "id", "ph", "-90 minutes")
    assert cache.get("t_cache", "ph", ttl_hours=1.0, key_col="id") is None   # 90min > 1h -> stale
    cache.set("t_cache", "ph", {"v": 1}, key_col="id")
    _age_row(db, "t_cache", "id", "ph", "-30 minutes")
    assert cache.get("t_cache", "ph", ttl_hours=1.0, key_col="id") is not None  # 30min < 1h -> hit


def test_cache_rejects_bad_identifier(db):
    with pytest.raises(ValueError):
        cache.get("t_cache; DROP TABLE x", "k", ttl_hours=1)


# ---------------- rate_limit ----------------

def test_rate_limit_allows_under_limit_then_blocks(db):
    rate_limit.init_table("t_rl")
    for i in range(3):
        allowed, used = rate_limit.check("t_rl", "1.2.3.4", limit=3)
        assert allowed is True
        assert used == i
        rate_limit.record("t_rl", "1.2.3.4")
    allowed, used = rate_limit.check("t_rl", "1.2.3.4", limit=3)
    assert allowed is False
    assert used == 3


def test_rate_limit_is_per_ip(db):
    rate_limit.init_table("t_rl")
    for _ in range(5):
        rate_limit.record("t_rl", "1.1.1.1")
    allowed, _ = rate_limit.check("t_rl", "9.9.9.9", limit=3)
    assert allowed is True   # a different IP is unaffected


def test_rate_limit_window_expiry(db):
    rate_limit.init_table("t_rl")
    rate_limit.record("t_rl", "5.5.5.5")
    # backdate the call beyond the window
    conn = sqlite3.connect(db)
    conn.execute("UPDATE t_rl SET called_at = datetime('now', '-25 hours') WHERE source_ip = '5.5.5.5'")
    conn.commit()
    conn.close()
    allowed, used = rate_limit.check("t_rl", "5.5.5.5", limit=1, window_hours=24)
    assert allowed is True
    assert used == 0   # the old call is outside the 24h window


def test_rate_limit_rejects_bad_identifier(db):
    with pytest.raises(ValueError):
        rate_limit.check("t_rl; DROP TABLE x", "1.2.3.4", limit=1)
