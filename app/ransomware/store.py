"""
SQLite persistence for the Ransomware Watch tab.

Separate database from the main falconeye.db (RANSOMWARE_DB, default
/opt/falconeye/data/ransomware.db) — same convention as the daily report and
Telegram session: outside the git tree, resolved dynamically so tests can
point it at a throwaway file via the env var.

This module is the ONLY thing that touches ransomware.db. Both the collector
(app/collectors/ransomware_collect.py, the sole writer) and the router
(app/ransomware/routes.py, read-only) go through it, so schema and the
credential write-guard live in exactly one place.

Credential handling (see docs/ransomware-watch-runbook.md and the v3.16.0
brief, Part 3): RansomLook's mirror-health endpoint returns the raw mirror
URL, and for some groups that URL embeds working leak-site credentials
(scheme://user:pass@host). This module never accepts a raw slug — callers
must hash it first (hash_mirror_slug) — and upsert_mirror() independently
refuses to write anything that still looks like a credentialed URI, as a
backstop against a future call site that skips the hash.
"""
import hashlib
import json
import logging
import os
import re
import sqlite3
import urllib.parse

from app.config import RANSOMWARE_DB as _DB_DEFAULT

log = logging.getLogger("falconeye.ransomware")

# SEA/PH country set the tab reports on, ISO 3166-1 alpha-2.
SEA_COUNTRIES = ["PH", "SG", "MY", "ID", "TH", "VN", "HK", "TW"]

# A longer-than-30d uptime figure is only computed locally once the health
# series has meaningfully more depth than the API's own 30d figure — otherwise
# it would just be a near-duplicate number under a different label.
_MIN_SERIES_LEN_FOR_COMPUTED_UPTIME = 45

_CREDENTIAL_URI_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/@\s]+:[^/@\s]+@")


class CredentialGuardError(ValueError):
    """Raised when a write would have persisted a credential-bearing URI."""


def _db_path() -> str:
    return os.getenv("RANSOMWARE_DB", _DB_DEFAULT)


def _connect() -> sqlite3.Connection:
    # check_same_thread=False: routes.py hands this connection to FastAPI via
    # Depends(), which can cross threads under Starlette's async bridge (same
    # reasoning as app/database.py's get_db()). The collector, by contrast,
    # opens/closes a connection within a single synchronous call each time.
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, coltype: str) -> None:
    """Additive migration: add *column* to *table* if an older schema (or an
    already-populated production DB) doesn't have it yet. SQLite has no
    ADD COLUMN IF NOT EXISTS, so check PRAGMA table_info first."""
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")


def init_tables() -> None:
    """Create all Ransomware Watch tables if absent. Idempotent."""
    conn = _connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS victims (
              id TEXT PRIMARY KEY,
              match_key TEXT NOT NULL,
              group_name TEXT NOT NULL,
              victim_name TEXT NOT NULL,
              country TEXT,
              sector TEXT,
              discovered TEXT,
              attackdate TEXT,
              corroborated INTEGER NOT NULL DEFAULT 0,
              infostealer_count INTEGER NOT NULL DEFAULT 0,
              infostealer_json TEXT,
              permalink TEXT,
              first_seen_via TEXT,
              first_seen_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            )
            """
        )
        # Additive migrations for a victims table created before these columns
        # existed (CREATE TABLE IF NOT EXISTS above is a no-op against it).
        #
        # first_seen_via: the TRIGGER that caused this row to first exist, not
        # the upstream endpoint used. 'collector' = anything the scheduled
        # collector ingests, including its own per-country queries.
        # 'country_filter' = a future user-triggered on-demand country fetch.
        # 'search' = a future user-triggered company search. NULL means the
        # row predates this column (true statement, not backfilled — a v3.16.0
        # decision, see docs/ransomware-watch-runbook.md).
        _ensure_column(conn, "victims", "first_seen_via", "TEXT")
        # permalink: ransomware.live's OWN hosted link for this victim
        # (https://www.ransomware.live/id/...), populated only from PRO's
        # `permalink` field - never from `post_url`/`claim_url`/`url`, which
        # are the raw leak-site address. store.safe_permalink() enforces the
        # host check at write time too, as a backstop.
        _ensure_column(conn, "victims", "permalink", "TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_victims_match_key ON victims(match_key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_victims_country ON victims(country)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_victims_discovered ON victims(discovered)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_victims_group ON victims(group_name)")

        # Forward-compatibility table: created empty in v3.16.0, not consumed
        # until a later release, specifically so that release doesn't need a
        # schema migration against a by-then much larger victims table. The
        # collector stamps one row per standing-scope country (SEA_COUNTRIES)
        # on every run with source='collector', so a future per-country
        # on-demand query can check here first before hitting an upstream.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS country_coverage (
              country TEXT PRIMARY KEY,
              last_fetched TEXT NOT NULL,
              victim_count INTEGER NOT NULL,
              source TEXT NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS groups (
              group_name TEXT NOT NULL,
              window_days INTEGER NOT NULL,
              post_count INTEGER NOT NULL,
              last_post TEXT,
              updated_at TEXT NOT NULL,
              PRIMARY KEY (group_name, window_days)
            )
            """
        )

        # mirror_hash is sha256(raw slug)[:16] — the raw slug (which can embed
        # live leak-site credentials) is never a valid value here; see
        # upsert_mirror()'s guard below.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mirrors (
              group_name TEXT NOT NULL,
              mirror_hash TEXT NOT NULL,
              position_index INTEGER NOT NULL,
              uptime_30d INTEGER,
              uptime_computed INTEGER,
              series_len INTEGER NOT NULL DEFAULT 0,
              updated_at TEXT NOT NULL,
              PRIMARY KEY (group_name, mirror_hash)
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS press (
              id TEXT PRIMARY KEY,
              title TEXT,
              group_name TEXT,
              published_at TEXT,
              has_infostealer INTEGER NOT NULL DEFAULT 0,
              fetched_at TEXT NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS watchlist_hits (
              id TEXT PRIMARY KEY,
              term TEXT NOT NULL,
              tier INTEGER,
              match_type TEXT NOT NULL,
              matched_name TEXT,
              group_name TEXT,
              discovered TEXT,
              found_at TEXT NOT NULL
            )
            """
        )
        # Migration for a watchlist_hits table created before tiers existed
        # (CREATE TABLE IF NOT EXISTS above is a no-op against it) - additive,
        # nullable, non-destructive. Pre-migration rows keep tier=NULL rather
        # than a guessed backfill; the UI treats NULL as untiered/legacy.
        _ensure_column(conn, "watchlist_hits", "tier", "INTEGER")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_watchlist_found_at ON watchlist_hits(found_at)")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS collector_runs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              phase TEXT NOT NULL,
              source TEXT NOT NULL,
              status TEXT NOT NULL,
              detail TEXT,
              started_at TEXT NOT NULL,
              finished_at TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_collector_runs_phase ON collector_runs(phase, finished_at)")
        conn.commit()
    finally:
        conn.close()


try:
    init_tables()
except Exception as exc:  # pragma: no cover - only trips when DB path is unwritable at import
    log.warning("ransomware: deferred table init (DB not ready at import): %s", exc)


# ---------- hashing / normalization ----------

def _norm(s) -> str:
    return (s or "").strip().lower()


def victim_id(group_name: str, victim_name: str, discovered: str) -> str:
    """PK for one source's victim record: hash of group + name + discovered
    *date* (not full timestamp), so re-collecting the same victim on a later
    cycle upserts the same row instead of accumulating duplicates."""
    date_part = (discovered or "")[:10]
    raw = f"{_norm(group_name)}|{_norm(victim_name)}|{date_part}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def victim_match_key(group_name: str, victim_name: str) -> str:
    """Cross-source corroboration key: group + name, deliberately no date,
    since the two trackers scrape the same leak post at different times."""
    raw = f"{_norm(group_name)}|{_norm(victim_name)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def hash_mirror_slug(slug: str) -> str:
    """Collapse a raw mirror URL (which may embed live credentials) to a
    stable opaque id. Call this immediately on receipt, before the raw string
    is assigned anywhere that outlives the call."""
    return hashlib.sha256((slug or "").encode("utf-8")).hexdigest()[:16]


def looks_like_credential_uri(s: str) -> bool:
    return bool(s) and bool(_CREDENTIAL_URI_RE.match(s.strip()))


def press_id(title: str, published_at: str) -> str:
    raw = f"{_norm(title)}|{(published_at or '')[:10]}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def watchlist_hit_id(term: str, matched_name: str, group_name: str, discovered: str) -> str:
    raw = f"{_norm(term)}|{_norm(matched_name)}|{_norm(group_name)}|{discovered or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _summarize_infostealer(info: dict | None) -> tuple[int, str | None]:
    """Reduce ransomware.live's `infostealer` object to a safe summary: counts
    and dates only, nothing that resembles actual credential material."""
    if not info or not isinstance(info, dict):
        return 0, None
    employees = info.get("employees") or 0
    users = info.get("users") or 0
    thirdparties = info.get("thirdparties") or 0
    count = employees + users + thirdparties
    if count <= 0:
        return 0, None
    safe = {
        "employees": employees,
        "users": users,
        "thirdparties": thirdparties,
        "employees_url": info.get("employees_url") or 0,
        "users_url": info.get("users_url") or 0,
        "last_employee_compromised": info.get("last_employee_compromised"),
        "last_user_compromised": info.get("last_user_compromised"),
        "update": info.get("update"),
    }
    return count, json.dumps(safe)


# ---------- writes (collector only) ----------

_ALLOWED_PERMALINK_HOSTS = {"ransomware.live", "www.ransomware.live"}


def safe_permalink(url: str | None) -> str | None:
    """Only ever pass through ransomware.live's OWN link (their `permalink`
    field). Never the raw leak-site address (`post_url`/`claim_url`/`url` in
    their schemas) — this is a host-check backstop in case a future field
    rename or a v2-fallback record's differently-named field ever gets passed
    in here by mistake."""
    if not url:
        return None
    try:
        host = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return None
    if host and host.lower() in _ALLOWED_PERMALINK_HOSTS and url.startswith("https://"):
        return url
    return None


def upsert_victim(conn: sqlite3.Connection, *, group_name: str, victim_name: str, country: str | None,
                   sector: str | None, discovered: str | None, attackdate: str | None,
                   infostealer: dict | None, permalink: str | None, first_seen_via: str, now_iso: str) -> str:
    vid = victim_id(group_name, victim_name, discovered)
    mkey = victim_match_key(group_name, victim_name)
    info_count, info_json = _summarize_infostealer(infostealer)
    safe_link = safe_permalink(permalink)
    conn.execute(
        """
        INSERT INTO victims (id, match_key, group_name, victim_name, country, sector, discovered, attackdate,
                              corroborated, infostealer_count, infostealer_json, permalink, first_seen_via,
                              first_seen_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          country=excluded.country, sector=excluded.sector, attackdate=excluded.attackdate,
          infostealer_count=excluded.infostealer_count, infostealer_json=excluded.infostealer_json,
          permalink=excluded.permalink, updated_at=excluded.updated_at
        """,
        # first_seen_via is deliberately absent from the UPDATE SET above - it
        # records what first caused this row to exist and is never overwritten.
        (vid, mkey, group_name, victim_name, country or "", sector or "", discovered, attackdate,
         info_count, info_json, safe_link, first_seen_via, now_iso, now_iso),
    )
    return vid


def upsert_country_coverage(conn: sqlite3.Connection, *, country: str, victim_count: int, source: str, now_iso: str) -> None:
    conn.execute(
        """
        INSERT INTO country_coverage (country, last_fetched, victim_count, source)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(country) DO UPDATE SET
          last_fetched=excluded.last_fetched, victim_count=excluded.victim_count, source=excluded.source
        """,
        (country, now_iso, victim_count, source),
    )


def mark_corroborated(conn: sqlite3.Connection, match_keys, now_iso: str) -> None:
    """Flag victims whose match_key also appeared in the other source's
    current snapshot. One-directional (never unflags) — a victim that drops
    out of RansomLook's rolling recent-posts window on a later cycle doesn't
    retroactively become single-source again."""
    keys = [k for k in set(match_keys or []) if k]
    if not keys:
        return
    conn.executemany(
        "UPDATE victims SET corroborated = 1, updated_at = ? WHERE match_key = ? AND corroborated = 0",
        [(now_iso, k) for k in keys],
    )


def replace_group_activity(conn: sqlite3.Connection, window_days: int, rows: list[dict], now_iso: str) -> None:
    """rows: [{group, count, last_post}, ...] straight from /api/hot/{days} —
    no local ranking. Full replace per window so a group that fell out of the
    top of the ranking doesn't linger."""
    conn.execute("DELETE FROM groups WHERE window_days = ?", (window_days,))
    conn.executemany(
        "INSERT INTO groups (group_name, window_days, post_count, last_post, updated_at) VALUES (?, ?, ?, ?, ?)",
        [(r.get("group"), window_days, r.get("count") or 0, r.get("last_post"), now_iso) for r in rows],
    )


def upsert_mirror(conn: sqlite3.Connection, *, group_name: str, position_index: int, mirror_hash: str,
                   uptime_30d, series: list, now_iso: str) -> None:
    if looks_like_credential_uri(mirror_hash):
        log.warning(
            "ransomware: refused to write a credential-bearing mirror value for group=%s (redacted)",
            group_name,
        )
        raise CredentialGuardError("refused to store a credential-bearing URI as a mirror value")

    series = series or []
    series_len = len(series)
    uptime_computed = None
    if series_len >= _MIN_SERIES_LEN_FOR_COMPUTED_UPTIME:
        ones = sum(1 for x in series if x)
        uptime_computed = round(100 * ones / series_len)

    conn.execute(
        """
        INSERT INTO mirrors (group_name, mirror_hash, position_index, uptime_30d, uptime_computed, series_len, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(group_name, mirror_hash) DO UPDATE SET
          position_index=excluded.position_index, uptime_30d=excluded.uptime_30d,
          uptime_computed=excluded.uptime_computed, series_len=excluded.series_len,
          updated_at=excluded.updated_at
        """,
        (group_name, mirror_hash, position_index, uptime_30d, uptime_computed, series_len, now_iso),
    )


def clear_mirrors_for_group(conn: sqlite3.Connection, group_name: str) -> None:
    conn.execute("DELETE FROM mirrors WHERE group_name = ?", (group_name,))


def upsert_press(conn: sqlite3.Connection, *, title: str, group_name: str | None, published_at: str | None,
                  has_infostealer: bool, now_iso: str) -> None:
    pid = press_id(title, published_at)
    conn.execute(
        """
        INSERT INTO press (id, title, group_name, published_at, has_infostealer, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET has_infostealer=excluded.has_infostealer, fetched_at=excluded.fetched_at
        """,
        (pid, title, group_name, published_at, 1 if has_infostealer else 0, now_iso),
    )


def record_watchlist_hit(conn: sqlite3.Connection, *, term: str, tier: int, match_type: str, matched_name: str | None,
                          group_name: str | None, discovered: str | None, now_iso: str) -> None:
    """tier 1 = high-precision proper noun, alerting. tier 2 = broad
    geographic term, logged for review only, never alerts (see the v3.16.0
    watchlist rework brief)."""
    assert tier in (1, 2)
    hid = watchlist_hit_id(term, matched_name or "", group_name or "", discovered or "")
    conn.execute(
        """
        INSERT OR IGNORE INTO watchlist_hits (id, term, tier, match_type, matched_name, group_name, discovered, found_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (hid, term, tier, match_type, matched_name, group_name, discovered, now_iso),
    )


def record_run(conn: sqlite3.Connection, *, phase: str, source: str, status: str, detail: str | None,
                started_at: str, finished_at: str | None) -> None:
    assert status in ("ok", "degraded", "error")
    conn.execute(
        "INSERT INTO collector_runs (phase, source, status, detail, started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?)",
        (phase, source, status, detail, started_at, finished_at),
    )


# ---------- reads (routes only) ----------

def last_run(conn: sqlite3.Connection, phase: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM collector_runs WHERE phase = ? AND finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 1",
        (phase,),
    ).fetchone()


def last_attempted_run(conn: sqlite3.Connection) -> sqlite3.Row | None:
    """Most recent run of any kind, finished or not — for the cold-start banner."""
    return conn.execute("SELECT * FROM collector_runs ORDER BY id DESC LIMIT 1").fetchone()


def has_any_data(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT EXISTS(SELECT 1 FROM victims LIMIT 1)").fetchone()
    return bool(row[0]) if row else False


def pulse_stats(conn: sqlite3.Connection) -> dict:
    year = conn.execute("SELECT strftime('%Y', 'now')").fetchone()[0]
    ytd = conn.execute(
        "SELECT COUNT(*) FROM victims WHERE substr(discovered, 1, 4) = ?", (year,)
    ).fetchone()[0]
    active_groups = conn.execute(
        "SELECT COUNT(DISTINCT group_name) FROM groups WHERE window_days = 30"
    ).fetchone()[0]
    countries_hit = conn.execute(
        "SELECT COUNT(DISTINCT country) FROM victims WHERE country IS NOT NULL AND country != ''"
    ).fetchone()[0]
    total_recent = conn.execute("SELECT COUNT(*) FROM victims").fetchone()[0]

    recent_100 = conn.execute(
        "SELECT infostealer_count FROM victims ORDER BY discovered DESC LIMIT 100"
    ).fetchall()
    sample_n = len(recent_100)
    with_infostealer = sum(1 for r in recent_100 if r["infostealer_count"] > 0)

    return {
        "victims_ytd": ytd,
        "active_groups": active_groups,
        "countries_hit": countries_hit,
        "total_victims_tracked": total_recent,
        "infostealer_sample_size": sample_n,
        "infostealer_sample_hits": with_infostealer,
    }


def map_counts(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT country, COUNT(*) as count FROM victims WHERE country IS NOT NULL AND country != '' "
        "GROUP BY country ORDER BY count DESC"
    ).fetchall()
    return [{"country": r["country"], "count": r["count"]} for r in rows]


def ph_sea_counts(conn: sqlite3.Connection) -> list[dict]:
    placeholders = ",".join("?" for _ in SEA_COUNTRIES)
    rows = conn.execute(
        f"SELECT country, COUNT(*) as count FROM victims WHERE country IN ({placeholders}) GROUP BY country",
        SEA_COUNTRIES,
    ).fetchall()
    counts = {r["country"]: r["count"] for r in rows}
    return [{"country": c, "count": counts.get(c, 0)} for c in SEA_COUNTRIES]


def ph_sea_monthly_trend(conn: sqlite3.Connection, months: int = 6) -> list[dict]:
    placeholders = ",".join("?" for _ in SEA_COUNTRIES)
    rows = conn.execute(
        f"""
        SELECT substr(discovered, 1, 7) as ym, country, COUNT(*) as count
        FROM victims
        WHERE country IN ({placeholders}) AND discovered IS NOT NULL
        GROUP BY ym, country
        ORDER BY ym DESC
        LIMIT ?
        """,
        SEA_COUNTRIES + [months * len(SEA_COUNTRIES)],
    ).fetchall()
    return [{"month": r["ym"], "country": r["country"], "count": r["count"]} for r in rows]


def ph_sea_victims(conn: sqlite3.Connection, limit: int = 200) -> list[dict]:
    placeholders = ",".join("?" for _ in SEA_COUNTRIES)
    rows = conn.execute(
        f"""
        SELECT victim_name, group_name, country, sector, discovered, corroborated, infostealer_count, permalink
        FROM victims WHERE country IN ({placeholders})
        ORDER BY discovered DESC LIMIT ?
        """,
        SEA_COUNTRIES + [limit],
    ).fetchall()
    return [dict(r) for r in rows]


def latest_victims(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    rows = conn.execute(
        """
        SELECT victim_name, group_name, country, sector, discovered, corroborated, infostealer_count, infostealer_json, permalink
        FROM victims ORDER BY discovered DESC LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def group_activity(conn: sqlite3.Connection, window_days: int) -> list[dict]:
    rows = conn.execute(
        "SELECT group_name, post_count, last_post FROM groups WHERE window_days = ? ORDER BY post_count DESC",
        (window_days,),
    ).fetchall()
    return [dict(r) for r in rows]


_MIRRORS_SHOWN_PER_GROUP = 8


def mirrors_by_group(conn: sqlite3.Connection) -> dict:
    """Positional labels only (Part 3) — never the slug. Some groups have
    hundreds of historical mirror entries (observed live: qilin alone had
    ~640), mostly long-dead, so this ranks by uptime and caps what's shown per
    group rather than dumping the full list."""
    rows = conn.execute(
        "SELECT group_name, uptime_30d, uptime_computed, series_len FROM mirrors"
    ).fetchall()
    by_group: dict = {}
    for r in rows:
        by_group.setdefault(r["group_name"], []).append(r)

    out: dict = {}
    for group_name, entries in by_group.items():
        entries.sort(key=lambda r: (r["uptime_30d"] if r["uptime_30d"] is not None else -1), reverse=True)
        shown = entries[:_MIRRORS_SHOWN_PER_GROUP]
        hidden = len(entries) - len(shown)
        out[group_name] = {
            "mirrors": [
                {
                    "label": f"Mirror {i}",
                    "uptime_30d": r["uptime_30d"],
                    "uptime_computed": r["uptime_computed"],
                    "computed_window_days": r["series_len"] if r["uptime_computed"] is not None else None,
                }
                for i, r in enumerate(shown, start=1)
            ],
            "total_count": len(entries),
            "hidden_count": max(hidden, 0),
        }
    return out


def mirror_health_candidate_groups(conn: sqlite3.Connection) -> list[str]:
    """Groups worth polling /api/health/{name} for: PH/SEA-relevant (appeared
    in a SEA-country victim) plus globally active (appeared in the last hot/30
    ranking). Deliberately NOT "all RansomLook-tracked groups" (~588) — see
    Part 4 of the v3.16.0 brief on polite consumption of a free service."""
    placeholders = ",".join("?" for _ in SEA_COUNTRIES)
    sea_rows = conn.execute(
        f"SELECT DISTINCT group_name FROM victims WHERE country IN ({placeholders})",
        SEA_COUNTRIES,
    ).fetchall()
    active_rows = conn.execute(
        "SELECT DISTINCT group_name FROM groups WHERE window_days = 30"
    ).fetchall()
    names = {r["group_name"] for r in sea_rows if r["group_name"]}
    names |= {r["group_name"] for r in active_rows if r["group_name"]}
    return sorted(names)


def watchlist_hits(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    rows = conn.execute(
        "SELECT term, tier, match_type, matched_name, group_name, discovered, found_at "
        "FROM watchlist_hits ORDER BY found_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]
