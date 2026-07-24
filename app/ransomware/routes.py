"""
Ransomware Watch API — read-only, local SQLite only.

Per Part 1 of the v3.16.0 brief: this router NEVER calls ransomware.live or
RansomLook. All data comes from ransomware.db, written on a schedule by
app/collectors/ransomware_collect.py (a systemd timer, not this process).
Every panel response carries an "as_of" timestamp and a source_status so the
UI can show staleness/degradation instead of pretending live data.

Cold start (Part 7): a phase that has never finished a run reports
state="not_yet_collected" with the most recent attempted run time (if any)
rather than an empty-but-normal-looking payload.
"""
import json
import re
import sqlite3
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from slowapi import Limiter

from app.ransomware import live, store
from app.utils.client_ip import get_client_ip, get_client_ip_key

router = APIRouter(prefix="/api/ransomware", tags=["ransomware"])
limiter = Limiter(key_func=get_client_ip_key)

# v3.17.0 on-demand paths.
_COUNTRY_CODE_RE = re.compile(r"^[A-Za-z]{2}$")
COUNTRY_ONDEMAND_TTL_SECONDS = 24 * 3600
COUNTRY_ONDEMAND_PER_HOUR = 20
COUNTRY_ONDEMAND_PER_DAY = 100
SEARCH_MIN_CHARS = 3
SEARCH_PER_MINUTE = 10
SEARCH_PER_HOUR = 100

_PHASE_SOURCE_LABEL = {
    "ransomware_live": "ransomware.live",
    "ransomware_live_v2": "ransomware.live (v2 fallback)",
    "ransomlook": "RansomLook",
}


def _db():
    conn = store._connect()
    try:
        yield conn
    finally:
        conn.close()


def _phase_meta(conn: sqlite3.Connection, phase: str) -> dict:
    row = store.last_run(conn, phase)
    if row is None:
        last_attempt = store.last_attempted_run(conn)
        return {
            "state": "not_yet_collected",
            "as_of": None,
            "last_attempted_at": last_attempt["started_at"] if last_attempt else None,
            "source_status": "never_run",
            "source_label": None,
            "detail": None,
        }
    return {
        "state": "ok",
        "as_of": row["finished_at"],
        "last_attempted_at": row["started_at"],
        "source_status": row["status"],
        "source_label": _PHASE_SOURCE_LABEL.get(row["source"], row["source"]),
        "detail": row["detail"],
    }


def _cold_response(meta: dict, **extra) -> dict:
    return {**meta, **extra}


# ---------- 1. Global pulse ----------

@router.get("/pulse")
@limiter.limit("60/minute")
async def pulse(request: Request, conn: sqlite3.Connection = Depends(_db)):
    meta = _phase_meta(conn, "victims_stats")
    if meta["state"] == "not_yet_collected":
        return _cold_response(meta)

    stats = store.pulse_stats(conn)
    sample_n = stats["infostealer_sample_size"]
    sample_hits = stats["infostealer_sample_hits"]
    infostealer_line = (
        f"{sample_hits} of last {sample_n} victims show credential exposure" if sample_n else None
    )
    return {
        **meta,
        "victims_ytd": stats["victims_ytd"],
        "active_groups": stats["active_groups"],
        "countries_hit": stats["countries_hit"],
        "total_victims_tracked": stats["total_victims_tracked"],
        "infostealer_sample_line": infostealer_line,
        "infostealer_sample_size": sample_n,
        "infostealer_sample_hits": sample_hits,
    }


# ---------- 2. World map ----------

@router.get("/map")
@limiter.limit("60/minute")
async def world_map(request: Request, conn: sqlite3.Connection = Depends(_db)):
    meta = _phase_meta(conn, "victims_stats")
    if meta["state"] == "not_yet_collected":
        return _cold_response(meta, countries=[])
    return {**meta, "countries": store.map_counts(conn)}


# ---------- 3. PH and SEA ----------

@router.get("/ph-sea")
@limiter.limit("60/minute")
async def ph_sea(request: Request, conn: sqlite3.Connection = Depends(_db)):
    meta = _phase_meta(conn, "victims_stats")
    if meta["state"] == "not_yet_collected":
        return _cold_response(meta, counts=[], trend=[], victims=[])
    return {
        **meta,
        "counts": store.ph_sea_counts(conn),
        "trend": store.ph_sea_monthly_trend(conn),
        "victims": store.ph_sea_victims(conn),
    }


# ---------- 4. Latest victims, global ----------

@router.get("/latest")
@limiter.limit("60/minute")
async def latest(request: Request, conn: sqlite3.Connection = Depends(_db)):
    meta = _phase_meta(conn, "victims_stats")
    if meta["state"] == "not_yet_collected":
        return _cold_response(meta, victims=[])

    rows = store.latest_victims(conn, limit=50)
    victims = []
    for r in rows:
        info = None
        if r.get("infostealer_json"):
            try:
                info = json.loads(r["infostealer_json"])
            except (TypeError, ValueError):
                info = None
        victims.append({
            "victim_name": r["victim_name"],
            "group_name": r["group_name"],
            "country": r["country"],
            "sector": r["sector"],
            "discovered": r["discovered"],
            "corroborated": bool(r["corroborated"]),
            "infostealer_count": r["infostealer_count"],
            "infostealer_detail": info,
            "permalink": r["permalink"],
        })
    return {**meta, "victims": victims}


# ---------- 5. Group activity ----------

@router.get("/groups")
@limiter.limit("60/minute")
async def group_activity(request: Request, conn: sqlite3.Connection = Depends(_db)):
    meta = _phase_meta(conn, "group_activity")
    if meta["state"] == "not_yet_collected":
        return _cold_response(meta, groups_7d=[], groups_30d=[])
    return {
        **meta,
        "groups_7d": store.group_activity(conn, 7),
        "groups_30d": store.group_activity(conn, 30),
    }


# ---------- 6. Leak site health ----------

@router.get("/mirrors")
@limiter.limit("60/minute")
async def mirrors(request: Request, conn: sqlite3.Connection = Depends(_db)):
    meta = _phase_meta(conn, "mirror_health")
    if meta["state"] == "not_yet_collected":
        return _cold_response(meta, groups={})
    return {**meta, "groups": store.mirrors_by_group(conn)}


# ---------- 8. Watchlist ----------

@router.get("/watchlist")
@limiter.limit("60/minute")
async def watchlist(request: Request, conn: sqlite3.Connection = Depends(_db)):
    meta = _phase_meta(conn, "watchlist")
    if meta["state"] == "not_yet_collected":
        return _cold_response(meta, hits=[])
    return {**meta, "hits": store.watchlist_hits(conn)}


# ---------- v3.17.0: country filter (hybrid: standing scope + TTL cache + on-demand) ----------

def _shape_victim_row(r) -> dict:
    """Same shape as /latest, deliberately - the frontend renders all three
    (latest / country / search) through the same rwVictimCard()/rwPhSeaRow(),
    per Part 3 of the v3.17.0 brief: no new render variants."""
    info = None
    if r["infostealer_json"]:
        try:
            info = json.loads(r["infostealer_json"])
        except (TypeError, ValueError):
            info = None
    return {
        "victim_name": r["victim_name"],
        "group_name": r["group_name"],
        "country": r["country"],
        "sector": r["sector"],
        "discovered": r["discovered"],
        "corroborated": bool(r["corroborated"]),
        "infostealer_count": r["infostealer_count"],
        "infostealer_detail": info,
        "permalink": r["permalink"],
    }


def _country_coverage_fresh(coverage_row, ttl_seconds: int) -> bool:
    if not coverage_row:
        return False
    try:
        last = datetime.fromisoformat(coverage_row["last_fetched"])
    except (TypeError, ValueError):
        return False
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - last).total_seconds() < ttl_seconds


def _country_response(country, coverage_state, coverage_row, victims, *, rate_limited=False, upstream_status="not_called"):
    return {
        "country": country,
        "coverage_state": coverage_state,  # standing_scope | cached | fetched_now | not_yet_queried
        "source": coverage_row["source"] if coverage_row else None,
        "last_fetched": coverage_row["last_fetched"] if coverage_row else None,
        "victim_count": coverage_row["victim_count"] if coverage_row else len(victims),
        "victims": victims,
        "rate_limited": rate_limited,
        "upstream_status": upstream_status,  # not_called | ok | unavailable
    }


@router.get("/country/{country}")
@limiter.limit("60/minute")
async def country_lookup(country: str, request: Request, conn: sqlite3.Connection = Depends(_db)):
    country = (country or "").strip().upper()
    if not _COUNTRY_CODE_RE.match(country):
        raise HTTPException(status_code=400, detail="country must be a 2-letter ISO 3166-1 alpha-2 code")

    coverage = store.get_country_coverage(conn, country)

    # Standing-scope countries are the collector's job, always. This branch
    # NEVER calls upstream, regardless of whether/how stale the coverage row
    # is - "read country_coverage, do not seed it" (Part 1).
    if country in store.SEA_COUNTRIES:
        victims = [_shape_victim_row(r) for r in store.victims_for_country(conn, country)]
        return _country_response(country, "standing_scope", coverage, victims)

    if _country_coverage_fresh(coverage, COUNTRY_ONDEMAND_TTL_SECONDS):
        victims = [_shape_victim_row(r) for r in store.victims_for_country(conn, country)]
        return _country_response(country, "cached", coverage, victims)

    client_ip = get_client_ip(request)
    allowed_hour, _ = store.check_rate_limit_window(
        conn, "ransomware_country_ondemand_rate_limit", client_ip, 3600, COUNTRY_ONDEMAND_PER_HOUR)
    allowed_day, _ = store.check_rate_limit_window(
        conn, "ransomware_country_ondemand_rate_limit", client_ip, 86400, COUNTRY_ONDEMAND_PER_DAY)
    if not (allowed_hour and allowed_day):
        if coverage:
            victims = [_shape_victim_row(r) for r in store.victims_for_country(conn, country)]
            return _country_response(country, "cached", coverage, victims, rate_limited=True)
        return _country_response(country, "not_yet_queried", None, [], rate_limited=True)

    store.record_rate_limit_event(conn, "ransomware_country_ondemand_rate_limit", client_ip)

    raw_victims, status = await live.fetch_country_live(country)
    if raw_victims is None:
        # Degraded: PRO unreachable. Fall back to whatever's cached, or the
        # honest not-yet-queried state - never a 500 (Part 4).
        if coverage:
            victims = [_shape_victim_row(r) for r in store.victims_for_country(conn, country)]
            return _country_response(country, "cached", coverage, victims, upstream_status="unavailable")
        return _country_response(country, "not_yet_queried", None, [], upstream_status="unavailable")

    now_iso = datetime.now(timezone.utc).isoformat()
    for raw in raw_victims:
        if not isinstance(raw, dict):
            continue
        f = live.extract_pro_victim_fields(raw)
        if not f["group_name"] or not f["victim_name"]:
            continue
        store.upsert_victim(conn, first_seen_via="country_filter", now_iso=now_iso, **f)
    store.upsert_country_coverage(conn, country=country, victim_count=len(raw_victims), source="on_demand", now_iso=now_iso)
    conn.commit()

    victims = [_shape_victim_row(r) for r in store.victims_for_country(conn, country)]
    fresh_coverage = store.get_country_coverage(conn, country)
    return _country_response(country, "fetched_now", fresh_coverage, victims, upstream_status="ok")


# ---------- v3.17.0: company search (always upstream, guarded) ----------

def _zero_result_note(victims: list) -> str | None:
    if victims:
        return None
    return ("No entries in tracked leak sites. Neither ransomware.live nor RansomLook claims "
            "complete coverage - this is not confirmation of anything.")


@router.get("/search")
@limiter.limit("30/minute")
async def search_victims(request: Request, q: str = "", conn: sqlite3.Connection = Depends(_db)):
    q = (q or "").strip()
    if len(q) < SEARCH_MIN_CHARS:
        raise HTTPException(status_code=400, detail=f"Search query must be at least {SEARCH_MIN_CHARS} characters")

    client_ip = get_client_ip(request)
    allowed_min, _ = store.check_rate_limit_window(conn, "ransomware_search_rate_limit", client_ip, 60, SEARCH_PER_MINUTE)
    allowed_hour, _ = store.check_rate_limit_window(conn, "ransomware_search_rate_limit", client_ip, 3600, SEARCH_PER_HOUR)
    if not (allowed_min and allowed_hour):
        return {
            "rate_limited": True, "degraded": False, "degraded_note": None,
            "truncated": False, "zero_result_note": None, "cache_hit": False, "victims": [],
        }

    store.record_rate_limit_event(conn, "ransomware_search_rate_limit", client_ip)

    normalized = live.normalize_query(q)
    cached = live.get_cached_search(normalized)
    if cached is not None:
        return {
            "rate_limited": False, "degraded": False, "degraded_note": None,
            "truncated": len(cached) >= live.SEARCH_RESULT_CAP,
            "zero_result_note": _zero_result_note(cached), "cache_hit": True, "victims": cached,
        }

    raw_victims, status = await live.fetch_search_live(q)
    if raw_victims is None:
        # Degraded: deliberate exception to "always upstream" (Part 4) - a
        # plain local LIKE scan, clearly labelled, only while PRO is down.
        local_rows = store.search_victims_local(conn, q)
        shaped = [_shape_victim_row(r) for r in local_rows]
        return {
            "rate_limited": False, "degraded": True,
            "degraded_note": ("ransomware.live is currently unreachable. These results come from "
                               "FalconEye's partial local cache only - a lack of results here is not "
                               "confirmation of anything."),
            "truncated": False, "zero_result_note": _zero_result_note(shaped) if shaped == [] else None,
            "cache_hit": False, "victims": shaped,
        }

    now_iso = datetime.now(timezone.utc).isoformat()
    truncated = len(raw_victims) > live.SEARCH_RESULT_CAP
    capped = raw_victims[: live.SEARCH_RESULT_CAP]

    vids = []
    for raw in capped:
        if not isinstance(raw, dict):
            continue
        f = live.extract_pro_victim_fields(raw)
        if not f["group_name"] or not f["victim_name"]:
            continue
        vids.append(store.upsert_victim(conn, first_seen_via="search", now_iso=now_iso, **f))
    conn.commit()

    shaped = []
    if vids:
        placeholders = ",".join("?" for _ in vids)
        rows = conn.execute(
            f"""
            SELECT victim_name, group_name, country, sector, discovered, corroborated,
                   infostealer_count, infostealer_json, permalink
            FROM victims WHERE id IN ({placeholders}) ORDER BY discovered DESC
            """,
            vids,
        ).fetchall()
        shaped = [_shape_victim_row(r) for r in rows]

    live.set_cached_search(normalized, shaped)

    return {
        "rate_limited": False, "degraded": False, "degraded_note": None,
        "truncated": truncated, "zero_result_note": _zero_result_note(shaped),
        "cache_hit": False, "victims": shaped,
    }


# ---------- overall status (drives the tab-level cold-start / degradation banner) ----------

@router.get("/status")
@limiter.limit("60/minute")
async def status(request: Request, conn: sqlite3.Connection = Depends(_db)):
    phases = ["victims_stats", "group_activity", "mirror_health", "watchlist"]
    sources = {phase: _phase_meta(conn, phase) for phase in phases}
    any_data = store.has_any_data(conn)
    all_cold = all(s["state"] == "not_yet_collected" for s in sources.values())
    if all_cold:
        last_attempt = store.last_attempted_run(conn)
        return {
            "state": "not_yet_collected",
            "last_attempted_at": last_attempt["started_at"] if last_attempt else None,
        }
    return {
        "state": "ok" if any_data else "partial",
        "phases": sources,
    }
