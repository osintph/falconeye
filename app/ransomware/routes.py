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
import sqlite3

from fastapi import APIRouter, Depends, Request
from slowapi import Limiter

from app.ransomware import store
from app.utils.client_ip import get_client_ip_key

router = APIRouter(prefix="/api/ransomware", tags=["ransomware"])
limiter = Limiter(key_func=get_client_ip_key)

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
