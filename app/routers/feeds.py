import sqlite3
from fastapi import APIRouter, Depends
from app.database import get_db

router = APIRouter(prefix="/api/feeds", tags=["feeds"])


@router.get("/status")
async def feed_status(db: sqlite3.Connection = Depends(get_db)):
    total = db.execute("SELECT COUNT(*) as n FROM phishing_scans").fetchone()["n"]
    live = db.execute("SELECT COUNT(*) as n FROM phishing_scans WHERE is_live = 1").fetchone()["n"]
    by_source = db.execute(
        "SELECT ingest_source, COUNT(*) as n FROM phishing_scans GROUP BY ingest_source ORDER BY n DESC"
    ).fetchall()
    by_brand = db.execute(
        "SELECT target_brand, COUNT(*) as n FROM phishing_scans GROUP BY target_brand ORDER BY n DESC LIMIT 10"
    ).fetchall()
    latest = db.execute(
        "SELECT phishing_url, target_brand, ingest_source, date_scanned FROM phishing_scans ORDER BY date_scanned DESC LIMIT 10"
    ).fetchall()
    return {
        "total": total,
        "live": live,
        "by_source": [dict(r) for r in by_source],
        "by_brand": [dict(r) for r in by_brand],
        "latest": [dict(r) for r in latest],
    }


@router.get("/search")
async def search_feeds(
    brand: str | None = None,
    source: str | None = None,
    live_only: bool = False,
    limit: int = 50,
    db: sqlite3.Connection = Depends(get_db),
):
    limit = min(limit, 200)
    query = "SELECT phishing_url, target_brand, ingest_source, is_live, date_scanned, kit_indicators FROM phishing_scans WHERE 1=1"
    params = []

    if brand:
        query += " AND target_brand = ?"
        params.append(brand)
    if source:
        query += " AND ingest_source = ?"
        params.append(source)
    if live_only:
        query += " AND is_live = 1"

    query += " ORDER BY date_scanned DESC LIMIT ?"
    params.append(limit)

    rows = db.execute(query, params).fetchall()
    return [dict(r) for r in rows]
