import sqlite3
import feedparser
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.database import get_db
from app.config import NEWS_CACHE_TTL_MINUTES

router = APIRouter(prefix="/api/news", tags=["news"])
limiter = Limiter(key_func=get_remote_address)

FEEDS = {
    "global_cyber": [
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
        {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
        {"name": "The Record", "url": "https://therecord.media/feed"},
        {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"},
    ],
    "ph_cyber": [
        {"name": "CyberSecurity.PH", "url": "https://www.cybersecurity.ph/feed/"},
        {"name": "Inquirer Technology", "url": "https://technology.inquirer.net/feed"},
        {"name": "Rappler Technology", "url": "https://www.rappler.com/technology/feed/"},
    ],
    "ph_tech": [
        {"name": "Rappler Technology", "url": "https://www.rappler.com/technology/feed/"},
        {"name": "Inquirer Technology", "url": "https://technology.inquirer.net/feed"},
        {"name": "GMA SciTech", "url": "https://data.gmanetwork.com/gno/rss/scitech/feed.xml"},
        {"name": "Philstar Technology", "url": "https://www.philstar.com/rss/business"},
        {"name": "Manila Times Technology", "url": "https://www.manilatimes.net/business/technology/feed/"},
    ],
}


def cache_is_stale(db: sqlite3.Connection, category: str) -> bool:
    row = db.execute(
        "SELECT fetched_at FROM news_cache WHERE feed_category = ? ORDER BY fetched_at DESC LIMIT 1",
        (category,),
    ).fetchone()
    if not row:
        return True
    fetched = datetime.fromisoformat(row["fetched_at"])
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - fetched > timedelta(minutes=NEWS_CACHE_TTL_MINUTES)


def refresh_category(db: sqlite3.Connection, category: str) -> None:
    import logging
    log = logging.getLogger("falconeye.news")
    feeds = FEEDS.get(category, [])

    for feed in feeds:
        try:
            parsed = feedparser.parse(feed["url"])
            if parsed.bozo and not parsed.entries:
                log.warning(f"Feed parse failed for {feed['name']}: {parsed.get('bozo_exception')}")
                continue
            if not parsed.entries:
                log.warning(f"Feed returned no entries: {feed['name']}")
                continue
            entry_count = 0
            for entry in parsed.entries[:15]:
                title = entry.get("title", "").strip()
                url = entry.get("link", "").strip()
                summary = entry.get("summary", "").strip()[:500]
                published = entry.get("published", "") or entry.get("updated", "")
                if not title or not url:
                    continue
                db.execute(
                    """
                    INSERT OR IGNORE INTO news_cache (feed_category, feed_source, title, url, summary, published_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (category, feed["name"], title, url, summary, published),
                )
                entry_count += 1
            log.info(f"Feed {feed['name']}: stored {entry_count} entries")
        except Exception as e:
            log.warning(f"Feed exception for {feed['name']}: {e}")

    db.commit()

    db.execute(
        """
        DELETE FROM news_cache WHERE feed_category = ? AND id NOT IN (
            SELECT id FROM news_cache WHERE feed_category = ? ORDER BY fetched_at DESC LIMIT 200
        )
        """,
        (category, category),
    )
    db.commit()


@router.get("/{category}")
@limiter.limit("30/minute")
async def get_news(request: Request, category: str, db: sqlite3.Connection = Depends(get_db)):
    if category not in FEEDS:
        return []

    if cache_is_stale(db, category):
        refresh_category(db, category)

    rows = db.execute(
        """
        SELECT feed_source, title, url, summary, published_at, fetched_at
        FROM news_cache
        WHERE feed_category = ?
        ORDER BY fetched_at DESC, id DESC
        LIMIT 60
        """,
        (category,),
    ).fetchall()

    return [dict(row) for row in rows]
