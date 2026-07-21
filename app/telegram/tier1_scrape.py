"""
Tier 1 — free scraping of t.me's public preview pages. No credentials needed,
always attempted first, works for ANY entity type (the old Channel Inspector
only handled t.me/s/{channel}, which 404s for users, bots, and channels/groups
without preview enabled).

Detection rules below were confirmed empirically (2026-07-21) by fetching real
t.me/{identifier} pages for a known user, bot, channel, and supergroup, since
t.me's HTML has no explicit "type" field:
  - No .tgme_page_title element at all -> t.me has nothing on this identifier
    (this is also what a syntactically-valid-but-unowned username returns, so
    it means "unresolved", not a confirmed absence — tier 3 gets a chance to
    resolve it before we call it not-found).
  - Action button text "Start Bot" -> bot.
  - .tgme_page_extra text containing "member(s)" -> group/supergroup.
  - .tgme_page_extra text containing "subscriber(s)" (incl. "no subscribers")
    -> channel (a personal account with public broadcast enabled, e.g. @durov,
    also lands here — tier 3's entity type is authoritative when available).
  - Anything else (no counter, "Send Message"/"View in Telegram" action) -> user.
  - .verified-icon inside .tgme_page_title -> verified badge.
  - .tgme_page_context_link_wrap a[href^="/s/"] -> a channel-style preview page
    exists at t.me/s/{identifier} (confirmed: NOT present for groups even when
    public, so it is not attempted for the "group" type).
"""
import logging
import re

from bs4 import BeautifulSoup

from app.telegram import entity
from app.utils.safe_fetch import safe_fetch, SafeFetchError

log = logging.getLogger("falconeye.telegram")

OK = "ok"
UNRESOLVED = "unresolved"
ERROR = "error"

FETCH_TIMEOUT = 15.0
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

_COUNT_RE = re.compile(r'([\d][\d\s ,]*)\s*(members?|subscribers?|monthly users)', re.IGNORECASE)


def _parse_count(text: str) -> int | None:
    if not text:
        return None
    if re.search(r'\bno\s+(members?|subscribers?)\b', text, re.IGNORECASE):
        return 0
    m = _COUNT_RE.search(text)
    if not m:
        return None
    digits = re.sub(r'[^\d]', '', m.group(1))
    return int(digits) if digits else None


def _detect_entity_type(action_text: str, extra_texts: list[str]) -> str:
    if (action_text or "").strip().lower() == "start bot":
        return "bot"
    combined = " ".join(extra_texts)
    if re.search(r'\bmembers?\b', combined, re.IGNORECASE):
        return "group"
    if re.search(r'\bsubscribers?\b', combined, re.IGNORECASE):
        return "channel"
    return "user"


def _parse_profile_page(html: str, identifier: str) -> dict | None:
    soup = BeautifulSoup(html, "lxml")

    title_el = soup.select_one(".tgme_page_title")
    if not title_el:
        return None  # unresolved — see module docstring

    name_span = title_el.select_one("span")
    display_name = name_span.get_text(strip=True) if name_span else title_el.get_text(strip=True)
    verified = title_el.select_one(".verified-icon") is not None

    action_el = soup.select_one(".tgme_page_action a")
    action_text = action_el.get_text(strip=True) if action_el else ""

    extra_texts = [el.get_text(strip=True) for el in soup.select(".tgme_page_extra")]
    entity_type = _detect_entity_type(action_text, extra_texts)

    member_count = None
    for t in extra_texts:
        member_count = _parse_count(t)
        if member_count is not None:
            break

    desc_el = soup.select_one(".tgme_page_description")
    description = desc_el.get_text(strip=True) if desc_el else ""

    photo_el = soup.select_one(".tgme_page_photo_image")
    photo_url = photo_el.get("src") if photo_el else None

    has_preview = soup.select_one('.tgme_page_context_link_wrap a[href^="/s/"]') is not None

    return {
        "entity_type": entity_type,
        "display_name": display_name,
        "verified": verified,
        "description": description,
        "photo_url": photo_url,
        "member_count": member_count,
        "has_preview": has_preview and entity_type != "group",
        "messages": [],
    }


def _parse_preview_messages(html: str) -> list[dict]:
    """Reuses the old Channel Inspector's message-preview parser (t.me/s/{x})."""
    soup = BeautifulSoup(html, "lxml")
    messages = []
    for msg_el in soup.select(".tgme_widget_message"):
        data_post = msg_el.get("data-post", "")
        msg_id = data_post.split("/")[-1] if data_post else None
        msg_link = f"https://t.me/{data_post}" if data_post else None

        body_el = msg_el.select_one(".tgme_widget_message_text")
        body_text = body_el.get_text(separator="\n", strip=True) if body_el else ""

        time_el = msg_el.select_one(".tgme_widget_message_date time")
        timestamp = time_el.get("datetime") if time_el else None

        views_el = msg_el.select_one(".tgme_widget_message_views")
        views = views_el.get_text(strip=True) if views_el else None

        forward_el = msg_el.select_one(".tgme_widget_message_forwarded_from_name")
        forwarded_from = forward_el.get_text(strip=True) if forward_el else None

        inline_links = []
        if body_el:
            for a in body_el.select("a[href]"):
                href = a.get("href", "").strip()
                if href.startswith("http"):
                    inline_links.append(href)

        messages.append({
            "id": msg_id,
            "link": msg_link,
            "timestamp": timestamp,
            "body": body_text[:2000],
            "views": views,
            "forwarded_from": forwarded_from,
            "inline_links": inline_links[:20],
        })
    return messages


async def _fetch(url: str) -> str:
    result = await safe_fetch(
        url, headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}, timeout=FETCH_TIMEOUT,
    )
    if result["status"] != 200:
        raise SafeFetchError(f"HTTP {result['status']}")
    return result["body"]


async def run(identifier: str) -> dict:
    try:
        html = await _fetch(f"https://t.me/{identifier}")
    except SafeFetchError as exc:
        log.warning("telegram tier1: fetch failed for %s: %s", identifier, exc)
        return {"ok": False, "state": ERROR, "data": {}, "error": str(exc)}
    except Exception as exc:
        log.warning("telegram tier1: unexpected error for %s: %s", identifier, type(exc).__name__)
        return {"ok": False, "state": ERROR, "data": {}, "error": type(exc).__name__}

    data = _parse_profile_page(html, identifier)
    if data is None:
        return {"ok": False, "state": UNRESOLVED, "data": {}, "error": "No public t.me page for this identifier"}

    if data["has_preview"]:
        try:
            preview_html = await _fetch(f"https://t.me/s/{identifier}")
            data["messages"] = _parse_preview_messages(preview_html)
        except Exception as exc:
            log.info("telegram tier1: preview fetch skipped for %s: %s", identifier, type(exc).__name__)

    return {"ok": True, "state": OK, "data": data, "error": None}
