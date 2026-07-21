"""
Tier 2 — Telegram Bot API enrichment via getChat / getChatMemberCount.

Confirmed against the current Bot API docs (core.telegram.org/bots/api,
2026-07-21): ChatFullInfo has no member-count field, so getChatMemberCount is
a required second call. Bots cannot resolve arbitrary users or other bots by
username (getChat only works for chats/channels the bot has a relationship
to) — that's an expected, permanent limitation, not a bug, so this tier is
skipped entirely (NOT_APPLICABLE) for user/bot entity types rather than making
a call we already know will fail.

The bot token NEVER appears in a log line or an API response — every error
path below returns a fixed, generic message.
"""
import json
import logging

from app.config import TELEGRAM_BOT_TOKEN
from app.utils.safe_fetch import safe_fetch, SafeFetchError

log = logging.getLogger("falconeye.telegram")

OK = "ok"
NO_CREDS = "no_creds"
NOT_APPLICABLE = "not_applicable"
NOT_FOUND = "not_found"
ERROR = "error"

_TIMEOUT = 10.0
_APPLICABLE_TYPES = ("channel", "group", "supergroup")


async def _call(method: str, chat_id: str) -> dict:
    """One Bot API GET call. Raises RuntimeError with a token-free message on
    any failure; never includes the request URL (which embeds the token) in
    a log line or exception message."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/{method}?chat_id={chat_id}"
    try:
        result = await safe_fetch(url, timeout=_TIMEOUT)
    except SafeFetchError:
        log.warning("telegram tier2: %s fetch failed", method)
        raise RuntimeError(f"{method} fetch error")
    try:
        return json.loads(result["body"])
    except Exception:
        log.warning("telegram tier2: %s returned malformed JSON", method)
        raise RuntimeError(f"{method} malformed response")


async def run(identifier: str, entity_type: str) -> dict:
    if not TELEGRAM_BOT_TOKEN:
        return {"ok": False, "state": NO_CREDS, "data": {}, "error": "Bot API token not configured"}
    if entity_type not in _APPLICABLE_TYPES:
        return {"ok": False, "state": NOT_APPLICABLE, "data": {}, "error": "Bot API cannot resolve users or bots by username"}

    chat_id = f"@{identifier}"
    try:
        chat_resp = await _call("getChat", chat_id)
    except RuntimeError as exc:
        return {"ok": False, "state": ERROR, "data": {}, "error": str(exc)}

    if not chat_resp.get("ok"):
        desc = (chat_resp.get("description") or "").lower()
        if "not found" in desc:
            return {"ok": False, "state": NOT_FOUND, "data": {}, "error": "Chat not found via Bot API"}
        return {"ok": False, "state": ERROR, "data": {}, "error": chat_resp.get("description") or "Bot API error"}

    chat = chat_resp["result"]

    member_count = None
    try:
        count_resp = await _call("getChatMemberCount", chat_id)
        if count_resp.get("ok"):
            member_count = count_resp.get("result")
    except RuntimeError:
        pass  # non-fatal — getChat's data still stands without a count

    pinned = chat.get("pinned_message") or {}
    data = {
        "title": chat.get("title"),
        "username": chat.get("username"),
        "description": chat.get("description"),
        "bio": chat.get("bio"),
        "invite_link": chat.get("invite_link"),
        "linked_chat_id": chat.get("linked_chat_id"),
        "member_count": member_count,
        "slow_mode_delay": chat.get("slow_mode_delay"),
        "has_protected_content": chat.get("has_protected_content"),
        "has_hidden_members": chat.get("has_hidden_members"),
        "pinned_message_text": pinned.get("text") or pinned.get("caption"),
    }
    return {"ok": True, "state": OK, "data": data, "error": None}
