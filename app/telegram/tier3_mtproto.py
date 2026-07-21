"""
Tier 3 — MTProto via Telethon, using the API_ID/API_HASH/session file bootstrapped
by scripts/telegram_login.py (run once, interactively, over SSH). Reaches depth
scraping and the Bot API can't: user resolution, verified/scam/fake flags,
DC geolocation, and a rough account-age estimate.

Connection lifecycle: one client is lazily connected on first use per gunicorn
worker process and reused after that (repeatedly connecting/disconnecting per
request is slow and looks anomalous to Telegram). Known caveat: gunicorn runs
multiple worker processes, and Telethon's sqlite session file is not designed
for concurrent multi-process access — under concurrent load this can
occasionally raise "database is locked", which is caught below and surfaces as
a transient tier-3 error rather than a crash. Revisit if this proves frequent
in practice (e.g. pin tier-3 traffic to one worker).

FLOOD_WAIT handling: Telethon raises FloodWaitError with the required wait in
seconds. Waits at or under _FLOOD_WAIT_CAP_SECONDS are slept through inline;
anything longer is reported as a flood_wait state so a single request can't
hang for an unbounded amount of time.
"""
import asyncio
import logging
import os
import sqlite3

from telethon import TelegramClient
from telethon.errors import FloodWaitError, UsernameInvalidError, UsernameNotOccupiedError
from telethon.tl.functions.channels import GetFullChannelRequest
from telethon.tl.functions.users import GetFullUserRequest
from telethon.tl.types import Chat, Channel, User

from app.config import TELEGRAM_API_ID, TELEGRAM_API_HASH, TELEGRAM_SESSION_PATH

log = logging.getLogger("falconeye.telegram")

OK = "ok"
NO_CREDS = "no_creds"
NOT_AUTHENTICATED = "not_authenticated"
NOT_FOUND = "not_found"
FLOOD_WAIT = "flood_wait"
ERROR = "error"

_FLOOD_WAIT_CAP_SECONDS = 10

# Public, stable, widely-documented MTProto DC locations (core.telegram.org/api/datacenter
# and corroborated across client implementations), confirmed 2026-07-21.
_DC_LOCATIONS = {
    1: "Miami, USA", 2: "Amsterdam, Netherlands", 3: "Miami, USA",
    4: "Amsterdam, Netherlands", 5: "Singapore",
}

# Rough ID -> signup-era lookup ONLY. Telegram IDs trend upward with signup
# time but are sharded across registration servers (not perfectly sequential)
# and the ID space was widened from 32-bit to 64-bit in 2021, which breaks
# naive linear interpolation across that boundary. Checkpoints are derived
# from Telegram's own publicly announced user-count milestones, not a
# verified ID audit — treat this as an order-of-magnitude estimate, not a date.
_ID_ERA_CHECKPOINTS = [
    (10_000_000, "2013-2014"),
    (100_000_000, "2015-2016"),
    (200_000_000, "2017-2018"),
    (400_000_000, "2019-2020"),
    (700_000_000, "2021"),
    (1_000_000_000, "2022-2023"),
    (2_000_000_000, "2024-2025"),
]

_creds_ok = bool(TELEGRAM_API_ID and TELEGRAM_API_HASH and TELEGRAM_SESSION_PATH)
_client: TelegramClient | None = None
_client_lock = asyncio.Lock()


def estimate_account_era(entity_id: int) -> str:
    for threshold, era in _ID_ERA_CHECKPOINTS:
        if entity_id <= threshold:
            return era
    return "2026 or later"


def _dc_location(photo) -> str | None:
    dc_id = getattr(photo, "dc_id", None)
    if dc_id is None:
        return None
    loc = _DC_LOCATIONS.get(dc_id)
    return f"DC{dc_id} ({loc})" if loc else f"DC{dc_id}"


async def _get_client() -> TelegramClient | None:
    global _client
    if not _creds_ok or not os.path.exists(TELEGRAM_SESSION_PATH):
        return None
    async with _client_lock:
        if _client is None:
            c = TelegramClient(TELEGRAM_SESSION_PATH, int(TELEGRAM_API_ID), TELEGRAM_API_HASH)
            try:
                await c.connect()
            except Exception as exc:
                log.error("telegram tier3: connect failed: %s", type(exc).__name__)
                return None
            if not await c.is_user_authorized():
                await c.disconnect()
                log.warning("telegram tier3: session file present but not authorized")
                return None
            _client = c
        elif not _client.is_connected():
            try:
                await _client.connect()
            except Exception as exc:
                log.error("telegram tier3: reconnect failed: %s", type(exc).__name__)
                return None
    return _client


async def _with_flood_wait_retry(coro_fn):
    try:
        return await coro_fn()
    except FloodWaitError as exc:
        if exc.seconds <= _FLOOD_WAIT_CAP_SECONDS:
            await asyncio.sleep(exc.seconds)
            return await coro_fn()
        raise


def _build_user_data(u: User, full) -> dict:
    about = None
    try:
        about = full.full_user.about
    except AttributeError:
        pass
    return {
        "entity_type": "bot" if u.bot else "user",
        "id": u.id,
        "display_name": " ".join(filter(None, [u.first_name, u.last_name])) or None,
        "username": u.username,
        "verified": bool(u.verified),
        "scam": bool(u.scam),
        "fake": bool(u.fake),
        "premium": bool(getattr(u, "premium", False)),
        "bio": about,
        "dc_location": _dc_location(u.photo),
        "account_era_estimate": estimate_account_era(u.id),
        "phone_visible": bool(getattr(u, "phone", None)),
    }


def _build_channel_data(c: Channel, full) -> dict:
    fc = full.full_chat
    return {
        "entity_type": "group" if c.megagroup else "channel",
        "id": c.id,
        "display_name": c.title,
        "username": c.username,
        "verified": bool(c.verified),
        "scam": bool(c.scam),
        "fake": bool(c.fake),
        "bio": getattr(fc, "about", None),
        "member_count": getattr(fc, "participants_count", None),
        "dc_location": _dc_location(c.photo),
        "account_era_estimate": estimate_account_era(c.id),
    }


def _build_chat_data(c: Chat) -> dict:
    return {
        "entity_type": "group",
        "id": c.id,
        "display_name": c.title,
        "member_count": getattr(c, "participants_count", None),
    }


async def _resolve(client: TelegramClient, identifier: str) -> dict | None:
    ent = await _with_flood_wait_retry(lambda: client.get_entity(f"@{identifier}"))
    if isinstance(ent, User):
        full = await _with_flood_wait_retry(lambda: client(GetFullUserRequest(ent)))
        return _build_user_data(ent, full)
    if isinstance(ent, Channel):
        full = await _with_flood_wait_retry(lambda: client(GetFullChannelRequest(ent)))
        return _build_channel_data(ent, full)
    if isinstance(ent, Chat):
        return _build_chat_data(ent)
    return None


async def run(identifier: str) -> dict:
    if not _creds_ok:
        return {"ok": False, "state": NO_CREDS, "data": {}, "error": "MTProto API_ID/API_HASH/SESSION_PATH not configured"}

    client = await _get_client()
    if client is None:
        return {"ok": False, "state": NOT_AUTHENTICATED, "data": {}, "error": "MTProto session not authenticated"}

    try:
        data = await _resolve(client, identifier)
    except FloodWaitError as exc:
        return {"ok": False, "state": FLOOD_WAIT, "data": {}, "error": f"Rate limited by Telegram; retry after {exc.seconds}s"}
    except (ValueError, UsernameNotOccupiedError, UsernameInvalidError):
        return {"ok": False, "state": NOT_FOUND, "data": {}, "error": "No entity resolves for this identifier"}
    except sqlite3.OperationalError:
        log.warning("telegram tier3: session database busy")
        return {"ok": False, "state": ERROR, "data": {}, "error": "MTProto session busy, try again"}
    except Exception as exc:
        log.error("telegram tier3: resolve failed: %s", type(exc).__name__)
        return {"ok": False, "state": ERROR, "data": {}, "error": type(exc).__name__}

    if data is None:
        return {"ok": False, "state": ERROR, "data": {}, "error": "Unrecognized entity type"}

    return {"ok": True, "state": OK, "data": data, "error": None}
