"""
CAIDA Hoiho for the Route Map tab: this instance's configuration, the
routemap package's client.

The client itself (the API shape, the batching, the gate on what may leave the
server) moved to ``routemap.engine.hoiho`` in v3.36.0; read that module's
docstring for why hostnames come first and what the API returns. What stays here
is what only FalconEye knows:

  * ``HOIHO_ENABLED``, ``HOIHO_BASE_URL`` and ``HOIHO_TIMEOUT_SECONDS`` from the
    environment
  * the User-Agent naming this instance's operator
  * the cache: router hostnames, 30 days, in the application database's
    ``route_map_hostname_cache`` table, exactly as before the move

Everything is read at call time, so switching the source off (or a test
patching any name here) takes effect on the next trace.
"""
from __future__ import annotations

import logging

import httpx
from routemap.engine import hoiho as _engine

from app.config import HOIHO_BASE_URL, HOIHO_CACHE_TTL_HOURS, HOIHO_ENABLED, HOIHO_TIMEOUT_SECONDS, OPERATOR_CONTACT_UA
from app.utils import cache
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.routemap.hoiho")

CACHE_TABLE = "route_map_hostname_cache"
USER_AGENT = f"FalconEye/3.35 ({OPERATOR_CONTACT_UA}; traceroute geolocation)"

BATCH_SIZE = _engine.BATCH_SIZE
_match_to_record = _engine.match_to_record


def init_table() -> None:
    """Self-init, matching every other router: a database created fresh rather
    than migrated in place must not 500 the tab on its first lookup."""
    cache.init_table(CACHE_TABLE, key_col="hostname")


init_table()


class _DatabaseCache:
    """The engine's cache protocol over FalconEye's SQLite cache table.

    ``cache.get`` and ``cache.set`` are looked up on the module at call time,
    deliberately, so a test that patches ``app.utils.cache.get`` is patching
    what this uses.
    """

    def get(self, key: str) -> dict | None:
        record = cache.get(CACHE_TABLE, key, HOIHO_CACHE_TTL_HOURS, key_col="hostname")
        if record is None:
            return None
        record.pop("cache_hit", None)
        record.pop("fetched_at", None)
        return record

    def set(self, key: str, value: dict) -> None:
        cache.set(CACHE_TABLE, key, value, key_col="hostname")


def _client() -> _engine.Hoiho:
    return _engine.Hoiho(base_url=HOIHO_BASE_URL, timeout=HOIHO_TIMEOUT_SECONDS,
                         user_agent=USER_AGENT, cache=_DatabaseCache())


async def _post_batch(client: httpx.AsyncClient, hostnames: list[str]) -> tuple[dict, str | None]:
    """One POST /lookups with this instance's settings. Never raises."""
    return await _client().post_batch(client, hostnames)


async def lookup(hostnames: list[str]) -> tuple[dict, str | None]:
    """Locate every hostname. Returns (records, ruleset_date), or
    ``({}, None)`` when the source is switched off on this instance."""
    if not HOIHO_ENABLED:
        return {}, None
    return await _client().lookup(hostnames)


async def lookup_one(hostname: str) -> dict | None:
    """One hostname, for the GET form. Used by the tests and by nothing else."""
    records, _ = await lookup([hostname])
    record = records.get((hostname or "").strip().strip("."))
    if record is None:
        log.info("event=hoiho_miss hostname=%s", tag(hostname))
    return record
