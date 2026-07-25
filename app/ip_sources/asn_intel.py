"""
ASN enrichment for the IP Reputation tab (v3.20.0).

Turns "this IP resolves to ASN N" into the operator's full announced
footprint - the pivot from one abusive IP to "the operator announces these
other 5,000 prefixes" that matters for bulletproof-host investigations.

Originally briefed against BGPview (api.bgpview.io), which turned out to have
shut down permanently on 2025-11-26 (DNS for the whole apex + api subdomain
is gone). Its replacement, bgp.tools, has no per-ASN REST API (WHOIS + full
table dumps only) and no peers/upstreams/downstreams data at all. So this
runs entirely on RIPEstat (stat.ripe.net), which is already integrated
elsewhere in this file's family (see fetch_ripestat in ip_intel.py) and is
free, no-auth, and reliable:

  - network-info      : which ASN + covering prefix a specific IP sits in
  - as-overview        : the ASN's registered holder name
  - announced-prefixes : every prefix currently visible in RIPE RIS for that
                          ASN - actual live BGP visibility, not a registration
                          superset, so (unlike the original BGPview brief)
                          there's no "treat as unverified" caveat needed here
  - asn-neighbours      : BGP-adjacent ASNs, classified by RIPE as left/right/
                          uncertain based on path position relative to their
                          route collectors. This is the closest free
                          equivalent to BGPview's peers/upstreams/downstreams,
                          but it is NOT verified settlement-free peering data
                          - it's rendered as "upstream-side" / "downstream-
                          side" and labelled with that caveat, never claimed
                          as ground truth.

Two cache scopes, both >=24h (ASN topology moves on a scale of weeks, and
RIPEstat, while generous, still deserves a light touch):
  - per-ASN identity + prefixes + neighbours, shared across every IP lookup
    that resolves into the same ASN
  - the per-IP network-info call is NOT separately cached here; it's cheap
    and already covered by the outer 6h ip_intel_cache on the whole response

Every fetcher degrades to None/False on any failure (bad response, timeout,
malformed JSON) and fetch()/fetch_routing() never raise - a broken or
rate-limited RIPEstat call must never blank or 500 the rest of the IP
Reputation result, it just makes this block report unavailable.
"""
import asyncio
import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta

import httpx

from app.config import DB_PATH
from app.ip_sources.base import FETCH_TIMEOUT, USER_AGENT

log = logging.getLogger("falconeye.ip.asn_intel")

RIPESTAT_BASE = "https://stat.ripe.net/data"
CACHE_TTL_HOURS = 24
PREFIX_SERVER_CAP = 10_000   # safety valve on payload size; Cloudflare alone announces ~5,300
NEIGHBOUR_TOP_N = 15          # per bucket, for the expand-to-load routing view


# ---- Cache table (per-ASN, keyed by call so different pieces expire independently) ----

def _init_cache():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS asn_intel_cache (
            cache_key TEXT PRIMARY KEY,
            response_json TEXT,
            fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_asn_intel_cache_fetched ON asn_intel_cache(fetched_at)")
    conn.commit()
    conn.close()


_init_cache()


def _get_cached(db: sqlite3.Connection, key: str) -> dict | None:
    row = db.execute(
        "SELECT response_json, fetched_at FROM asn_intel_cache WHERE cache_key = ?", (key,)
    ).fetchone()
    if not row:
        return None
    fetched = datetime.fromisoformat(row["fetched_at"])
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - fetched > timedelta(hours=CACHE_TTL_HOURS):
        return None
    return json.loads(row["response_json"])


def _store_cache(db: sqlite3.Connection, key: str, data: dict) -> None:
    db.execute(
        "INSERT OR REPLACE INTO asn_intel_cache (cache_key, response_json, fetched_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
        (key, json.dumps(data)),
    )
    db.commit()


# ---- RIPEstat calls ----

async def _ripe_get(client: httpx.AsyncClient, call: str, resource: str) -> dict | None:
    try:
        r = await client.get(
            f"{RIPESTAT_BASE}/{call}/data.json",
            params={"resource": resource},
            timeout=FETCH_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
    except Exception as e:
        log.warning(f"RIPEstat {call} exception for {resource}: {e}")
        return None
    if r.status_code != 200:
        log.warning(f"RIPEstat {call} returned {r.status_code} for {resource}")
        return None
    try:
        body = r.json()
    except Exception:
        return None
    if body.get("status") != "ok":
        return None
    return body.get("data")


async def fetch_network_info(client: httpx.AsyncClient, ip: str) -> tuple[int | None, str | None]:
    data = await _ripe_get(client, "network-info", ip)
    if not data:
        return None, None
    asns = data.get("asns") or []
    if not asns:
        return None, None
    try:
        asn = int(asns[0])
    except (TypeError, ValueError):
        return None, None
    return asn, data.get("prefix")


async def fetch_as_overview(client: httpx.AsyncClient, db: sqlite3.Connection, asn: int) -> dict | None:
    key = f"as_overview:{asn}"
    cached = _get_cached(db, key)
    if cached is not None:
        return cached
    data = await _ripe_get(client, "as-overview", f"AS{asn}")
    if data is None:
        return None
    _store_cache(db, key, data)
    return data


async def fetch_announced_prefixes(client: httpx.AsyncClient, db: sqlite3.Connection, asn: int) -> dict | None:
    key = f"asn_prefixes:{asn}"
    cached = _get_cached(db, key)
    if cached is not None:
        return cached
    data = await _ripe_get(client, "announced-prefixes", f"AS{asn}")
    if data is None:
        return None
    raw = data.get("prefixes") or []
    # Store the processed shape, not the raw per-prefix timelines - RIPE RIS
    # already limits this to currently-visible announcements, we just need
    # the prefix strings for display.
    prefix_strs = sorted({p.get("prefix") for p in raw if p.get("prefix")})
    total = len(prefix_strs)
    result = {
        "list": prefix_strs[:PREFIX_SERVER_CAP],
        "total_count": total,
        "truncated": total > PREFIX_SERVER_CAP,
    }
    _store_cache(db, key, result)
    return result


async def fetch_neighbours(client: httpx.AsyncClient, db: sqlite3.Connection, asn: int) -> list[dict] | None:
    key = f"asn_neighbours:{asn}"
    cached = _get_cached(db, key)
    if cached is not None:
        return cached.get("neighbours")
    data = await _ripe_get(client, "asn-neighbours", f"AS{asn}")
    if data is None:
        return None
    neighbours = data.get("neighbours") or []
    _store_cache(db, key, {"neighbours": neighbours})
    return neighbours


# ---- Assembly ----

def _split_holder(holder: str | None) -> tuple[str | None, str | None]:
    """RIPEstat's as-overview holder is typically "NAME - Description, Inc.".
    Split on the first " - " into a short handle and a longer description;
    with no dash, treat the whole string as the description."""
    holder = (holder or "").strip()
    if not holder:
        return None, None
    if " - " in holder:
        name, _, desc = holder.partition(" - ")
        return (name.strip() or None), (desc.strip() or None)
    return None, holder


def assemble_core(asn: int, ip_prefix: str | None, as_overview: dict | None, prefixes: dict | None) -> dict:
    if as_overview is None and prefixes is None:
        return {"available": False, "asn": asn}

    name, description = _split_holder((as_overview or {}).get("holder"))
    org = description or name or f"AS{asn}"  # the descriptive name reads better in a sentence than the short AS handle

    p = prefixes or {"list": [], "total_count": 0, "truncated": False}
    count = p.get("total_count", 0)
    plural = "es" if count != 1 else ""
    summary = (
        f"This IP sits in AS{asn}, {org}, which currently announces "
        f"{count:,} prefix{plural} (live BGP visibility via RIPE RIS)."
    )

    return {
        "available": True,
        "asn": asn,
        "name": name,
        "description": description,
        "covering_prefix": ip_prefix,
        "prefixes": {"count": count, "list": p.get("list", []), "truncated": p.get("truncated", False)},
        "summary": summary,
    }


async def fetch(client: httpx.AsyncClient, db: sqlite3.Connection, ip: str) -> dict:
    """Identity + announced prefixes only - the default path, folded into the
    main IP lookup. Never raises."""
    try:
        asn, ip_prefix = await fetch_network_info(client, ip)
        if not asn:
            return {"available": False}
        as_overview, prefixes = await asyncio.gather(
            fetch_as_overview(client, db, asn),
            fetch_announced_prefixes(client, db, asn),
            return_exceptions=True,
        )
        if isinstance(as_overview, Exception): as_overview = None
        if isinstance(prefixes, Exception): prefixes = None
        return assemble_core(asn, ip_prefix, as_overview, prefixes)
    except Exception as e:
        log.warning(f"ASN intel exception for {ip}: {e}")
        return {"available": False}


async def _resolve_names(client: httpx.AsyncClient, db: sqlite3.Connection, entries: list[dict]) -> dict[int, str | None]:
    targets = sorted({n["asn"] for n in entries if n.get("asn") is not None})
    if not targets:
        return {}
    results = await asyncio.gather(*[fetch_as_overview(client, db, a) for a in targets], return_exceptions=True)
    names: dict[int, str | None] = {}
    for a, r in zip(targets, results):
        if isinstance(r, dict):
            name, desc = _split_holder(r.get("holder"))
            names[a] = name or desc
    return names


async def fetch_routing(client: httpx.AsyncClient, db: sqlite3.Connection, asn: int) -> dict:
    """Peers/upstreams-equivalent - expand-to-load only, never part of the
    main lookup gather. Never raises."""
    try:
        neighbours = await fetch_neighbours(client, db, asn)
        if neighbours is None:
            return {"available": False}

        left = sorted((n for n in neighbours if n.get("type") == "left"), key=lambda n: n.get("power") or 0, reverse=True)
        right = sorted((n for n in neighbours if n.get("type") == "right"), key=lambda n: n.get("power") or 0, reverse=True)
        uncertain_count = sum(1 for n in neighbours if n.get("type") == "uncertain")

        top_left, top_right = left[:NEIGHBOUR_TOP_N], right[:NEIGHBOUR_TOP_N]
        names = await _resolve_names(client, db, top_left + top_right)

        def _fmt(bucket):
            return [{"asn": n["asn"], "name": names.get(n["asn"]), "power": n.get("power")}
                    for n in bucket if n.get("asn") is not None]

        return {
            "available": True,
            "upstream_side": {"total": len(left), "shown": _fmt(top_left)},
            "downstream_side": {"total": len(right), "shown": _fmt(top_right)},
            "uncertain_count": uncertain_count,
            "caveat": ("RIPE-inferred from BGP path position relative to route collectors "
                       "(upstream-side / downstream-side), not verified settlement-free peering data."),
        }
    except Exception as e:
        log.warning(f"ASN routing exception for AS{asn}: {e}")
        return {"available": False}
