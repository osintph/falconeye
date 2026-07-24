"""
Ransomware Watch collector.

Standalone script, run by the ransomware-collect.timer systemd unit (unit and
timer live outside the git tree — see docs/ransomware-watch-runbook.md).
Invoked as:

    /opt/falconeye/venv/bin/python -m app.collectors.ransomware_collect

with WorkingDirectory=/opt/falconeye/app_src so `app.*` imports resolve.

This is the ONLY code in FalconEye that calls ransomware.live or RansomLook.
The tab (app/ransomware/routes.py) reads local SQLite only — see Part 1 of
the v3.16.0 brief: a browser request must never trigger an outbound call to
either upstream.

Split cadence within a single process per run:
  - victims + press (PRO, X-API-KEY; falls back to the keyless v2 API on
    401/5xx, never as primary): every run (~30 min, jitter is the systemd
    timer's RandomizedDelaySec)
  - group activity, straight from RansomLook /api/hot/{7,30}: every run
  - watchlist search, RansomLook /api/search: every run
  - mirror health, RansomLook /api/health, scoped to relevant groups only
    (see store.mirror_health_candidate_groups): gated to once per ~6h via
    collector_runs, not every run — polling all ~588 RansomLook groups every
    30 minutes would be ~28k calls/day against a free single-operator service.

Credential handling: /api/health/{name} returns the raw mirror URL, which for
some groups embeds live leak-site credentials. This script never lets a raw
slug survive past the single line that hashes it — see store.hash_mirror_slug
and the write-guard in store.upsert_mirror.
"""
import asyncio
import logging
import os
import re
import sys
from datetime import datetime, timezone

import httpx

from app.config import RANSOMWARE_LIVE_API_KEY, RANSOMWARE_WATCHLIST_PATH
from app.ransomware import store

log = logging.getLogger("falconeye.ransomware.collect")

PRO_BASE = "https://api-pro.ransomware.live"
V2_BASE = "https://api.ransomware.live/v2"
RANSOMLOOK_BASE = "https://www.ransomlook.io/api"

HTTP_TIMEOUT = 20.0
MIRROR_HEALTH_INTERVAL_SECONDS = 6 * 3600
CORROBORATION_WINDOW_DAYS = 3
WATCHLIST_MIN_CHARS = 2

USER_AGENT = "FalconEye/3.16 (osintph.info; ransomware watch, non-commercial, attributed)"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get(d: dict, *keys, default=None):
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return default


# ---------- ransomware.live PRO client (+ v2 fallback) ----------

class ProClient:
    def __init__(self, key: str):
        self._key = key
        self.degraded = False  # set True if any PRO call fell back to v2 this run

    def _headers(self) -> dict:
        return {"X-API-KEY": self._key, "User-Agent": USER_AGENT}

    async def validate(self, client: httpx.AsyncClient) -> bool:
        """Startup key check. Logs a pass/fail line without ever echoing the
        key itself. Returns False for both a missing key and a rejected one —
        callers treat both as "PRO unavailable this run, fall back to v2"."""
        if not self._key:
            log.error("ransomware collector: RANSOMWARE_LIVE_API_KEY is not set - PRO key validation FAIL")
            return False
        try:
            resp = await client.get(f"{PRO_BASE}/validate", headers=self._headers())
        except httpx.HTTPError as exc:
            log.error("ransomware collector: PRO key validation FAIL (request error: %s)", type(exc).__name__)
            return False
        if resp.status_code == 200:
            log.info("ransomware collector: PRO key validation PASS")
            return True
        log.error("ransomware collector: PRO key validation FAIL (HTTP %s)", resp.status_code)
        return False

    async def _pro_get(self, client: httpx.AsyncClient, path: str, params: dict | None = None) -> httpx.Response:
        return await client.get(f"{PRO_BASE}{path}", headers=self._headers(), params=params)

    async def victims_recent(self, client: httpx.AsyncClient) -> tuple[list[dict], str]:
        try:
            resp = await self._pro_get(client, "/victims/recent")
        except httpx.HTTPError as exc:
            log.warning("ransomware collector: PRO /victims/recent request failed (%s), falling back to v2", type(exc).__name__)
            self.degraded = True
            return await self._v2_recent_victims(client), "ransomware_live_v2"

        if resp.status_code == 200:
            return resp.json().get("victims", []), "ransomware_live"
        if resp.status_code == 401 or resp.status_code >= 500:
            log.warning("ransomware collector: PRO /victims/recent HTTP %s, falling back to v2", resp.status_code)
            self.degraded = True
            return await self._v2_recent_victims(client), "ransomware_live_v2"
        log.warning("ransomware collector: PRO /victims/recent unexpected HTTP %s", resp.status_code)
        return [], "ransomware_live"

    async def victims_by_country(self, client: httpx.AsyncClient, country: str) -> tuple[list[dict], str]:
        try:
            resp = await self._pro_get(client, "/victims/", params={"country": country})
        except httpx.HTTPError as exc:
            log.warning("ransomware collector: PRO /victims/?country=%s request failed (%s)", country, type(exc).__name__)
            self.degraded = True
            return [], "ransomware_live_v2"

        if resp.status_code == 200:
            return resp.json().get("victims", []), "ransomware_live"
        if resp.status_code == 401 or resp.status_code >= 500:
            log.warning("ransomware collector: PRO /victims/?country=%s HTTP %s", country, resp.status_code)
            self.degraded = True
            # No per-country filter on the v2 fallback API; skip rather than
            # guess at a shape. The global v2 recent-victims fallback above
            # still covers whatever fraction of these happens to be recent.
            return [], "ransomware_live_v2"
        log.warning("ransomware collector: PRO /victims/?country=%s unexpected HTTP %s", country, resp.status_code)
        return [], "ransomware_live"

    async def press_recent(self, client: httpx.AsyncClient) -> list[dict]:
        try:
            resp = await self._pro_get(client, "/press/recent")
        except httpx.HTTPError as exc:
            log.warning("ransomware collector: PRO /press/recent failed (%s)", type(exc).__name__)
            return []
        if resp.status_code != 200:
            log.warning("ransomware collector: PRO /press/recent HTTP %s", resp.status_code)
            return []
        data = resp.json()
        return data.get("results", []) if isinstance(data, dict) else (data or [])

    async def _v2_recent_victims(self, client: httpx.AsyncClient) -> list[dict]:
        try:
            resp = await client.get(f"{V2_BASE}/recentvictims", headers={"User-Agent": USER_AGENT})
        except httpx.HTTPError as exc:
            log.error("ransomware collector: v2 fallback also failed (%s)", type(exc).__name__)
            return []
        if resp.status_code != 200:
            log.error("ransomware collector: v2 fallback HTTP %s", resp.status_code)
            return []
        data = resp.json()
        return data if isinstance(data, list) else []


# ---------- RansomLook client (keyless) ----------

class RansomLookClient:
    def __init__(self):
        self.available = True  # False if any call this run failed/timed out

    async def _get(self, client: httpx.AsyncClient, path: str, params: dict | None = None):
        try:
            resp = await client.get(f"{RANSOMLOOK_BASE}{path}", headers={"User-Agent": USER_AGENT}, params=params)
        except httpx.HTTPError as exc:
            log.warning("ransomware collector: RansomLook %s failed (%s)", path, type(exc).__name__)
            self.available = False
            return None
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            log.warning("ransomware collector: RansomLook %s HTTP %s", path, resp.status_code)
            self.available = False
            return None
        return resp.json()

    async def posts_since(self, client: httpx.AsyncClient, days: int) -> list[dict]:
        data = await self._get(client, "/posts", params={"days": days})
        if not data:
            return []
        return data.get("posts", [])

    async def hot(self, client: httpx.AsyncClient, days: int) -> list[dict]:
        data = await self._get(client, f"/hot/{days}")
        if not data:
            return []
        return data.get("rows", [])

    async def health(self, client: httpx.AsyncClient, group_name: str) -> list[dict]:
        data = await self._get(client, f"/health/{group_name}")
        return data or []

    async def search(self, client: httpx.AsyncClient, term: str) -> dict:
        data = await self._get(client, "/search", params={"q": term})
        return data or {}


# ---------- watchlist config ----------

_TIER_HEADER_RE = re.compile(r"^\[tier([12])\]$", re.IGNORECASE)


def load_watchlist_terms(path: str) -> list[tuple[str, int]]:
    """Two-tier config: a `[tier1]` section (high-precision proper nouns,
    alerting) and a `[tier2]` section (broad geographic terms, logged for
    review only, never alerts). '#' comments and blank lines are skipped.
    Terms shorter than WATCHLIST_MIN_CHARS are dropped before any outbound
    call is made. A term appearing before either header is skipped (with a
    warning) rather than silently guessed into a tier.

    Returns a list of (term, tier) tuples."""
    if not path or not os.path.exists(path):
        log.info("ransomware collector: no watchlist file at %s, skipping watchlist phase", path)
        return []
    terms = []
    current_tier = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            header = _TIER_HEADER_RE.match(line)
            if header:
                current_tier = int(header.group(1))
                continue
            if current_tier is None:
                log.warning("ransomware collector: watchlist term %r precedes any [tier1]/[tier2] header, skipped", line)
                continue
            if len(line) < WATCHLIST_MIN_CHARS:
                log.warning("ransomware collector: watchlist term %r shorter than %d chars, skipped", line, WATCHLIST_MIN_CHARS)
                continue
            terms.append((line, current_tier))
    return terms


# ---------- ingest phases ----------

def _extract_victim_fields(raw: dict) -> dict:
    """PRO's /victims/* and v2's /recentvictims use near-identical field
    names (group, victim, country, activity[=sector], discovered, attackdate,
    infostealer) — one extractor covers both sources.

    `permalink` is deliberately read from the `permalink` key only - PRO's
    own ransomware.live-hosted link for the victim - never from `post_url`/
    `claim_url`/`url`, which are the raw leak-site address. v2's schema has
    no `permalink` key at all, so this is naturally None for v2 fallback
    records rather than needing a source-specific branch."""
    return {
        "group_name": _get(raw, "group", default=""),
        "victim_name": _get(raw, "victim", default=""),
        "country": _get(raw, "country", default=""),
        "sector": _get(raw, "activity", default=""),
        "discovered": _get(raw, "discovered"),
        "attackdate": _get(raw, "attackdate"),
        "infostealer": raw.get("infostealer") if isinstance(raw.get("infostealer"), dict) else None,
        "permalink": raw.get("permalink"),
    }


async def run_victims_phase(pro: ProClient, ransomlook: RansomLookClient, client: httpx.AsyncClient) -> dict:
    started = _now_iso()
    conn = store._connect()
    new_count = 0
    try:
        recent, source = await pro.victims_recent(client)
        by_country = []
        for cc in store.SEA_COUNTRIES:
            rows, _ = await pro.victims_by_country(client, cc)
            by_country.extend(rows)

        all_raw = recent + by_country
        match_keys_seen = []
        for raw in all_raw:
            if not isinstance(raw, dict):
                continue
            f = _extract_victim_fields(raw)
            if not f["group_name"] or not f["victim_name"]:
                continue
            store.upsert_victim(conn, now_iso=started, first_seen_via="collector", **f)
            match_keys_seen.append(store.victim_match_key(f["group_name"], f["victim_name"]))
            new_count += 1

        # Cross-source corroboration: does this victim also show up in
        # RansomLook's own recent posts?
        rl_posts = await ransomlook.posts_since(client, CORROBORATION_WINDOW_DAYS)
        rl_keys = {
            store.victim_match_key(p.get("group_name", ""), p.get("post_title", ""))
            for p in rl_posts if isinstance(p, dict)
        }
        corroborated_keys = set(match_keys_seen) & rl_keys
        store.mark_corroborated(conn, corroborated_keys, started)

        # Press (best-effort, not fallback-covered).
        press_items = await pro.press_recent(client)
        for p in press_items:
            if not isinstance(p, dict):
                continue
            title = p.get("title") or ""
            if not title:
                continue
            rw = p.get("ransomware")
            group_name = None
            if isinstance(rw, dict):
                group_name = rw.get("group") or rw.get("group_name")
            elif isinstance(rw, str):
                group_name = rw
            has_info = bool(p.get("infostealer"))
            store.upsert_press(
                conn, title=title, group_name=group_name,
                published_at=p.get("added") or p.get("date"), has_infostealer=has_info, now_iso=started,
            )

        conn.commit()
        status = "degraded" if pro.degraded else "ok"
        detail = f"{new_count} victim rows upserted, {len(corroborated_keys)} newly corroborated, source={source}"
        store.record_run(conn, phase="victims_stats", source=source, status=status, detail=detail,
                          started_at=started, finished_at=_now_iso())
        conn.commit()
        log.info("ransomware collector: victims phase %s - %s", status, detail)
        return {"status": status, "count": new_count}
    except Exception:
        conn.rollback()
        store.record_run(conn, phase="victims_stats", source="ransomware_live", status="error",
                          detail="unhandled exception, see collector log", started_at=started, finished_at=_now_iso())
        conn.commit()
        log.exception("ransomware collector: victims phase failed")
        return {"status": "error", "count": 0}
    finally:
        conn.close()


async def run_group_activity_phase(ransomlook: RansomLookClient, client: httpx.AsyncClient) -> dict:
    started = _now_iso()
    conn = store._connect()
    try:
        total = 0
        skipped_windows = []
        for days in (7, 30):
            before = ransomlook.available
            rows = await ransomlook.hot(client, days)
            if before and not ransomlook.available:
                # This call is what failed - an empty `rows` here means
                # "unknown", not "zero active groups". Leave prior data in
                # place rather than wiping it to empty.
                skipped_windows.append(days)
                continue
            store.replace_group_activity(conn, days, rows, started)
            total += len(rows)
        conn.commit()
        status = "ok" if ransomlook.available else "degraded"
        detail = f"{total} group-activity rows across 7d/30d windows"
        if skipped_windows:
            detail += f"; {skipped_windows} window(s) unreachable, prior data kept"
        store.record_run(conn, phase="group_activity", source="ransomlook", status=status, detail=detail,
                          started_at=started, finished_at=_now_iso())
        conn.commit()
        log.info("ransomware collector: group activity phase %s - %s", status, detail)
        return {"status": status}
    except Exception:
        conn.rollback()
        store.record_run(conn, phase="group_activity", source="ransomlook", status="error",
                          detail="unhandled exception, see collector log", started_at=started, finished_at=_now_iso())
        conn.commit()
        log.exception("ransomware collector: group activity phase failed")
        return {"status": "error"}
    finally:
        conn.close()


async def run_mirror_health_phase(ransomlook: RansomLookClient, client: httpx.AsyncClient) -> dict:
    started = _now_iso()
    conn = store._connect()
    try:
        candidates = store.mirror_health_candidate_groups(conn)
        polled = 0
        rejected = 0
        for group_name in candidates:
            entries = await ransomlook.health(client, group_name)
            if not entries:
                continue
            store.clear_mirrors_for_group(conn, group_name)
            for idx, entry in enumerate(entries, start=1):
                if not isinstance(entry, dict):
                    continue
                raw_slug = entry.get("slug") or ""
                # Hash immediately; `raw_slug` must not be referenced again
                # after this line (never stored, logged, or returned).
                mirror_hash = store.hash_mirror_slug(raw_slug)
                del raw_slug
                try:
                    store.upsert_mirror(
                        conn, group_name=group_name, position_index=idx, mirror_hash=mirror_hash,
                        uptime_30d=entry.get("uptime_30d"), series=entry.get("series") or [], now_iso=started,
                    )
                except store.CredentialGuardError:
                    rejected += 1
                    continue
            polled += 1
        conn.commit()
        status = "ok" if ransomlook.available else "degraded"
        detail = f"polled {polled}/{len(candidates)} candidate groups"
        if rejected:
            detail += f", {rejected} mirror values rejected by the credential write-guard"
        store.record_run(conn, phase="mirror_health", source="ransomlook", status=status, detail=detail,
                          started_at=started, finished_at=_now_iso())
        conn.commit()
        log.info("ransomware collector: mirror health phase %s - %s", status, detail)
        return {"status": status}
    except Exception:
        conn.rollback()
        store.record_run(conn, phase="mirror_health", source="ransomlook", status="error",
                          detail="unhandled exception, see collector log", started_at=started, finished_at=_now_iso())
        conn.commit()
        log.exception("ransomware collector: mirror health phase failed")
        return {"status": "error"}
    finally:
        conn.close()


async def run_watchlist_phase(ransomlook: RansomLookClient, client: httpx.AsyncClient, watchlist_path: str) -> dict:
    started = _now_iso()
    conn = store._connect()
    try:
        terms = load_watchlist_terms(watchlist_path)
        hits = 0
        for term, tier in terms:
            if len(term) < WATCHLIST_MIN_CHARS:
                continue  # defense in depth; load_watchlist_terms already filters this
            result = await ransomlook.search(client, term)
            for match_type in ("posts", "groups", "markets", "leaks", "notes"):
                for item in result.get(match_type, []) or []:
                    if not isinstance(item, dict):
                        continue
                    matched_name = item.get("post_title") or item.get("name") or item.get("group_name")
                    group_name = item.get("group_name") or item.get("group")
                    store.record_watchlist_hit(
                        conn, term=term, tier=tier, match_type=match_type, matched_name=matched_name,
                        group_name=group_name, discovered=item.get("discovered"), now_iso=started,
                    )
                    hits += 1
        conn.commit()
        status = "ok" if ransomlook.available else "degraded"
        detail = f"{hits} hits across {len(terms)} watchlist terms"
        store.record_run(conn, phase="watchlist", source="ransomlook", status=status, detail=detail,
                          started_at=started, finished_at=_now_iso())
        conn.commit()
        log.info("ransomware collector: watchlist phase %s - %s", status, detail)
        return {"status": status}
    except Exception:
        conn.rollback()
        store.record_run(conn, phase="watchlist", source="ransomlook", status="error",
                          detail="unhandled exception, see collector log", started_at=started, finished_at=_now_iso())
        conn.commit()
        log.exception("ransomware collector: watchlist phase failed")
        return {"status": "error"}
    finally:
        conn.close()


def _mirror_health_due() -> bool:
    conn = store._connect()
    try:
        row = store.last_run(conn, "mirror_health")
    finally:
        conn.close()
    if not row:
        return True
    try:
        last = datetime.fromisoformat(row["finished_at"])
    except (TypeError, ValueError):
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - last).total_seconds()
    return age >= MIRROR_HEALTH_INTERVAL_SECONDS


async def run_once() -> None:
    store.init_tables()
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        pro = ProClient(RANSOMWARE_LIVE_API_KEY)
        await pro.validate(client)  # logs pass/fail; PRO calls below self-degrade to v2 regardless

        ransomlook = RansomLookClient()

        await run_victims_phase(pro, ransomlook, client)
        await run_group_activity_phase(ransomlook, client)
        await run_watchlist_phase(ransomlook, client, RANSOMWARE_WATCHLIST_PATH)

        if _mirror_health_due():
            await run_mirror_health_phase(ransomlook, client)
        else:
            log.info("ransomware collector: mirror health not due yet, skipped this run")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    asyncio.run(run_once())


if __name__ == "__main__":
    main()
