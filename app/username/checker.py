"""
Async httpx sweep of a site list for one username.

Every constructed URL is validated with the canonical SSRF primitive
(app.utils.safe_fetch.resolve_and_check) before it is fetched — the vendored
hosts are trusted and the username is strictly validated + URL-encoded upstream,
but we keep the guard for consistency with the other tabs. Hosts are resolved
once per sweep (cached) off the event loop via asyncio.to_thread.

check_one never raises: failures become a CheckResult with `error` populated.
The sweep is wall-clock bounded so a slow tail can't hold a worker past the
gunicorn timeout — un-checked sites are reported, not awaited forever.
"""
import asyncio
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import quote, urlparse

import httpx

from app.utils.safe_fetch import resolve_and_check, SafeFetchError
from app.username.parser import Site

log = logging.getLogger("falconeye.username")

USER_AGENT = "FalconEye/3.8.0 (+https://falconeye.osintph.info; OSINT username enumeration)"
_MAX_BODY = 200_000  # cap body used for substring detection


@dataclass
class CheckResult:
    site: Site
    hit: bool
    profile_url: str | None
    status_code: int | None
    error: str | None
    elapsed_ms: int


def build_url(site: Site, username_encoded: str) -> str:
    return (
        site.url_template
        .replace("{account}", username_encoded)
        .replace("{username}", username_encoded)
        .replace("{}", username_encoded)
    )


def _host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


# ---- detection ----

def _wmn_hit(det: dict, status: int, body: str) -> bool:
    e_code = det.get("e_code")
    e_string = det.get("e_string") or ""
    m_string = det.get("m_string") or ""
    if e_code is not None and status != e_code:
        return False
    if e_string and e_string not in body:
        return False
    if m_string and m_string in body:
        return False
    # A site with neither an expected string nor a distinct code is a weak signal;
    # require at least a matching e_code to call it a hit.
    if e_code is None and not e_string:
        return False
    return True


def _sherlock_hit(det: dict, status: int, body: str, location: str) -> bool:
    etype = det.get("errorType")
    if etype == "status_code":
        error_code = det.get("errorCode")
        if isinstance(error_code, int):
            return status != error_code and 200 <= status < 400
        return 200 <= status < 300
    if etype == "message":
        msgs = det.get("errorMsg")
        if isinstance(msgs, str):
            msgs = [msgs]
        elif not isinstance(msgs, list):
            msgs = []
        if status >= 400:
            return False
        return not any(m and m in body for m in msgs)
    if etype == "response_url":
        error_url = (det.get("errorUrl") or "").rstrip("/")
        if 300 <= status < 400:
            return not (error_url and (location or "").rstrip("/") == error_url)
        return 200 <= status < 300
    return False


def _evaluate(site: Site, status: int, body: str, location: str) -> bool:
    if site.detection.get("engine") == "wmn":
        return _wmn_hit(site.detection, status, body)
    return _sherlock_hit(site.detection, status, body, location)


async def check_one(client: httpx.AsyncClient, site: Site, username: str,
                    host_ok: dict) -> CheckResult:
    encoded = quote(username, safe="")
    url = build_url(site, encoded)

    ok, reason = host_ok.get(_host_of(url), (False, "host not validated"))
    if not ok:
        return CheckResult(site, False, None, None, f"blocked: {reason}", 0)

    # Sherlock regexCheck: username may be inapplicable to this site (skip, not a miss).
    rc = site.detection.get("regexCheck")
    if rc:
        try:
            if not re.search(rc, username):
                return CheckResult(site, False, None, None, "username_not_applicable", 0)
        except re.error:
            pass

    t0 = time.monotonic()
    try:
        resp = await client.get(url)
    except Exception as exc:
        return CheckResult(site, False, None, None, type(exc).__name__,
                           int((time.monotonic() - t0) * 1000))
    elapsed = int((time.monotonic() - t0) * 1000)

    body = ""
    if site.detection.get("engine") == "wmn" or site.detection.get("errorType") == "message":
        try:
            body = resp.text[:_MAX_BODY]
        except Exception:
            body = ""
    location = resp.headers.get("location", "")

    hit = _evaluate(site, resp.status_code, body, location)
    return CheckResult(site, hit, url if hit else None, resp.status_code, None, elapsed)


# The site list is fixed, so a host's SSRF verdict is stable for a process. Cache
# it (1h TTL) so only the first scan pays DNS cost; later scans reuse the verdict.
_HOST_CACHE: dict = {}   # host -> (ok: bool, reason: str|None, expires_at: float)
_HOST_TTL = 3600.0


async def _validate_hosts(hosts: set, dns_deadline: float) -> dict:
    """Resolve+SSRF-check each unique host, using the cache and a hard time cap.

    A hung/slow getaddrinfo cannot be cancelled, so we bound the whole phase with
    asyncio.wait: hosts not resolved in time default CLOSED (skipped, not cached)
    so they get another chance on the next scan.
    """
    now = time.time()
    result = {"": (False, "empty host")}
    to_resolve = []
    for h in hosts:
        if not h:
            continue
        cached = _HOST_CACHE.get(h)
        if cached and cached[2] > now:
            result[h] = (cached[0], cached[1])
        else:
            to_resolve.append(h)

    if not to_resolve:
        return result

    loop = asyncio.get_running_loop()
    # Isolated, generous pool — DNS is I/O-bound and releases the GIL; the default
    # executor (~8 workers) serializes hundreds of lookups.
    pool = ThreadPoolExecutor(max_workers=min(64, len(to_resolve)))

    async def one(host: str):
        try:
            await loop.run_in_executor(pool, resolve_and_check, host)
            return host, (True, None)
        except SafeFetchError as exc:
            return host, (False, str(exc))
        except Exception as exc:
            return host, (False, type(exc).__name__)

    task_host = {asyncio.create_task(one(h)): h for h in to_resolve}
    done, pending = await asyncio.wait(task_host.keys(), timeout=dns_deadline)
    for t in done:
        host, verdict = t.result()
        result[host] = verdict
        _HOST_CACHE[host] = (verdict[0], verdict[1], now + _HOST_TTL)
    for t in pending:
        result[task_host[t]] = (False, "dns timeout")
        t.cancel()
    pool.shutdown(wait=False)
    return result


async def sweep(sites: list, username: str, concurrency: int = 25,
                deadline_s: float = 50.0) -> tuple:
    """Run all checks under ONE wall-clock budget (deadline_s) covering both the
    DNS-validation and HTTP phases, so the whole request stays under the gunicorn
    worker timeout regardless of cold/warm host cache.

    Returns (results, unchecked_count). Sites not finished before the budget is
    spent are cancelled and counted, not awaited.
    """
    t_start = time.monotonic()
    encoded = quote(username, safe="")
    hosts = {_host_of(build_url(s, encoded)) for s in sites}

    # Give DNS up to ~30% of the budget, then hand the rest to the HTTP phase.
    dns_deadline = min(12.0, deadline_s * 0.3)
    host_ok = await _validate_hosts(hosts, dns_deadline)
    http_deadline = max(5.0, deadline_s - (time.monotonic() - t_start))

    sem = asyncio.Semaphore(concurrency)

    async def bounded(site: Site) -> CheckResult:
        async with sem:
            return await check_one(client, site, username, host_ok)

    async with httpx.AsyncClient(
        timeout=7.0,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
        limits=httpx.Limits(max_connections=concurrency + 10),
    ) as client:
        tasks = [asyncio.create_task(bounded(s)) for s in sites]
        done, pending = await asyncio.wait(tasks, timeout=http_deadline)
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    results = []
    for t in done:
        if t.cancelled() or t.exception() is not None:
            continue
        results.append(t.result())
    return results, len(pending)
