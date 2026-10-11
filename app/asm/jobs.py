"""The background scan runner.

Scans do not run in the request worker. POST /scan creates the scan row and
submits a job here; the route returns a scan id immediately and the UI polls for
status. At most ASM_MAX_CONCURRENT_SCANS run at once; further submissions queue up
to ASM_SCAN_QUEUE_MAX, after which a submission is refused. Monitoring runs reuse
run_scan directly (synchronously, in the timer process), so there is one scan
path.

The runner is single-event-loop in-process state: the integer counters are only
mutated between awaits, so no lock is needed. A worker recycle loses an in-flight
job, which leaves its row in 'running'; that is surfaced as a stale run rather
than a wrong result. No em dashes in this module.
"""
from __future__ import annotations

import asyncio
import logging

from app import config
from app.asm import discovery, findings as findings_mod, probe, report, store
from app.scanner.scope import registrable
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.asm.jobs")

_run_sem = asyncio.Semaphore(config.ASM_MAX_CONCURRENT_SCANS)
_queued = 0
_active = 0


def capacity() -> dict:
    """Current runner occupancy, for the UI to show a queued state."""
    return {"active": _active, "queued": _queued,
            "max_concurrent": config.ASM_MAX_CONCURRENT_SCANS,
            "queue_max": config.ASM_SCAN_QUEUE_MAX}


def can_accept() -> bool:
    return (_active + _queued) < (config.ASM_MAX_CONCURRENT_SCANS + config.ASM_SCAN_QUEUE_MAX)


def submit(scan_id: str) -> bool:
    """Queue a scan as a background task. Returns False when the runner is full."""
    global _queued
    if not can_accept():
        return False
    _queued += 1
    asyncio.ensure_future(_runner(scan_id))
    return True


async def _runner(scan_id: str) -> None:
    global _queued, _active
    async with _run_sem:
        _queued -= 1
        _active += 1
        try:
            await run_scan(scan_id)
        except Exception as exc:  # noqa: BLE001 - a crash must mark the scan, not vanish
            log.warning("asm scan %s failed: %s", scan_id, exc)
            store.fail_scan(scan_id, str(exc))
        finally:
            _active -= 1


async def run_scan(scan_id: str) -> dict:
    """Execute one scan to completion and persist it. Returns the summary.

    Used both by the background runner and by the monitoring timer. Raises on an
    unrecoverable error so the caller can record it.
    """
    scan = store.get_scan(scan_id)
    if not scan:
        raise RuntimeError("scan row missing")
    domain = scan["domain"]
    store.set_scan_running(scan_id)
    log.info("asm scan start id=%s domain=%s mode=%s", scan_id, tag(domain), scan["mode"])

    try:
        summary = await asyncio.wait_for(
            _execute(scan_id, domain), timeout=config.ASM_RUN_TIMEOUT_SECONDS)
    except asyncio.TimeoutError as exc:
        store.fail_scan(scan_id, "scan exceeded the run time cap")
        raise RuntimeError("run timeout") from exc
    return summary


async def _execute(scan_id: str, domain: str) -> dict:
    disc = await discovery.discover(domain)
    reg = disc.get("registrable") or registrable(domain) or domain

    # Prioritise the apex and www, then the rest, then apply the host cap.
    names = list(disc.get("hosts") or [])
    priority = [domain, f"www.{domain}"]
    ordered = [h for h in priority if h in names] + [h for h in names if h not in priority]
    ordered = ordered[:config.ASM_MAX_HOSTS_PER_RUN]

    sem_ports = asyncio.Semaphore(config.ASM_PORT_CONCURRENCY)
    host_sem = asyncio.Semaphore(config.ASM_HOST_CONCURRENCY)

    async def _one(host: str):
        async with host_sem:
            try:
                return await asyncio.wait_for(
                    probe.probe_host(host, reg, sem_ports=sem_ports,
                                     port_timeout=config.ASM_PORT_TIMEOUT_SECONDS),
                    timeout=config.ASM_HOST_TIMEOUT_SECONDS)
            except Exception as exc:  # noqa: BLE001 - one host must not sink the run
                log.info("asm probe gave up on %s: %s", tag(host), type(exc).__name__)
                return None

    records = [r for r in await asyncio.gather(*[_one(h) for h in ordered]) if r]
    posture = await probe.apex_mail_posture(domain)
    found = findings_mod.build(domain, records, posture)

    for r in records:
        store.add_host(scan_id, r["host"], r.get("resolved_ips"), r.get("cname"),
                       r.get("is_reference", 0),
                       r.get("cdn_provider") or (r.get("cname_target") if r.get("kind") == "reference" else ""),
                       r.get("http"), r.get("tls"), {"tech": r.get("fingerprint") or []},
                       r.get("open_ports"))
    for f in found:
        store.add_finding(scan_id, f.get("host"), f["severity"], f["kind"], f["title"], f.get("detail", ""))

    summary = report.summarize(domain, records, found, disc, posture)
    store.finish_scan(scan_id, summary)
    log.info("asm scan done id=%s domain=%s hosts=%d findings=%d",
             scan_id, tag(domain), len(records), len(found))
    return summary
