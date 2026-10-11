"""The background scan runner, with a cap and queue shared across all workers.

Scans do not run in the request worker. POST /scan creates the scan row ('queued')
and submits a job here; the route returns a scan id immediately and the UI polls
for status. The concurrency cap and the queue are SQLITE-BACKED, not in-process,
so they hold across all gunicorn workers: a worker only moves a scan from 'queued'
to 'running' through store.claim_scan_slot, whose single UPDATE atomically checks
that fewer than ASM_MAX_CONCURRENT_SCANS are running globally. Queue depth and
occupancy are read from the scan table too. Monitoring reuses run_scan directly
(synchronously, in the timer process), so there is one scan path.

A worker recycle loses an in-flight job: a 'running' row then ages out of the slot
accounting after the run-time budget plus slack, freeing the slot; a 'queued' row
left behind ages out of the queue accounting. No em dashes in this module.
"""
from __future__ import annotations

import asyncio
import logging

from app import config
from app.asm import discovery, findings as findings_mod, probe, report, store
from app.scanner.scope import registrable
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.asm.jobs")


def _slack() -> int:
    # A running row older than the run-time budget plus a minute is treated as a
    # dead worker's leftover and no longer holds its slot.
    return int(config.ASM_RUN_TIMEOUT_SECONDS) + 60


def capacity() -> dict:
    """Current runner occupancy, read from the shared scan table."""
    return {"active": store.count_running_scans(_slack()),
            "queued": store.count_recent_queued_scans(_slack()),
            "max_concurrent": config.ASM_MAX_CONCURRENT_SCANS,
            "queue_max": config.ASM_SCAN_QUEUE_MAX}


def can_accept() -> bool:
    c = capacity()
    return (c["active"] + c["queued"]) < (config.ASM_MAX_CONCURRENT_SCANS + config.ASM_SCAN_QUEUE_MAX)


def submit(scan_id: str) -> bool:
    """Schedule a scan as a background task in this worker. The global cap is
    enforced when the task claims a slot, not here."""
    asyncio.ensure_future(_runner(scan_id))
    return True


async def _runner(scan_id: str) -> None:
    # Wait for a global slot, then run. The claim is atomic across workers.
    deadline = store.now() + int(config.ASM_RUN_TIMEOUT_SECONDS)
    try:
        while not store.claim_scan_slot(scan_id, config.ASM_MAX_CONCURRENT_SCANS, _slack()):
            if store.now() >= deadline:
                store.fail_scan(scan_id, "timed out waiting for a free scan slot")
                return
            await asyncio.sleep(2)
        await run_scan(scan_id)
    except Exception as exc:  # noqa: BLE001 - a crash must mark the scan, not vanish
        log.warning("asm scan %s failed: %s", scan_id, exc)
        store.fail_scan(scan_id, str(exc))


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
