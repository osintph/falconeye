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
import hashlib
import logging
import os
import time

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
    """Execute one run to completion and finalize it (render the PDF, cache the
    result briefly, write the metadata audit). Returns the one-time payload.

    One-time model: result content is NOT written to durable tables. It lives in
    the ephemeral result cache plus the PDF file, both purged on download or by
    the TTL sweep. Only a metadata audit row lasts.
    """
    scan = store.get_scan(scan_id)
    if not scan:
        raise RuntimeError("scan row missing")
    domain = scan["domain"]
    kind = scan.get("kind") or "asm"
    store.set_scan_running(scan_id)
    log.info("asm run start id=%s kind=%s subject=%s", scan_id, kind, tag(domain))

    try:
        if kind == "hunt":
            from app.hunt import engine as hunt_engine
            payload = await asyncio.wait_for(
                hunt_engine.execute(scan), timeout=config.ASM_RUN_TIMEOUT_SECONDS)
        else:
            payload = await asyncio.wait_for(
                _execute_asm(scan), timeout=config.ASM_RUN_TIMEOUT_SECONDS)
    except asyncio.TimeoutError as exc:
        store.fail_scan(scan_id, "run exceeded the time cap")
        raise RuntimeError("run timeout") from exc

    _finalize(scan, payload)
    return payload


def _finalize(scan: dict, payload: dict) -> None:
    """Render the PDF, cache the result, write the audit, mark the scan done."""
    scan_id = scan["scan_id"]
    kind = payload.get("kind", "asm")
    pdf_path = None
    try:
        from app.pdf import report as pdf_report
        os.makedirs(config.ASM_PDF_DIR, exist_ok=True)
        pdf_path = os.path.join(config.ASM_PDF_DIR, scan_id + ".pdf")
        pdf_report.render_report(payload, pdf_path)
    except Exception as exc:  # noqa: BLE001 - a PDF failure must not lose the result
        log.warning("asm pdf render failed id=%s: %s", scan_id, exc)
        pdf_path = None
    payload["pdf_ready"] = bool(pdf_path)

    store.cache_result(scan_id, kind, payload, pdf_path or "")
    counts = payload.get("severity_counts") or {}
    domain_hash = hashlib.sha256((scan.get("domain") or "").encode("utf-8")).hexdigest()[:32]
    store.record_scan_audit(scan_id, kind, scan.get("mode", ""), int(bool(scan.get("operator"))),
                            scan.get("engagement") or "", domain_hash,
                            payload.get("hosts_probed") or len(payload.get("candidates") or []),
                            {k: counts.get(k, 0) for k in ("critical", "high", "medium", "low")})
    # The scan row keeps only metadata: state done plus the counts, not content.
    store.finish_scan(scan_id, {"severity_counts": counts, "incomplete": payload.get("incomplete", False)})
    log.info("asm run done id=%s kind=%s incomplete=%s", scan_id, kind, payload.get("incomplete"))


async def _execute_asm(scan: dict) -> dict:
    scan_id, domain = scan["scan_id"], scan["domain"]
    disc = await discovery.discover(domain)
    reg = disc.get("registrable") or registrable(domain) or domain

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
    return report.build_asm_payload(scan, records, found, disc, posture, time.time())
