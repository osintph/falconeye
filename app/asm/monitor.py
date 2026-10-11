"""Scheduled monitoring: re-verify, scan, diff, notify, prune.

Opt-in per verified domain (or per operator-added domain with an engagement
reference). A systemd timer runs scripts/asm_monitor.py, which calls run_due().
For each domain that is due:

  1. Re-verify ownership. DNS grants re-check the TXT record is still present;
     email grants re-check that a valid grant still exists. On failure the domain
     is paused and the owner is notified, and it is NOT scanned.
  2. Run a scan (reusing jobs.run_scan).
  3. Snapshot the result and diff it against the previous snapshot.
  4. Email the diff, over the existing mail path, ONLY when something changed.
  5. Save the new snapshot and prune snapshots past the retention window.

No em dashes in this module.
"""
from __future__ import annotations

import asyncio
import logging
import secrets

from app import config
from app.asm import jobs, mailer, report, store, verify
from app.utils.logsafe import tag

log = logging.getLogger("falconeye.asm.monitor")

_FREQ_SECONDS = {"daily": 86400, "weekly": 7 * 86400}


def _is_due(row: dict) -> bool:
    last = store.last_snapshot_ts(row["domain"])
    if last is None:
        return True
    interval = _FREQ_SECONDS.get(row.get("monitor_freq") or "weekly", 7 * 86400)
    # A small grace so a timer that fires slightly early still counts the run.
    return (store.now() - last) >= (interval - 1800)


async def _reverify(row: dict) -> bool:
    domain = row["domain"]
    if row.get("operator"):
        # Operator-added monitors do not use the ownership gate; the engagement
        # reference on the domain is the authorization of record.
        return True
    method = row.get("verify_method")
    if method == "dns":
        return await verify.dns_token_present(domain, row.get("dns_token_hash") or "")
    # email: a live grant must still exist.
    return store.active_grant_for_domain(domain) is not None


async def _run_one(row: dict) -> str:
    domain = row["domain"]
    if not await _reverify(row):
        store.set_monitor_paused(domain, True)
        if row.get("notify_email"):
            await mailer.send_monitor_diff(
                row["notify_email"], domain,
                "Ownership could not be re-verified, so monitoring is paused. "
                "Re-verify the domain in FalconEye to resume.")
        log.info("asm monitor paused (reverify failed) domain=%s", tag(domain))
        return "paused"

    scan_id = secrets.token_urlsafe(18)
    store.create_scan(scan_id, domain, "monitor", operator=int(bool(row.get("operator"))),
                      engagement=row.get("engagement") or "", state="queued")
    await jobs.run_scan(scan_id)

    hosts = store.get_hosts(scan_id)
    found = store.get_findings(scan_id)
    new_snap = report.snapshot(hosts, found)
    old_snap = store.latest_snapshot(domain)
    d = report.diff(old_snap, new_snap)
    store.save_snapshot(domain, new_snap)
    store.prune_snapshots(config.ASM_SNAPSHOT_RETENTION_DAYS)

    if d["changed"] and row.get("notify_email"):
        await mailer.send_monitor_diff(row["notify_email"], domain, "\n".join(d["lines"]))
        log.info("asm monitor change emailed domain=%s changes=%d", tag(domain), len(d["lines"]))
        return "changed"
    return "unchanged"


async def run_due() -> dict:
    """Scan every monitored domain that is due. Returns a small run summary."""
    if not config.ASM_MONITORING_ENABLED:
        return {"enabled": False, "ran": 0}
    rows = [r for r in store.list_active_monitors() if _is_due(r)]
    results = {"enabled": True, "ran": 0, "changed": 0, "paused": 0, "unchanged": 0, "errors": 0}
    for row in rows:
        try:
            outcome = await _run_one(row)
            results["ran"] += 1
            results[outcome] = results.get(outcome, 0) + 1
        except Exception as exc:  # noqa: BLE001 - one domain must not sink the batch
            results["errors"] += 1
            log.warning("asm monitor error domain=%s: %s", tag(row.get("domain")), exc)
    return results
