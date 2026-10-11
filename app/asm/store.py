"""All ASM SQLite tables and their helpers, in the main application database.

Every table is created at import with CREATE TABLE IF NOT EXISTS, per the new-tab
resilience rule, so a freshly created or restored database never 500s an ASM
route with "no such table". Targets are stored as given (a verified owner is
entitled to see their own domain); log lines elsewhere hash them with tag().

Timestamps are unix integers, matching app/abuse/store.py. JSON columns hold the
structured parts of a scan.

No em dashes in this module.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from typing import Optional

from app.config import DB_PATH

log = logging.getLogger("falconeye.asm.store")


def _connect() -> sqlite3.Connection:
    # A busy timeout so concurrent gunicorn workers wait briefly for the write
    # lock instead of failing with "database is locked" under contention.
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def now() -> int:
    return int(time.time())


def init_tables() -> None:
    """Create every ASM table and index if absent. Idempotent."""
    conn = _connect()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS asm_domains (
              domain TEXT PRIMARY KEY,
              status TEXT NOT NULL,
              source TEXT,
              verify_method TEXT,
              operator INTEGER NOT NULL DEFAULT 0,
              engagement TEXT,
              monitor_enabled INTEGER NOT NULL DEFAULT 0,
              monitor_freq TEXT NOT NULL DEFAULT 'weekly',
              monitor_paused INTEGER NOT NULL DEFAULT 0,
              notify_email TEXT,
              mgmt_version INTEGER NOT NULL DEFAULT 1,
              dns_token_hash TEXT,
              added_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS asm_verifications (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              domain TEXT NOT NULL,
              method TEXT NOT NULL,
              role TEXT,
              token_hash TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              consumed_at INTEGER,
              client_ip_hash TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_asm_verif_hash ON asm_verifications(token_hash);
            CREATE INDEX IF NOT EXISTS idx_asm_verif_domain ON asm_verifications(domain);

            CREATE TABLE IF NOT EXISTS asm_grants (
              grant_id TEXT PRIMARY KEY,
              domain TEXT NOT NULL,
              method TEXT,
              notify_email TEXT,
              issued_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              revoked_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_asm_grants_domain ON asm_grants(domain);

            CREATE TABLE IF NOT EXISTS asm_scans (
              scan_id TEXT PRIMARY KEY,
              domain TEXT NOT NULL,
              kind TEXT NOT NULL DEFAULT 'asm',
              mode TEXT NOT NULL,
              state TEXT NOT NULL,
              operator INTEGER NOT NULL DEFAULT 0,
              engagement TEXT,
              grant_id TEXT,
              created_at INTEGER NOT NULL,
              started_at INTEGER,
              finished_at INTEGER,
              summary_json TEXT,
              error TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_asm_scans_domain ON asm_scans(domain, created_at);

            CREATE TABLE IF NOT EXISTS asm_hosts (
              scan_id TEXT NOT NULL,
              host TEXT NOT NULL,
              resolved_ips_json TEXT,
              cname TEXT,
              is_reference INTEGER NOT NULL DEFAULT 0,
              cdn TEXT,
              http_json TEXT,
              tls_json TEXT,
              fingerprint_json TEXT,
              open_ports_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_asm_hosts_scan ON asm_hosts(scan_id);

            CREATE TABLE IF NOT EXISTS asm_findings (
              scan_id TEXT NOT NULL,
              host TEXT,
              severity TEXT NOT NULL,
              kind TEXT NOT NULL,
              title TEXT NOT NULL,
              detail TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_asm_findings_scan ON asm_findings(scan_id);

            CREATE TABLE IF NOT EXISTS asm_snapshots (
              domain TEXT NOT NULL,
              taken_at INTEGER NOT NULL,
              snapshot_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_asm_snapshots_domain ON asm_snapshots(domain, taken_at);

            CREATE TABLE IF NOT EXISTS asm_operator_sessions (
              sid TEXT PRIMARY KEY,
              issued_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              revoked_at INTEGER,
              client_ip_hash TEXT,
              engagement TEXT
            );

            CREATE TABLE IF NOT EXISTS asm_operator_audit (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              at INTEGER NOT NULL,
              event TEXT NOT NULL,
              client_ip_hash TEXT,
              engagement TEXT,
              detail TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_asm_audit_at ON asm_operator_audit(at);

            CREATE TABLE IF NOT EXISTS asm_rate_limit (
              scope TEXT NOT NULL,
              key TEXT NOT NULL,
              event_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_asm_rl ON asm_rate_limit(scope, key, event_at);

            -- v3.38.0 one-time model: result content lives here only, briefly.
            CREATE TABLE IF NOT EXISTS asm_result_cache (
              id TEXT PRIMARY KEY,
              kind TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              pdf_path TEXT,
              created_at INTEGER NOT NULL,
              delivered_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_asm_result_created ON asm_result_cache(created_at);

            -- Metadata-only audit that lasts; no hostnames or findings, domain hashed.
            CREATE TABLE IF NOT EXISTS asm_scan_audit (
              id TEXT PRIMARY KEY,
              at INTEGER NOT NULL,
              kind TEXT NOT NULL,
              mode TEXT,
              operator INTEGER NOT NULL DEFAULT 0,
              engagement TEXT,
              domain_hash TEXT,
              host_count INTEGER DEFAULT 0,
              crit INTEGER DEFAULT 0,
              high INTEGER DEFAULT 0,
              med INTEGER DEFAULT 0,
              low INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_asm_scan_audit_at ON asm_scan_audit(at);
            """
        )
        # Add the kind column to a pre-v3.38.0 asm_scans table.
        cols = {r[1] for r in conn.execute("PRAGMA table_info(asm_scans)")}
        if "kind" not in cols:
            conn.execute("ALTER TABLE asm_scans ADD COLUMN kind TEXT NOT NULL DEFAULT 'asm'")
        conn.commit()
    finally:
        conn.close()


try:
    init_tables()
except Exception as exc:  # pragma: no cover - only when the DB path is unwritable at import
    log.warning("asm: deferred table init (DB not ready at import): %s", exc)


# --------------------------------------------------------------- rate limits ----

def rl_count(scope: str, key: str, window_seconds: int) -> int:
    cutoff = now() - window_seconds
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM asm_rate_limit WHERE scope = ? AND key = ? AND event_at > ?",
            (scope, key, cutoff),
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row else 0


def rl_record(scope: str, key: str) -> None:
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO asm_rate_limit (scope, key, event_at) VALUES (?, ?, ?)",
            (scope, key, now()),
        )
        # Prune anything older than 30 days so the table does not grow forever.
        conn.execute("DELETE FROM asm_rate_limit WHERE event_at < ?", (now() - 2592000,))
        conn.commit()
    except Exception as exc:  # noqa: BLE001 - a limiter write must not 500 the request
        log.error("asm rate-limit write failed: %s", exc)
    finally:
        conn.close()


def rl_last_ts(scope: str, key: str) -> Optional[int]:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT MAX(event_at) FROM asm_rate_limit WHERE scope = ? AND key = ?",
            (scope, key),
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row and row[0] is not None else None


def rl_clear(scope: str, key: str) -> None:
    conn = _connect()
    try:
        conn.execute("DELETE FROM asm_rate_limit WHERE scope = ? AND key = ?", (scope, key))
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        log.error("asm rate-limit clear failed: %s", exc)
    finally:
        conn.close()


# ------------------------------------------------------------------- domains ----

def upsert_domain(domain: str, status: str, *, source: str = "", verify_method: str = "",
                  operator: int = 0, engagement: str = "", notify_email: str = "") -> None:
    ts = now()
    conn = _connect()
    try:
        conn.execute(
            """
            INSERT INTO asm_domains
              (domain, status, source, verify_method, operator, engagement, notify_email,
               added_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
              status = excluded.status,
              source = excluded.source,
              verify_method = excluded.verify_method,
              operator = excluded.operator,
              engagement = excluded.engagement,
              notify_email = COALESCE(NULLIF(excluded.notify_email, ''), asm_domains.notify_email),
              updated_at = excluded.updated_at
            """,
            (domain, status, source, verify_method, operator, engagement, notify_email, ts, ts),
        )
        conn.commit()
    finally:
        conn.close()


def get_domain(domain: str) -> Optional[dict]:
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM asm_domains WHERE domain = ?", (domain,)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def set_monitoring(domain: str, enabled: bool, freq: str, notify_email: str) -> None:
    conn = _connect()
    try:
        conn.execute(
            "UPDATE asm_domains SET monitor_enabled = ?, monitor_freq = ?, monitor_paused = 0, "
            "notify_email = COALESCE(NULLIF(?, ''), notify_email), updated_at = ? WHERE domain = ?",
            (1 if enabled else 0, freq, notify_email, now(), domain),
        )
        conn.commit()
    finally:
        conn.close()


def set_monitor_paused(domain: str, paused: bool) -> None:
    conn = _connect()
    try:
        conn.execute(
            "UPDATE asm_domains SET monitor_paused = ?, updated_at = ? WHERE domain = ?",
            (1 if paused else 0, now(), domain),
        )
        conn.commit()
    finally:
        conn.close()


def set_dns_token_hash(domain: str, token_hash: str) -> None:
    """Persist the DNS proof token hash so monitoring and on-demand runs can
    re-check the record is still present before every scan."""
    conn = _connect()
    try:
        conn.execute("UPDATE asm_domains SET dns_token_hash = ?, updated_at = ? WHERE domain = ?",
                     (token_hash, now(), domain))
        conn.commit()
    finally:
        conn.close()


def bump_mgmt_version(domain: str) -> int:
    conn = _connect()
    try:
        conn.execute(
            "UPDATE asm_domains SET mgmt_version = mgmt_version + 1, updated_at = ? WHERE domain = ?",
            (now(), domain),
        )
        conn.commit()
        row = conn.execute("SELECT mgmt_version FROM asm_domains WHERE domain = ?", (domain,)).fetchone()
    finally:
        conn.close()
    return row[0] if row else 1


def list_active_monitors() -> list:
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM asm_domains WHERE monitor_enabled = 1 AND monitor_paused = 0"
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def count_monitored() -> int:
    conn = _connect()
    try:
        row = conn.execute("SELECT COUNT(*) FROM asm_domains WHERE monitor_enabled = 1").fetchone()
    finally:
        conn.close()
    return row[0] if row else 0


def count_monitored_for_notify(email: str) -> int:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM asm_domains WHERE monitor_enabled = 1 AND notify_email = ? COLLATE NOCASE",
            (email,),
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row else 0


def delete_domain(domain: str) -> None:
    """Remove the domain and every record tied to it, immediately."""
    conn = _connect()
    try:
        scan_ids = [r[0] for r in conn.execute(
            "SELECT scan_id FROM asm_scans WHERE domain = ?", (domain,)).fetchall()]
        conn.execute("DELETE FROM asm_domains WHERE domain = ?", (domain,))
        conn.execute("DELETE FROM asm_verifications WHERE domain = ?", (domain,))
        conn.execute("DELETE FROM asm_grants WHERE domain = ?", (domain,))
        conn.execute("DELETE FROM asm_scans WHERE domain = ?", (domain,))
        conn.execute("DELETE FROM asm_snapshots WHERE domain = ?", (domain,))
        for sid in scan_ids:
            conn.execute("DELETE FROM asm_hosts WHERE scan_id = ?", (sid,))
            conn.execute("DELETE FROM asm_findings WHERE scan_id = ?", (sid,))
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------- verifications ----

def create_verification(domain: str, method: str, role: str, token_hash: str,
                        ttl_hours: int, client_ip_hash: str) -> int:
    ts = now()
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO asm_verifications "
            "(domain, method, role, token_hash, created_at, expires_at, client_ip_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (domain, method, role, token_hash, ts, ts + ttl_hours * 3600, client_ip_hash),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_live_verification(token_hash: str) -> Optional[dict]:
    """An unconsumed, unexpired verification matching *token_hash*, or None."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM asm_verifications WHERE token_hash = ? AND consumed_at IS NULL "
            "AND expires_at > ?",
            (token_hash, now()),
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def get_verification_any(token_hash: str) -> Optional[dict]:
    """The most recent verification for a token hash regardless of consumed or
    expired state, so a page can tell "already used" from "expired" from
    "not recognised"."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM asm_verifications WHERE token_hash = ? ORDER BY id DESC LIMIT 1",
            (token_hash,),
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def consume_verification(verif_id: int) -> bool:
    """Mark a verification consumed. Returns True only if it was still unconsumed,
    so a double-submit of the same link cannot issue two grants."""
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE asm_verifications SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL",
            (now(), verif_id),
        )
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


# -------------------------------------------------------------------- grants ----

def issue_grant(grant_id: str, domain: str, ttl_days: int, notify_email: str, method: str) -> None:
    ts = now()
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO asm_grants (grant_id, domain, method, notify_email, issued_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (grant_id, domain, method, notify_email, ts, ts + ttl_days * 86400),
        )
        conn.commit()
    finally:
        conn.close()


def get_live_grant(grant_id: str) -> Optional[dict]:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM asm_grants WHERE grant_id = ? AND revoked_at IS NULL AND expires_at > ?",
            (grant_id, now()),
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def active_grant_for_domain(domain: str) -> Optional[dict]:
    """The most recent live grant for *domain*, or None. Used by monitoring to
    re-check that an email-verified domain still has a valid grant."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM asm_grants WHERE domain = ? AND revoked_at IS NULL AND expires_at > ? "
            "ORDER BY issued_at DESC LIMIT 1",
            (domain, now()),
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def revoke_all_grants(domain: str) -> int:
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE asm_grants SET revoked_at = ? WHERE domain = ? AND revoked_at IS NULL",
            (now(), domain),
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


# --------------------------------------------------------------------- scans ----

def create_scan(scan_id: str, domain: str, mode: str, *, kind: str = "asm", operator: int = 0,
                engagement: str = "", grant_id: str = "", state: str = "queued") -> None:
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO asm_scans (scan_id, domain, kind, mode, state, operator, engagement, grant_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, domain, kind, mode, state, operator, engagement, grant_id, now()),
        )
        conn.commit()
    finally:
        conn.close()


def set_scan_running(scan_id: str) -> None:
    conn = _connect()
    try:
        conn.execute("UPDATE asm_scans SET state = 'running', started_at = ? WHERE scan_id = ?",
                     (now(), scan_id))
        conn.commit()
    finally:
        conn.close()


def finish_scan(scan_id: str, summary: dict) -> None:
    conn = _connect()
    try:
        conn.execute(
            "UPDATE asm_scans SET state = 'done', finished_at = ?, summary_json = ? WHERE scan_id = ?",
            (now(), json.dumps(summary), scan_id),
        )
        conn.commit()
    finally:
        conn.close()


def fail_scan(scan_id: str, error: str) -> None:
    conn = _connect()
    try:
        conn.execute(
            "UPDATE asm_scans SET state = 'error', finished_at = ?, error = ? WHERE scan_id = ?",
            (now(), error[:500], scan_id),
        )
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------- one-time result cache + audit ----

def cache_result(result_id: str, kind: str, payload: dict, pdf_path: str) -> None:
    """Hold a finished result and its PDF path, briefly. This is the only place
    result content lives, and only until download or the TTL sweep."""
    conn = _connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO asm_result_cache (id, kind, payload_json, pdf_path, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (result_id, kind, json.dumps(payload), pdf_path, now()),
        )
        conn.commit()
    finally:
        conn.close()


def get_result(result_id: str) -> Optional[dict]:
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM asm_result_cache WHERE id = ?", (result_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    out = dict(row)
    try:
        out["payload"] = json.loads(out["payload_json"])
    except (ValueError, TypeError):
        out["payload"] = None
    return out


def delete_result(result_id: str) -> None:
    """Delete the ephemeral row and its PDF file. Used after a completed download
    and by the sweep."""
    row = get_result(result_id)
    if row and row.get("pdf_path"):
        try:
            os.remove(row["pdf_path"])
        except OSError:
            pass
    conn = _connect()
    try:
        conn.execute("DELETE FROM asm_result_cache WHERE id = ?", (result_id,))
        conn.commit()
    finally:
        conn.close()


def sweep_results(ttl_seconds: int) -> int:
    """Delete every ephemeral result (and its PDF) older than the TTL. Called
    lazily on submit and on status reads, so there is no timer."""
    cutoff = now() - ttl_seconds
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, pdf_path FROM asm_result_cache WHERE created_at < ?", (cutoff,)).fetchall()
    finally:
        conn.close()
    for r in rows:
        if r["pdf_path"]:
            try:
                os.remove(r["pdf_path"])
            except OSError:
                pass
    conn = _connect()
    try:
        conn.execute("DELETE FROM asm_result_cache WHERE created_at < ?", (cutoff,))
        conn.commit()
    finally:
        conn.close()
    return len(rows)


def record_scan_audit(result_id: str, kind: str, mode: str, operator: int, engagement: str,
                      domain_hash: str, host_count: int, counts: dict) -> None:
    conn = _connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO asm_scan_audit "
            "(id, at, kind, mode, operator, engagement, domain_hash, host_count, crit, high, med, low) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (result_id, now(), kind, mode, operator, engagement, domain_hash, host_count,
             counts.get("critical", 0), counts.get("high", 0),
             counts.get("medium", 0), counts.get("low", 0)),
        )
        conn.commit()
    finally:
        conn.close()


def count_running_scans(slack_seconds: int) -> int:
    """Scans currently running, ignoring rows stale past the run-time budget plus
    slack (a worker that died mid-scan should not hold a slot forever)."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM asm_scans WHERE state = 'running' AND started_at >= ?",
            (now() - slack_seconds,),
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row else 0


def count_recent_queued_scans(slack_seconds: int) -> int:
    """Queued scans that are still fresh. A queued row left behind by a dead
    worker eventually ages out of the queue-capacity accounting."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM asm_scans WHERE state = 'queued' AND created_at >= ?",
            (now() - slack_seconds,),
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row else 0


def claim_scan_slot(scan_id: str, max_concurrent: int, slack_seconds: int) -> bool:
    """Atomically move a queued scan to running IFF fewer than *max_concurrent*
    are running globally. SQLite serializes the single UPDATE (one writer), so the
    count-and-claim is atomic across all gunicorn workers. Returns True on claim.
    """
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE asm_scans SET state = 'running', started_at = ? "
            "WHERE scan_id = ? AND state = 'queued' "
            "AND (SELECT COUNT(*) FROM asm_scans WHERE state = 'running' AND started_at >= ?) < ?",
            (now(), scan_id, now() - slack_seconds, max_concurrent),
        )
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def get_scan(scan_id: str) -> Optional[dict]:
    conn = _connect()
    try:
        row = conn.execute("SELECT * FROM asm_scans WHERE scan_id = ?", (scan_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    out = dict(row)
    out["summary"] = json.loads(out["summary_json"]) if out.get("summary_json") else None
    return out


def latest_done_scan(domain: str, operator: int) -> Optional[dict]:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM asm_scans WHERE domain = ? AND operator = ? AND state = 'done' "
            "ORDER BY finished_at DESC LIMIT 1",
            (domain, operator),
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def add_host(scan_id: str, host: str, resolved_ips, cname: str, is_reference: int,
             cdn: str, http: dict, tls: dict, fingerprint: dict, open_ports) -> None:
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO asm_hosts (scan_id, host, resolved_ips_json, cname, is_reference, cdn, "
            "http_json, tls_json, fingerprint_json, open_ports_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, host, json.dumps(resolved_ips or []), cname or "", int(is_reference), cdn or "",
             json.dumps(http) if http else None, json.dumps(tls) if tls else None,
             json.dumps(fingerprint) if fingerprint else None, json.dumps(open_ports or [])),
        )
        conn.commit()
    finally:
        conn.close()


def add_finding(scan_id: str, host: str, severity: str, kind: str, title: str, detail: str) -> None:
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO asm_findings (scan_id, host, severity, kind, title, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, host or "", severity, kind, title, detail or ""),
        )
        conn.commit()
    finally:
        conn.close()


def get_hosts(scan_id: str) -> list:
    conn = _connect()
    try:
        rows = conn.execute("SELECT * FROM asm_hosts WHERE scan_id = ?", (scan_id,)).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["resolved_ips"] = json.loads(d["resolved_ips_json"]) if d.get("resolved_ips_json") else []
        d["http"] = json.loads(d["http_json"]) if d.get("http_json") else None
        d["tls"] = json.loads(d["tls_json"]) if d.get("tls_json") else None
        d["fingerprint"] = json.loads(d["fingerprint_json"]) if d.get("fingerprint_json") else None
        d["open_ports"] = json.loads(d["open_ports_json"]) if d.get("open_ports_json") else []
        out.append(d)
    return out


def get_findings(scan_id: str) -> list:
    conn = _connect()
    try:
        rows = conn.execute("SELECT * FROM asm_findings WHERE scan_id = ?", (scan_id,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


# ----------------------------------------------------------------- snapshots ----

def save_snapshot(domain: str, snapshot: dict) -> None:
    conn = _connect()
    try:
        conn.execute("INSERT INTO asm_snapshots (domain, taken_at, snapshot_json) VALUES (?, ?, ?)",
                     (domain, now(), json.dumps(snapshot)))
        conn.commit()
    finally:
        conn.close()


def latest_snapshot(domain: str) -> Optional[dict]:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT snapshot_json FROM asm_snapshots WHERE domain = ? ORDER BY taken_at DESC LIMIT 1",
            (domain,),
        ).fetchone()
    finally:
        conn.close()
    if not row or not row[0]:
        return None
    try:
        return json.loads(row[0])
    except (ValueError, TypeError):
        return None


def last_snapshot_ts(domain: str) -> Optional[int]:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT MAX(taken_at) FROM asm_snapshots WHERE domain = ?", (domain,)).fetchone()
    finally:
        conn.close()
    return row[0] if row and row[0] is not None else None


def prune_snapshots(retention_days: int) -> int:
    cutoff = now() - retention_days * 86400
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM asm_snapshots WHERE taken_at < ?", (cutoff,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


# --------------------------------------------------------- operator sessions ----

def create_operator_session(sid: str, ttl_hours: int, client_ip_hash: str, engagement: str = "") -> None:
    ts = now()
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO asm_operator_sessions (sid, issued_at, expires_at, client_ip_hash, engagement) "
            "VALUES (?, ?, ?, ?, ?)",
            (sid, ts, ts + ttl_hours * 3600, client_ip_hash, engagement),
        )
        conn.commit()
    finally:
        conn.close()


def get_live_operator_session(sid: str) -> Optional[dict]:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM asm_operator_sessions WHERE sid = ? AND revoked_at IS NULL AND expires_at > ?",
            (sid, now()),
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def revoke_operator_session(sid: str) -> None:
    conn = _connect()
    try:
        conn.execute("UPDATE asm_operator_sessions SET revoked_at = ? WHERE sid = ?", (now(), sid))
        conn.commit()
    finally:
        conn.close()


def record_operator_audit(event: str, client_ip_hash: str, engagement: str = "", detail: str = "") -> None:
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO asm_operator_audit (at, event, client_ip_hash, engagement, detail) "
            "VALUES (?, ?, ?, ?, ?)",
            (now(), event, client_ip_hash, engagement, detail),
        )
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        log.error("asm audit write failed: %s", exc)
    finally:
        conn.close()
