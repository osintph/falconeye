"""Data migration for v3.39.0, run by scripts/release-actions/3.39.0.sh.

Run once per box through the .release_actions_applied mechanism, after
upgrade.sh has backed up the database and generated FE_HASH_KEY. Every step is
idempotent: a second run finds nothing left to change and reports zeros.

  1. Company dossiers: delete those older than PROSPECT_RETENTION_DAYS (rows and
     JSON files), then drop the unused ip_hash column from the rest.
  2. Attack Surface grants already revoked: for every domain with a revoked
     grant and no live one, delete what revoke now deletes
     (app.asm.store.delete_domain, the same function the revoke route calls).
  3. Run records: every finished or failed run row (and any older than the
     result TTL) has its plain domain, or Hunt keyword and legitimate domain,
     replaced with HMAC-SHA256(FE_HASH_KEY, value). Each audit row is re-keyed
     from its run row's plain value; an audit row whose run row is gone keeps
     only an unconvertible unsalted SHA-256, which is dropped (set to NULL).

Prints one line per step with row counts. No em dashes in this module.

Usage: migrate_3_39_0.py <app_src> <env_file or -> <db_path>
"""
from __future__ import annotations

import os
import re
import sqlite3
import sys

_WEAK = re.compile(r"^[0-9a-f]{32}$")


def _env_values(env_file: str) -> dict:
    """KEY=value pairs from the .env file, or from stdin when env_file is "-".
    The release action passes "-" and redirects .env into stdin from the root
    shell, because .env is usually root-owned 0600 and this runs as the service
    user; that also keeps the key out of argv and the process list."""
    out = {}
    try:
        f = sys.stdin if env_file == "-" else open(env_file, encoding="utf-8")
        try:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v
        finally:
            if f is not sys.stdin:
                f.close()
    except OSError:
        pass
    return out


def main(app_src: str, env_file: str, db_path: str) -> int:
    sys.path.insert(0, app_src)
    from app.utils.env import clean_env_value

    env = {k: clean_env_value(v) for k, v in _env_values(env_file).items()}
    if not env.get("FE_HASH_KEY"):
        print("migrate 3.39.0: FE_HASH_KEY is not set in .env; refusing to hash with a throwaway key")
        return 1
    # config reads the environment at import, so set it first.
    os.environ["FALCONEYE_DB"] = db_path
    os.environ["FE_HASH_KEY"] = env["FE_HASH_KEY"]
    for key in ("PROSPECT_RETENTION_DAYS", "ASM_RESULT_TTL_SECONDS", "FALCONEYE_DATA_DIR"):
        if env.get(key):
            os.environ[key] = env[key]

    from app import config
    from app.asm import store
    from app.prospect import investigations
    from app.utils import fehash

    # ---- 1. Company dossiers -------------------------------------------------
    swept = investigations.sweep_expired()
    conn = sqlite3.connect(db_path)
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(prospect_investigations)")]
        dropped = 0
        kept = conn.execute("SELECT COUNT(*) FROM prospect_investigations").fetchone()[0] if cols else 0
        if "ip_hash" in cols:
            try:
                conn.execute("ALTER TABLE prospect_investigations DROP COLUMN ip_hash")
            except sqlite3.OperationalError:
                # SQLite before 3.35 has no DROP COLUMN: rebuild the table.
                conn.executescript("""
                    CREATE TABLE prospect_investigations_new (
                        investigation_id TEXT PRIMARY KEY,
                        domain TEXT NOT NULL,
                        generated_at TEXT NOT NULL,
                        dossier_json_path TEXT NOT NULL);
                    INSERT INTO prospect_investigations_new
                        SELECT investigation_id, domain, generated_at, dossier_json_path
                        FROM prospect_investigations;
                    DROP TABLE prospect_investigations;
                    ALTER TABLE prospect_investigations_new RENAME TO prospect_investigations;
                """)
            dropped = 1
            conn.commit()
    finally:
        conn.close()
    print(f"migrate 3.39.0: dossiers older than {config.PROSPECT_RETENTION_DAYS} days deleted: "
          f"{swept['rows']} rows, {swept['files']} files; {kept} rows kept; "
          f"ip_hash column {'dropped' if dropped else 'already absent'}")

    # ---- 2. grants already revoked ------------------------------------------
    conn = sqlite3.connect(db_path)
    try:
        now = store.now()
        domains = [r[0] for r in conn.execute(
            "SELECT DISTINCT domain FROM asm_grants WHERE revoked_at IS NOT NULL AND domain NOT IN "
            "(SELECT domain FROM asm_grants WHERE revoked_at IS NULL AND expires_at > ?)", (now,))]
    finally:
        conn.close()
    totals: dict = {}
    for d in domains:
        for table, n in store.delete_domain(d).items():
            totals[table] = totals.get(table, 0) + n
    detail = ", ".join(f"{t}={n}" for t, n in sorted(totals.items()) if n) or "nothing"
    print(f"migrate 3.39.0: revoked grants: {len(domains)} domains, deleted {detail}")

    # ---- 3. run records -----------------------------------------------------
    cutoff = store.now() - config.ASM_RESULT_TTL_SECONDS
    conn = sqlite3.connect(db_path)
    rekeyed = weak_dropped = eng_hashed = 0
    try:
        conn.row_factory = sqlite3.Row
        scans = {r["scan_id"]: dict(r) for r in conn.execute("SELECT * FROM asm_scans")}
        for row in conn.execute("SELECT id, kind, domain_hash, engagement FROM asm_scan_audit").fetchall():
            scan = scans.get(row["id"])
            new_hash, new_eng = row["domain_hash"], row["engagement"] or ""
            if not fehash.is_hashed(new_hash):
                if scan and scan.get("domain") and not fehash.is_hashed(scan["domain"]):
                    new_hash = fehash.hmac_value(scan["domain"])
                    rekeyed += 1
                elif new_hash and _WEAK.match(new_hash):
                    new_hash = None
                    weak_dropped += 1
            if (row["kind"] or "asm") == "hunt" and new_eng and not fehash.is_hashed(new_eng):
                new_eng = fehash.hmac_value(new_eng)
                eng_hashed += 1
            if new_hash != row["domain_hash"] or new_eng != (row["engagement"] or ""):
                conn.execute("UPDATE asm_scan_audit SET domain_hash = ?, engagement = ? WHERE id = ?",
                             (new_hash, new_eng, row["id"]))
        converted = 0
        for sid, scan in scans.items():
            if scan.get("state") not in ("done", "error") and (scan.get("created_at") or 0) >= cutoff:
                continue  # still queued or running: the old process may read it before the restart
            if store._redact_scan(conn, sid):
                converted += 1
        conn.commit()
        left = conn.execute(
            "SELECT COUNT(*) FROM asm_scans WHERE domain NOT LIKE 'h1:%' OR "
            "(kind = 'hunt' AND engagement != '' AND engagement NOT LIKE 'h1:%')").fetchone()[0]
    finally:
        conn.close()
    print(f"migrate 3.39.0: run rows converted to HMAC: {converted}; audit rows re-keyed: {rekeyed}; "
          f"unconvertible audit hashes dropped: {weak_dropped}; Hunt audit legitimate domains hashed: "
          f"{eng_hashed}; run rows still plain (in flight, the sweep converts them): {left}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
