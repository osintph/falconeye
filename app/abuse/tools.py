"""
Operator CLI for FalconEye rate-limit maintenance.

Run on the VPS as the falconeye user (no auth — it is a local admin tool):

    python -m app.abuse.tools reset-rate-limit --ip 1.2.3.4
    python -m app.abuse.tools reset-rate-limit --ip 1.2.3.4 --endpoint compose
    python -m app.abuse.tools reset-rate-limit --ip 1.2.3.4 --dry-run

Clears a client IP's rate-limit counters so a legitimate investigator who hit
their own cap during real casework (or the operator while debugging) can keep
working, without hand-writing SQLite DELETEs against the right table/column.
Covers every rate-limit table in the app, each of which stores the IP a little
differently (``client_ip`` / ``source_ip`` / ``scope='ip:<ip>'``).
"""
import argparse
import sqlite3
import sys

from app.config import DB_PATH

# endpoint key -> (table, match column, value template for the IP)
RATE_LIMIT_TABLES = {
    "lookup":   ("abuse_lookup_rate_limit",   "client_ip", "{ip}"),
    "compose":  ("abuse_compose_rate_limit",  "client_ip", "{ip}"),
    "send":     ("abuse_send_rate_limit",     "scope",     "ip:{ip}"),
    "username": ("username_rate_limit",       "scope",     "ip:{ip}"),
    "url":      ("url_expand_rate_limit",     "source_ip", "{ip}"),
    "qr":       ("qr_decode_rate_limit",      "source_ip", "{ip}"),
    "dork":     ("dork_gen_rate_limit",       "source_ip", "{ip}"),
    "decoder":  ("script_decoder_rate_limit", "source_ip", "{ip}"),
    "llm":      ("llm_rate_limit",            "source_ip", "{ip}"),
}


def reset_rate_limit(ip: str, endpoints: list, dry_run: bool = False, db_path: str = DB_PATH) -> int:
    """Delete an IP's rows from the selected rate-limit tables. Returns total rows."""
    conn = sqlite3.connect(db_path)
    total = 0
    try:
        for key in endpoints:
            table, column, template = RATE_LIMIT_TABLES[key]
            value = template.format(ip=ip)
            # table/column come only from the fixed registry above; value is bound.
            try:
                count = conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE {column} = ?", (value,)
                ).fetchone()[0]
            except sqlite3.OperationalError:
                print(f"  {key:<9} {table:<28} — table not present, skipped")
                continue
            if not dry_run and count:
                conn.execute(f"DELETE FROM {table} WHERE {column} = ?", (value,))
            total += count
            verb = "would delete" if dry_run else "deleted"
            print(f"  {key:<9} {table:<28} — {verb} {count} row(s)  [{column}={value}]")
        if not dry_run:
            conn.commit()
    finally:
        conn.close()
    prefix = "DRY RUN — " if dry_run else ""
    print(f"{prefix}Total: {total} row(s) across {len(endpoints)} table(s) for IP {ip}")
    return total


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.abuse.tools",
        description="FalconEye operator tools (run locally on the VPS as the falconeye user).",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    rl = sub.add_parser("reset-rate-limit", help="Clear rate-limit counters for a client IP.")
    rl.add_argument("--ip", required=True, help="Client IP to clear (as recorded, i.e. CF-Connecting-IP).")
    rl.add_argument(
        "--endpoint", default="all", choices=[*RATE_LIMIT_TABLES.keys(), "all"],
        help="Rate-limit table(s) to clear. Default: all.",
    )
    rl.add_argument("--dry-run", action="store_true", help="Show what would be deleted without deleting.")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "reset-rate-limit":
        endpoints = list(RATE_LIMIT_TABLES) if args.endpoint == "all" else [args.endpoint]
        reset_rate_limit(args.ip, endpoints, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
