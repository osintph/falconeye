#!/usr/bin/env python3
"""
Initialize (or re-initialize) the FalconEye SQLite database.
Safe to run multiple times; all DDL uses CREATE TABLE IF NOT EXISTS.

Usage:
    python scripts/init_db.py [db_path]

Default db_path: db/falconeye.db
Production path: /opt/falconeye/db/falconeye.db
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from falconeye.db import get_connection, init_db


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize the FalconEye SQLite database")
    parser.add_argument(
        "db_path",
        nargs="?",
        default="db/falconeye.db",
        help="Path to database file (default: db/falconeye.db)",
    )
    args = parser.parse_args()

    init_db(args.db_path)

    conn = get_connection(args.db_path)
    tables = sorted(
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    )
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    conn.close()

    print(f"Database ready: {args.db_path}")
    print(f"Journal mode:   {mode}")
    print(f"Tables:         {', '.join(tables)}")


if __name__ == "__main__":
    main()
