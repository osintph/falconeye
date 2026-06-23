#!/usr/bin/env python3
"""
Initialize (or re-initialize) the FalconEye SQLite database.
Safe to run multiple times; all DDL uses CREATE TABLE IF NOT EXISTS.

Usage:
    python scripts/init_db.py [db_path]

If db_path is omitted, FALCONEYE_DB_PATH from the environment is used.
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
        default=None,
        help="Path to database file (default: FALCONEYE_DB_PATH env var)",
    )
    args = parser.parse_args()

    if args.db_path:
        db_path = args.db_path
    else:
        from falconeye.config import ConfigError, get_db_path
        db_path = get_db_path()

    init_db(db_path)

    conn = get_connection(db_path)
    tables = sorted(
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    )
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    conn.close()

    print(f"Database ready: {db_path}")
    print(f"Journal mode:   {mode}")
    print(f"Tables:         {', '.join(tables)}")


if __name__ == "__main__":
    main()
