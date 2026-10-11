#!/usr/bin/env python3
"""Run due ASM monitoring. Invoked by the falconeye-asm-monitor systemd timer.

Scans every monitored domain whose schedule is due, re-verifying ownership first
and emailing a diff only when something changed. Reads FALCONEYE_DB and the mail
and other settings from the environment (the systemd unit supplies the .env).
No em dashes in this file.
"""
import asyncio
import os
import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))
os.chdir(_ROOT)

from app.asm import monitor  # noqa: E402


def main() -> int:
    result = asyncio.run(monitor.run_due())
    print("falconeye asm monitor:", result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
