"""Fetch the WHOISDS free daily newly-registered-domain lists into the rolling
local store the Hunt reads (HUNT_NRD_DIR), pruning to HUNT_NRD_DAYS. Run daily by
a systemd timer on the VPS. The free lists carry only domain names (no whois) and
are explicitly reusable including commercially, with no login; verified
2026-10-11. The list is overwhelmingly gTLD; .ph coverage is negligible.

Stdlib only (urllib), so the timer does not depend on the app venv's packages.
Idempotent: a day already stored is skipped. No em dashes in this module.

Usage: python -m app.hunt.nrd_fetch [--days N]
"""
from __future__ import annotations

import base64
import datetime as dt
import io
import os
import sys
import urllib.request
import zipfile

from app import config

_BASE = "https://www.whoisds.com//whois-database/newly-registered-domains/{}/nrd"
_UA = "FalconEye-Hunt/NRD (+https://falconeye.osintph.info; free WHOISDS daily list)"


def _url_for(day: dt.date) -> str:
    token = base64.b64encode(f"{day.isoformat()}.zip".encode()).decode()
    return _BASE.format(token)


def _fetch_day(day: dt.date, out_dir: str) -> str:
    """Download and store one day's list, or "" on failure or if already present."""
    dest = os.path.join(out_dir, f"{day.isoformat()}.txt")
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return ""  # already have it
    req = urllib.request.Request(_url_for(day), headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            if resp.status != 200:
                return ""
            body = resp.read()
    except Exception:  # noqa: BLE001
        return ""
    text = ""
    try:
        if body[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(body)) as z:
                for name in z.namelist():
                    text += z.read(name).decode("utf-8", "replace")
        else:
            text = body.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""
    lines = [ln.strip().lower() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return ""
    tmp = dest + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.replace(tmp, dest)
    return dest


def _prune(out_dir: str, keep_days: int) -> int:
    cutoff = dt.date.today() - dt.timedelta(days=keep_days)
    removed = 0
    for name in os.listdir(out_dir):
        if not name.endswith(".txt"):
            continue
        try:
            d = dt.date.fromisoformat(name[:-4])
        except ValueError:
            continue
        if d < cutoff:
            try:
                os.remove(os.path.join(out_dir, name))
                removed += 1
            except OSError:
                pass
    return removed


def run(back_days: int = 5) -> dict:
    out_dir = config.HUNT_NRD_DIR
    os.makedirs(out_dir, exist_ok=True)
    fetched = []
    today = dt.date.today()
    # WHOISDS publishes a day's list the following day, so start at yesterday.
    for off in range(1, back_days + 1):
        got = _fetch_day(today - dt.timedelta(days=off), out_dir)
        if got:
            fetched.append(os.path.basename(got))
    removed = _prune(out_dir, config.HUNT_NRD_DAYS)
    have = sorted(f for f in os.listdir(out_dir) if f.endswith(".txt"))
    return {"fetched": fetched, "pruned": removed, "stored_days": len(have)}


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    back = 5
    if "--days" in argv:
        try:
            back = int(argv[argv.index("--days") + 1])
        except (ValueError, IndexError):
            back = 5
    result = run(back)
    print(f"NRD fetch: new={result['fetched']} pruned={result['pruned']} "
          f"stored_days={result['stored_days']} dir={config.HUNT_NRD_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
