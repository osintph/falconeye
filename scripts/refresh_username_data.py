"""Refresh the vendored WhatsMyName and Sherlock data files.

Run manually before a Username Enumeration release cycle (suggested every 4-6
weeks). Fetches upstream, validates the shape and a minimum site count, and only
then overwrites the vendored file under app/data/ — so a bad upstream fetch can
never leave FalconEye with an empty or truncated data file.

    python3 scripts/refresh_username_data.py

Confirm the upstream paths below if a fetch 404s — WebBreacher and
sherlock-project have both restructured their repos in the past.
"""
import json
import sys
from pathlib import Path

import httpx

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
SHERLOCK_URL = "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json"

DATA_DIR = Path(__file__).resolve().parent.parent / "app" / "data"


def _count(data) -> int:
    if isinstance(data, dict) and "sites" in data:
        return len(data["sites"])
    if isinstance(data, dict):
        return len([k for k in data if not str(k).startswith("$")])
    if isinstance(data, list):
        return len(data)
    return 0


def fetch_and_validate(url: str, target: Path, min_sites: int, source_name: str) -> bool:
    print(f"Fetching {source_name} from {url}")
    try:
        r = httpx.get(url, timeout=30.0, follow_redirects=True)
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        print(f"  ERROR: fetch/parse failed: {exc}", file=sys.stderr)
        return False

    count = _count(data)
    if count < min_sites:
        print(f"  ERROR: {source_name} returned {count} sites, expected {min_sites}+ — NOT written",
              file=sys.stderr)
        return False

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"  OK: wrote {count} sites to {target.relative_to(DATA_DIR.parent.parent)}")
    return True


def main() -> int:
    ok_wmn = fetch_and_validate(
        WMN_URL, DATA_DIR / "whatsmyname" / "wmn-data.json", 400, "WhatsMyName")
    ok_sher = fetch_and_validate(
        SHERLOCK_URL, DATA_DIR / "sherlock" / "data.json", 300, "Sherlock")

    if not ok_wmn:
        print("WhatsMyName refresh FAILED — vendored file left unchanged.", file=sys.stderr)
        return 1
    if not ok_sher:
        print("Sherlock refresh failed — WhatsMyName updated, Sherlock left unchanged. "
              "The tab still runs (WMN-only if Sherlock data is stale/absent).", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
