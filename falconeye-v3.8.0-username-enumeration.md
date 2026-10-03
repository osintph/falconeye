# FalconEye v3.8.0 — Username Enumeration tab

## Context

Every existing FalconEye tab operates on infrastructure. Domains, IPs, wallets, headers, redirect chains, QR pixels, all of it is about the machinery. None of them operate on identity.

Username Enumeration is the OSINT primitive that turns "I have a handle" into "here is where else that handle appears." A scammer's Telegram username also appears on a GitHub account with their real name in the commit history. A BEC actor's LinkedIn handle also matches a decade-old MySpace profile with their high school. The tab does not deliver verdicts, it surfaces leads for human verification. That is what usernames give you.

v3.8.0 ships this tab using a dual-engine approach: WhatsMyName as primary, Sherlock as secondary, results merged and cross-validated where both hit. Feasibility of dual is assessed below and the answer is yes.

## Dual-engine evaluation

**WhatsMyName** (WebBreacher, MIT) ships a single JSON/YAML data file with ~600 sites, each with a URL template and a detection heuristic. Actively maintained, community pull requests weekly. Strong coverage of forums, dev platforms, and niche sites.

**Sherlock** (sherlock-project, MIT) ships a JSON data file with ~400 sites. Also actively maintained. Overlaps heavily with WMN on major platforms but has unique coverage of some Chinese platforms and newer social sites WMN has not yet added.

**Feasibility.** High. Both are MIT-licensed static data files. Both encode URL templates and detection logic in machine-readable form. The schemas differ but are bridgeable in a single adapter layer. No Python dependency on either project's runtime code, we vendor the data and write our own checker.

**Value add of Sherlock on top of WMN.** Roughly 200-300 unique sites plus cross-validation signal (a hit appearing in both engines is higher confidence than a hit in either alone). Not a game-changer, but meaningful for casework and worth the complexity cost.

**Decision.** Ship dual-engine in v3.8.0. If Sherlock's data pipeline proves flaky during Part A, Claude Code drops to WMN-only and notes it in the CHANGELOG. Fallback path is preserved.

## Scope

- One new tab, Username, added between Contact and News in the nav
- Backend package `app/username/` with parser, checker, merger, router
- Vendored data files: WMN and Sherlock, both refreshed on release cadence, not runtime
- Sync request pattern (no async jobs), split into Quick Scan (top 200 sites, ~15s) and Full Scan (all sites, ~60s)
- Rate limits: 3 scans per client IP per hour, 20 per day, 100 global per day
- Version bump to 3.8.0 in all four spots

## Files touched

### New
- `app/username/__init__.py`
- `app/username/parser.py` (WMN and Sherlock adapters, unified site list)
- `app/username/checker.py` (async httpx sweep, concurrency cap)
- `app/username/merger.py` (dedup, source tagging, category rollup)
- `app/username/routes.py` (POST /api/username/scan)
- `app/username/store.py` (rate limit tables, self-initializing)
- `app/data/whatsmyname/wmn-data.json` (vendored, initial fetch during A2)
- `app/data/sherlock/data.json` (vendored, initial fetch during A2)
- `scripts/refresh_username_data.py` (refresh script for release cadence)
- `docs/username-enumeration.md`
- `tests/username/test_parser.py`
- `tests/username/test_checker.py`
- `tests/username/test_merger.py`
- `tests/username/test_routes.py`

### Modified
- `app/main.py` (register router, version bump to 3.8.0)
- `app/static/index.html` (new tab nav entry, panel, version bump in JSON-LD, featureList update)
- `app/static/js/app.js` (username tab logic, results rendering, pivot handlers)
- `requirements.txt` (add PyYAML if not already present, for parsing WMN's YAML if that format is used)
- `README.md` (feature note, current version bump)
- `CHANGELOG.md` (v3.8.0 entry)

## Manual prerequisites (Sigmund)

None. This tab has no external API keys, no SaaS integration, no email delivery. Everything runs from the vendored data files against public social platforms with async httpx.

## Cautionary notes

- **Username validation is a security boundary.** Vendored URL templates contain `{username}` placeholders. If username contains path traversal, query parameters, or unusual characters, the substituted URL points somewhere unexpected. Enforce strict validation: alphanumeric plus `._-`, length 1 to 40 chars. Reject anything else at the router before any check runs.
- **URL encoding after validation.** Even after validation, URL-encode the username with `urllib.parse.quote` before substitution. Belt and braces.
- **safe_fetch on every outbound request.** Vendored URLs are trusted but pass every constructed URL through the existing `safe_fetch` helper anyway. Consistency with the URL Expander and abuse lookup patterns.
- **Rate limits are load protection, not abuse prevention.** A single scan makes 200-800 outbound HTTP requests. Three scans per IP per hour is a genuine concurrency ceiling on the VPS, not a soft policy. Enforce it before spawning any async work.
- **Adult content exclusion by default.** WMN tags adult sites with a boolean. Filter them out at the parser level unless the user explicitly toggles "include adult sites" in the UI. Sherlock does not tag consistently so err on the side of exclusion when in doubt.
- **False positives are real.** 5 to 10% of hits will be false positives from sites that return 200 for any username or that bot-detect and serve a generic page. Surface this in the UI and in the docs, do not overstate confidence.
- **Do not use nano.** Use sed, vi, or `sudo tee` heredoc as always.
- **No auth surface, no admin gate.** Public tool, public feature, same as URL Expander and QR.

## Part A. Dependency check and data ingestion

### A1. Verify existing deps

```bash
cd /opt/falconeye/app_src
python3 -c "import httpx; print('httpx', httpx.__version__)"
python3 -c "import yaml; print('PyYAML', yaml.__version__)" 2>&1
python3 -c "import json; print('json stdlib ok')"
```

Report results. httpx is present. PyYAML may or may not be, depending on whether the initial WMN data file is YAML or JSON.

### A2. Fetch and vendor WMN data

WMN publishes their data file at:
```
https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json
```

(Confirm the current path via web search before fetching; WebBreacher has restructured the repo occasionally.)

```bash
mkdir -p /opt/falconeye/app_src/app/data/whatsmyname
curl -sSL https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json \
  -o /opt/falconeye/app_src/app/data/whatsmyname/wmn-data.json
ls -la /opt/falconeye/app_src/app/data/whatsmyname/
python3 -c "import json; d = json.load(open('/opt/falconeye/app_src/app/data/whatsmyname/wmn-data.json')); print('WMN sites:', len(d.get('sites', d)))"
```

Site count should be 600+. If under 400 or fetch fails, stop and report.

### A3. Fetch and vendor Sherlock data

Sherlock publishes their site list at:
```
https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json
```

(Confirm current path via web search before fetching; the sherlock-project repo has moved data.json a few times.)

```bash
mkdir -p /opt/falconeye/app_src/app/data/sherlock
curl -sSL https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json \
  -o /opt/falconeye/app_src/app/data/sherlock/data.json
ls -la /opt/falconeye/app_src/app/data/sherlock/
python3 -c "import json; d = json.load(open('/opt/falconeye/app_src/app/data/sherlock/data.json')); print('Sherlock sites:', len(d))"
```

Site count should be 350+. If fetch fails or file is empty, drop Sherlock from v3.8.0 and proceed WMN-only. Log the fallback decision in the CHANGELOG.

### A4. Refresh script for future releases

Create `scripts/refresh_username_data.py`:

```python
"""Refresh vendored WhatsMyName and Sherlock data files.

Run manually before each username enumeration tab release cycle.
Fetches from upstream, validates schema, writes to app/data/.
"""
import json
import sys
from pathlib import Path
import httpx

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
SHERLOCK_URL = "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json"

DATA_DIR = Path(__file__).resolve().parent.parent / "app" / "data"


def fetch_and_validate(url: str, target: Path, min_sites: int, source_name: str) -> None:
    print(f"Fetching {source_name}...")
    r = httpx.get(url, timeout=30.0, follow_redirects=True)
    r.raise_for_status()
    data = r.json()

    if isinstance(data, dict) and "sites" in data:
        count = len(data["sites"])
    elif isinstance(data, dict):
        count = len(data)
    elif isinstance(data, list):
        count = len(data)
    else:
        print(f"ERROR: unexpected {source_name} shape", file=sys.stderr)
        sys.exit(1)

    if count < min_sites:
        print(f"ERROR: {source_name} returned {count} sites, expected {min_sites}+", file=sys.stderr)
        sys.exit(1)

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2))
    print(f"  wrote {count} sites to {target}")


def main() -> None:
    fetch_and_validate(WMN_URL, DATA_DIR / "whatsmyname" / "wmn-data.json", 400, "WhatsMyName")
    fetch_and_validate(SHERLOCK_URL, DATA_DIR / "sherlock" / "data.json", 300, "Sherlock")


if __name__ == "__main__":
    main()
```

Test it:

```bash
python3 /opt/falconeye/app_src/scripts/refresh_username_data.py
```

Should print counts for both sources.

## Part B. Backend implementation

### B1. Parser module

Path: `app/username/parser.py`

Two adapters, one unified output.

```python
"""Parse WMN and Sherlock data files into a unified internal site list."""
from dataclasses import dataclass
from pathlib import Path
import json
from typing import Literal


@dataclass
class Site:
    name: str
    url_template: str  # contains {username}
    category: str
    detection: dict    # engine-specific keys, see below
    sources: list[str] # ["wmn"], ["sherlock"], or ["wmn", "sherlock"]
    is_nsfw: bool
    priority: int      # 1-3, higher = more likely to yield useful hits


def load_wmn(path: Path) -> list[Site]:
    """Parse WhatsMyName data file.

    WMN detection schema:
      - e_code: expected HTTP status on hit (int)
      - e_string: expected substring in response body on hit
      - m_code: expected status on miss
      - m_string: expected substring on miss
    """
    ...


def load_sherlock(path: Path) -> list[Site]:
    """Parse Sherlock data file.

    Sherlock detection schema:
      - errorType: "status_code" | "message" | "response_url"
      - errorMsg: string that appears when username does NOT exist (for message type)
      - errorCode: status code for non-existence (for status_code type)
      - errorUrl: URL redirected to when username does not exist (for response_url type)

    Invert to hit-detection: hit is the absence of error signal.
    """
    ...


def merge_sites(wmn_sites: list[Site], sherlock_sites: list[Site]) -> list[Site]:
    """Deduplicate sites appearing in both engines.

    Key: normalized hostname of the url_template (lowercase, strip www).
    On collision: prefer WMN's detection (better-tested), tag sources=["wmn", "sherlock"].
    """
    ...


def load_all(data_dir: Path) -> list[Site]:
    """Convenience: load both, merge, return unified list."""
    ...
```

Category taxonomy (map both engines onto):

- Social (Facebook, Twitter, Instagram, etc.)
- Developer (GitHub, GitLab, StackOverflow, etc.)
- Gaming (Steam, Xbox, PSN, Twitch)
- Forum (Reddit, various vBulletin sites)
- Regional (weibo, VK, LINE, etc.)
- Adult (excluded by default)
- Other (anything unmapped)

Sherlock does not have categories. Map Sherlock-only sites by hostname pattern where obvious, otherwise "Other".

Priority (1-3):
- 3: high-value sites always worth checking (top 20 platforms)
- 2: mid-value, forums and dev platforms
- 1: everything else

Quick Scan = priority 2 and 3 only (~200 sites). Full Scan = all priorities (~800 sites).

### B2. Checker module

Path: `app/username/checker.py`

```python
"""Async httpx sweep against a list of sites for a given username."""
import asyncio
import httpx
from urllib.parse import quote
from typing import Callable
from .parser import Site
from app.utils.safe_fetch import check_url


@dataclass
class CheckResult:
    site: Site
    hit: bool
    profile_url: str | None  # populated on hit
    status_code: int | None
    error: str | None
    elapsed_ms: int


async def check_one(client: httpx.AsyncClient, site: Site, username: str) -> CheckResult:
    """Check a single site. Never raises. Returns CheckResult with error populated on failure."""
    encoded = quote(username, safe="")
    url = site.url_template.replace("{username}", encoded).replace("{account}", encoded)

    ok, reason = check_url(url)
    if not ok:
        return CheckResult(site=site, hit=False, profile_url=None, status_code=None,
                          error=f"safe_fetch rejected: {reason}", elapsed_ms=0)

    # Fetch and evaluate detection heuristic based on site.detection
    ...


async def sweep(sites: list[Site], username: str, concurrency: int = 20,
                progress_callback: Callable = None) -> list[CheckResult]:
    """Run all site checks with a semaphore-bounded concurrency cap.
    Returns list of results in undefined order.
    """
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=False,
                                  headers={"User-Agent": "FalconEye/3.8.0 (+https://falconeye.osintph.info)"}) as client:
        tasks = [_bounded_check(sem, client, site, username) for site in sites]
        results = await asyncio.gather(*tasks, return_exceptions=False)
    return results


async def _bounded_check(sem, client, site, username):
    async with sem:
        return await check_one(client, site, username)
```

Detection logic per site (implemented inside `check_one`):

- **WMN e_code + e_string**: hit if status matches e_code AND e_string appears in body
- **WMN m_code + m_string**: miss if status matches m_code OR m_string appears in body
- **Sherlock status_code**: hit if status is NOT the errorCode
- **Sherlock message**: hit if errorMsg does NOT appear in body
- **Sherlock response_url**: hit if final URL does NOT match errorUrl

Timeouts and connection errors: not a hit, error populated, continue.

### B3. Merger module

Path: `app/username/merger.py`

Post-processing on the raw CheckResult list:

- Filter to hits only
- Group by category
- Sort within category by source count descending (dual-source first) then site name
- Add confidence tier: `high` if sources=["wmn","sherlock"], `medium` otherwise
- Compute summary stats: total checked, hits, per-category counts, dual-source count

### B4. Router

Path: `app/username/routes.py`

```python
POST /api/username/scan
  Body: {"username": str, "scope": "quick" | "full", "include_nsfw": bool}
  Auth: none
  Rate limit: 3 per client IP per hour, 20 per day, 100 global per day
  Returns: {
    "username": str,
    "scope": str,
    "checked_count": int,
    "hit_count": int,
    "dual_source_count": int,
    "duration_ms": int,
    "categories": [
      {
        "name": str,
        "hits": [
          {"site": str, "url": str, "confidence": "high" | "medium",
           "sources": ["wmn"] | ["sherlock"] | ["wmn", "sherlock"]}
        ]
      }
    ],
    "warnings": [str]
  }
```

Username validation: `^[a-zA-Z0-9._-]{1,40}$`. Reject anything else with 400 and clear error message.

Register router in `app/main.py`.

### B5. Rate limit tables

Add to `app/database.py`:

```sql
CREATE TABLE IF NOT EXISTS username_rate_limit (
  scope TEXT NOT NULL,  -- 'ip:<clientip>' or 'global'
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_username_rl_scope_ts
  ON username_rate_limit(scope, ts);
```

Self-initialize at import per the pattern the abuse tab established.

## Part C. Frontend implementation

### C1. Tab nav entry

`app/static/index.html`. Insert Username tab between Contact and News. Icon: user silhouette SVG, matching existing tab icon style (monochrome, inherits currentColor, same size as neighbors).

### C2. Username panel

Content layout:

- Hero heading: `Username Enumeration`
- Subtitle: `Check where a username appears across ~800 platforms using WhatsMyName and Sherlock data. Cross-validated hits carry higher confidence. Results are leads for human verification, not proof of identity.`
- Input: single text field for username, sample link (`Try sample (test)` fills with a known-existing test username)
- Scope toggle: radio buttons `Quick Scan (~200 sites, faster)` / `Full Scan (all sites, ~60s)`. Default: Quick.
- NSFW toggle: checkbox `Include adult platforms`, default off, small hint text explaining what this does
- Investigate button (label: `Scan`)

### C3. Results rendering

- Progress indicator during scan (simple spinner is fine, no live progress needed for sync request)
- Summary card at top:
  - Total sites checked
  - Total hits
  - Dual-source (high-confidence) hit count
  - Duration
- Category sections, collapsible, sorted by hit count descending:
  - Section header: category name + hit count badge
  - Per-hit card: platform name, profile URL as clickable link (target=_blank rel=noopener), confidence badge (green `high` or gray `medium`), source badges (`WMN`, `Sherlock`, or both)
- Empty categories collapsed by default
- Footer: `Export as CSV` button, downloads a CSV of all hits

### C4. Pivots

Where relevant, one-click pivot buttons on individual hits:
- Telegram hit → button pushes username to Telegram tab
- Domain hit (some sites have username-in-subdomain patterns like `{username}.medium.com`) → push hostname to Domain tab
- Copy handle button → copies the username to clipboard (useful when the investigator wants to paste elsewhere)

### C5. Warnings and disclaimers

Prominent yellow callout above results:

> **How to use this.** A hit means the username has a profile at that platform. It does NOT mean the same person owns all matching profiles. False positives run 5 to 10% because some platforms return the same response for any username. Verify each lead manually before drawing conclusions. Do not use this tool for stalking or harassment.

## Part D. Documentation

### D1. Update README.md

- Bump `Current version: **3.7.1**` to `**3.8.0**`
- Feature intro paragraph: add `username enumeration across 800 platforms`
- Update Tabs section with the new Username entry

### D2. Prepend CHANGELOG.md with v3.8.0

Entry text:

```
## v3.8.0 (YYYY-MM-DD)

### Added

- **Username Enumeration tab.** Check where a username appears across roughly 800 platforms using vendored data from WhatsMyName and Sherlock, merged and deduplicated. Cross-validated hits (present in both engines) carry a "high confidence" badge, single-source hits carry "medium". Quick Scan (top 200 priority sites, ~15s) and Full Scan (all sites, ~60s) modes. Adult platforms excluded by default with an opt-in toggle. Rate limits: 3 scans per client IP per hour, 20 per day, 100 global per day. One-click pivots to Telegram, Domain, and clipboard.
- **Vendored data pipeline.** WhatsMyName and Sherlock data files vendored under `app/data/`. Refresh script at `scripts/refresh_username_data.py` fetches upstream and validates schema, run manually at release cadence.
- **Category taxonomy** for hits: Social, Developer, Gaming, Forum, Regional, Adult, Other. Mapping applied at parse time.
- **Strict username validation** and URL encoding on all substituted templates. Every outbound check passes through the existing `safe_fetch` helper.

### Operator notes

Both WhatsMyName and Sherlock are MIT-licensed and vendored, no runtime dependency on either project's code. Refresh cadence is at operator discretion; suggested every 4 to 6 weeks or before major releases. False positives run 5 to 10% because some platforms serve identical responses to any username query; hits are surfaced as leads for human verification.
```

### D3. New docs page: `docs/username-enumeration.md`

Sections:

1. **Overview** — what the tab does, what a hit means, what it does not mean
2. **Data sources** — WMN and Sherlock, both MIT, both vendored, refresh cadence
3. **Confidence tiers** — high (dual-source), medium (single-source), how to interpret
4. **False positive expectations** — 5-10% typical, why, how to mitigate
5. **Rate limits** — the numbers and why
6. **Ethical use** — brief statement about not using for stalking or harassment
7. **Data refresh procedure** — how to run `scripts/refresh_username_data.py` and when

### D4. Update JSON-LD softwareVersion and main.py version

Both to `3.8.0`. Add username enumeration to the `featureList` array in JSON-LD.

## Part E. Testing

Same discipline as v3.7.0: unit tests on the Mac dev environment, deployed to staging on :8001, smoke tests before Sigmund click-through.

### E1. Unit tests

`tests/username/test_parser.py`:
- WMN JSON fixture parses to correct site count
- Sherlock JSON fixture parses to correct site count
- Merge dedups by hostname
- NSFW filter excludes tagged sites
- Malformed data returns empty list, does not raise

`tests/username/test_checker.py`:
- Mock httpx responses for hit cases per detection type (WMN e_code, WMN e_string, Sherlock status_code, Sherlock message, Sherlock response_url)
- Mock miss cases for each type
- Mock timeout returns error result, does not raise
- Concurrency cap is respected (assert max concurrent requests)
- Username with special chars gets URL-encoded correctly
- Username with path traversal (`../etc/passwd`) is rejected before check runs

`tests/username/test_merger.py`:
- Hits grouped by category correctly
- Dual-source hits marked as high confidence
- Empty categories excluded from output

`tests/username/test_routes.py`:
- Valid username returns 200 with structured response
- Invalid username returns 400 with clear error
- Rate limit blocks 4th request within an hour
- Quick vs Full scope produces different site counts

Run:

```bash
cd /opt/falconeye/app_src
source venv/bin/activate
pytest tests/username/ -v
```

All must pass.

### E2. Deploy to staging on :8001

Same rsync pattern as v3.7.0. Live service on :8000 stays at 3.7.1 untouched.

### E3. Smoke test

```bash
curl -s -X POST http://127.0.0.1:8001/api/username/scan \
  -H "Content-Type: application/json" \
  -d '{"username": "test", "scope": "quick", "include_nsfw": false}' | python3 -m json.tool | head -60
```

Expected: `checked_count` around 200, some `hits`, `duration_ms` under 30000.

Test validation:

```bash
curl -s -X POST http://127.0.0.1:8001/api/username/scan \
  -H "Content-Type: application/json" \
  -d '{"username": "../etc/passwd", "scope": "quick", "include_nsfw": false}'
```

Expected: 400 with clear validation error.

Test rate limit: run the scan 4 times in quick succession. Fourth must return `rate_limited: true` or 429.

## Part F. Human review

Same pattern as v3.7.0. Staging up on :8001, Claude Code stops, Sigmund clicks through.

Checklist:

- [ ] Enter a known username (yours or another public handle). Confirm hits appear in expected categories.
- [ ] Enter a nonsense username like `xnzq837hvbcnzxbnv`. Confirm zero or very few hits.
- [ ] Toggle Full Scan. Confirm site count and duration match expectations.
- [ ] Read a few hits. Click through profile links. Confirm they resolve.
- [ ] Try the CSV export button. Confirm the file downloads and contains all hits.
- [ ] Try a Telegram pivot on a Telegram hit. Confirm the Telegram tab prefills.
- [ ] Test invalid usernames (path traversal, spaces, unicode). Confirm the tab rejects cleanly with a helpful error.

Report changes to Claude Code. Common asks: category rewording, priority adjustments, sample username change.

## Part G. Commit, tag, release

Only after Sigmund approves staging.

### G1. Commit

```bash
git add -A
git commit -m "v3.8.0: Username Enumeration tab

Dual-engine username lookup across roughly 800 platforms using vendored
data from WhatsMyName (600 sites) and Sherlock (400 sites), merged and
deduplicated. Cross-validated hits carry a high-confidence badge,
single-source hits carry medium. Quick Scan (top 200 priority sites,
~15s) and Full Scan (all sites, ~60s) modes.

Strict username validation, URL encoding on every substituted template,
safe_fetch on every outbound request. Concurrency capped at 20. Rate
limits: 3 scans per client IP per hour, 20 per day, 100 global per day.

Vendored data pipeline: refresh script at scripts/refresh_username_data.py.
Both data sources are MIT-licensed and vendored, no runtime dependency
on either upstream project.

Version bumps: README, CHANGELOG, JSON-LD, main.py app + health."
```

### G2. Tag and push

```bash
git tag -a v3.8.0 -m "v3.8.0: Username Enumeration"
git push origin main
git push origin v3.8.0
```

### G3. GitHub release

Standard `gh release create v3.8.0` with notes derived from CHANGELOG. Same pattern as v3.7.1.

### G4. Live deploy

Sigmund's call. Option B pattern from v3.7.1: commit and push land the release, live flip is a separate deliberate action. Claude Code hands Sigmund the exact restart command syntax for his systemd unit.

## Final report to Sigmund

1. Confirm dual-engine shipped (or WMN-only if Sherlock had to be dropped in Part A).
2. Total site count merged.
3. Unit test count and pass status.
4. Staging clicked through and approved.
5. Commit hash, tag, release URL.
6. Live flip command syntax for Sigmund.
7. Refresh script location and suggested cadence.
8. Blog post draft is next.
