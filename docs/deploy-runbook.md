# FalconEye deploy / release runbook

The canonical, verified deploy sequence for FalconEye. This is the **real**
mechanism the production box uses — earlier briefs that described a `git pull`
deploy did not match it. Keep this doc in sync with reality.

## Where it runs

- Host: single OVH VPS, SSH on port 9999 as `ubuntu` (see private ops notes).
- App: gunicorn under systemd unit **`falconeye`** — `User=ubuntu`,
  `WorkingDirectory=/opt/falconeye/app_src`, bound `127.0.0.1:8000`, 3 workers,
  `--timeout 90`. nginx in front; Cloudflare at the edge.
- Code tree: `/opt/falconeye/app_src` (a git checkout, deployed by resetting to a
  **tag** since v3.28.0, see below). Runtime data/config live **outside** the tree:
  `/opt/falconeye/data/` (SQLite DBs), `/opt/falconeye/private/` (watchlist etc.),
  `/opt/falconeye/venv/` (Python), `/opt/falconeye/backups/`.
- Staging tree: `/opt/falconeye/staging_src`, a second independent git checkout.
  **There is no staging systemd unit** and nothing normally listens on `:8001`.

## Ownership invariant (root cause of past deploy friction — normalized 2026-07-25)

The whole tree under `/opt/falconeye/app_src` must be owned by **`ubuntu:ubuntu`**
(the service user). For a long time the tracked **files** were `ubuntu`-owned but
several **directories** (`app/`, `app/static/`, `app/utils/`, `app/ip_sources/`,
`tests/`) were owned by uid **501** (the Mac account) — the leftover of an
`rsync -a` run as root whose follow-up `chown` step was skipped (macOS `rsync`
has no `--chown`, so the chown is a *separate* step and is easy to miss). Effect:
`ubuntu` could edit existing files in place but **could not create or delete**
files in those dirs, so `git pull` / `git reset --hard` and any new-file or
deletion deploy failed with permission errors — which is why deploys quietly
became "overwrite existing files in place" and the git checkout drifted.

**Fixed once, on 2026-07-25:**

```
sudo chown -R ubuntu:ubuntu /opt/falconeye/app_src
```

After this, `git reset --hard origin/main` works cleanly (verified), and the
checkout was reconciled from a stale v3.19.0 HEAD back to `origin/main`. **If a
future deploy ever reintroduces uid-501 on a directory (an `rsync` as root without
the chown), re-run the chown above.** Verify with:
`ssh … 'stat -c "%U:%G %n" /opt/falconeye/app_src/app /opt/falconeye/app_src/app/utils'`,
or count offenders directly:
`ssh … 'find /opt/falconeye/app_src ! -user ubuntu | wc -l'` (expect `0`).

**`staging_src` drifts independently and was still broken until 2026-08-23.**
`app_src` was normalized in July but `/opt/falconeye/staging_src` was not, so the
first staged deploy failed with `unable to unlink old 'app/config.py': Permission
denied` and `cannot create directory at 'tests/scanner'`. Fixed with the same
command against the staging path. **Check both trees.**

**Corollary: never run the deploy git commands under `sudo`.** With ownership
normalized they do not need root, and `sudo git` is what created the ~180
root-owned loose objects under `.git/objects/` that later made ordinary commits
fail with `insufficient permission for adding an object to repository database`.
Verify none exist: `ssh … 'sudo find /opt/falconeye/app_src/.git/objects -user root | wc -l'`
(expect `0`).

## Standard release sequence

Author on the Mac (`/Users/sigmund/code/falconeye`); the VPS checkout is a mirror.

1. **Make the change** on the Mac.
2. **Version bump — 5 places** (only when cutting a release). There is no shared
   version constant; every one of these is hand-edited, so grep before you push:
   `grep -rn "<old-version>" README.md app/main.py app/static/index.html`.
   - `app/main.py` — `FastAPI(version=…)` **and** the `/health` return.
   - `app/static/index.html` — JSON-LD `softwareVersion`.
   - `app/static/index.html` — the `?v=` cache-bust on **both** `app.js` and
     `style.css` (this is what makes browsers/Cloudflare refetch — no manual
     purge needed).
   - `README.md` — the `Current version: **x.y.z**` line near the top, **and**
     the "controls are in place as of vX.Y.Z" line under Security posture. This
     one is easy to miss and silently drifted from v3.20.0 to v3.28.0, eight
     releases, before anyone noticed.

   Version strings that are **not** part of the bump: `vX.Y.Z` references inside
   code comments, docstrings, HTML comments and `.env.example` are historical
   ("introduced in vX.Y.Z") and must be left alone. Two cosmetic ones are pinned
   and go stale by design: `Description=` in `falconeye.service` and the banner
   `echo` in `scripts/provision.sh`, both still saying v3.5.0.
3. **CHANGELOG.md** — Keep a Changelog format: `## [x.y.z] - YYYY-MM-DD`, newest
   on top, `---` between entries. That separator is a **plain ASCII hyphen**, not
   an en/em dash; check an existing heading before writing a new one.
4. **Merge, tag, push — all from the Mac** (Mac `origin` is SSH with a key; `gh`
   is authed as `osintph` and is **not** on the VPS). History is **linear, no
   merge commits**, so land feature work with a fast-forward:
   `git checkout main && git merge --ff-only <branch>`. Tags are **annotated**
   (`git tag -a vX.Y.Z -m "…"`, tagger `osintph <sb@osintph.info>`). Then
   `git push origin main && git push origin vX.Y.Z`. Confirm it landed:
   `git ls-remote --tags origin vX.Y.Z`.
5. **Record the rollback target before touching the box:**
   `ssh … 'cd /opt/falconeye/app_src && git rev-parse HEAD'`. Write it down.
6. **Stage on `:8001` first** (see "Staging" below). Do not skip this for anything
   that adds a router, a table, or a dependency.
7. **Deploy the tag to the box.** Deploy a **tag, never a branch**:
   ```
   ssh … 'cd /opt/falconeye/app_src && git fetch --tags origin && git reset --hard vX.Y.Z'
   ```
   No `sudo` (see the ownership section). The VPS *can* fetch from GitHub over
   HTTPS because the repo is public; only push needs credentials. The older
   `rsync -a --relative … --rsync-path="sudo rsync"` recipe plus a mandatory
   `sudo chown -R ubuntu:ubuntu` remains the fallback if ownership ever drifts.
8. **Dependencies.** Prove whether anything changed rather than guessing:
   `git diff <prev-tag> <new-tag> -- requirements.txt` (empty means no change).
   If it changed: `sudo /opt/falconeye/venv/bin/pip install -r requirements.txt`.
   Beware naive `pip list` diffs: extras (`qrcode[pil]`, `uvicorn[standard]`,
   `redis[asyncio]`) look "missing" because pip lists the base name.
9. **Restart** if any `.py` changed: `sudo systemctl restart falconeye`
   (passwordless sudo). Static-only needs no restart.
10. **Verify:**
    - `sudo systemctl status falconeye --no-pager | head -10` → `active (running)`.
    - `sudo journalctl -u falconeye --since "5 min ago" --no-pager | grep -ci traceback`
      → `0`. Older tracebacks in the buffer are pre-existing; scope by time.
    - Origin: `curl -s http://127.0.0.1:8000/health` → expect the new version.
    - Public edge: `curl -s https://falconeye.osintph.info/ | grep 'app.js?v='`.
    - New self-creating tables landed:
      `sudo sqlite3 /opt/falconeye/data/falconeye.db "SELECT name FROM sqlite_master WHERE name LIKE '<prefix>_%';"`.
    - If an IP-response field changed, flush stale rows:
      `sudo sqlite3 /opt/falconeye/data/falconeye.db "DELETE FROM ip_intel_cache
      WHERE response_json NOT LIKE '%<newfield>%';"`.
11. **GitHub release from the Mac:**
    `gh release create vX.Y.Z --repo osintph/falconeye --verify-tag --title "vX.Y.Z: <summary>" --notes-file <file>`.
12. **Keep both checkouts in sync** so they never drift:
    `ssh … 'cd /opt/falconeye/app_src && git fetch --tags origin && git reset --hard <tag-or-origin/main>'`,
    and the same for `staging_src`. Leave **no feature branch** checked out on the
    box: `git rev-parse --abbrev-ref HEAD` should be `main`.

## Rollback

The reverse of step 7, using the sha recorded in step 5:

```
ssh … 'cd /opt/falconeye/app_src && git reset --hard <previous-sha>'
ssh … 'sudo /opt/falconeye/venv/bin/pip install -r requirements.txt'   # only if deps changed
ssh … 'sudo systemctl restart falconeye'
curl -s http://127.0.0.1:8000/health   # expect the OLD version back
```

## Staging on `:8001`

There is **no staging service**. `falconeye.service` is the only FalconEye unit,
so there is nothing to `systemctl restart` and no staging journal. Staging is the
second checkout plus a throwaway uvicorn:

```
ssh … 'cd /opt/falconeye/staging_src && git fetch --tags origin && git reset --hard vX.Y.Z'
ssh … 'cd /opt/falconeye/staging_src && nohup env FALCONEYE_DB=/tmp/falconeye_staging.db \
   /opt/falconeye/venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 \
   > /tmp/staging_8001.log 2>&1 &'
```

Read `/tmp/staging_8001.log`, not `journalctl`. Smoke-test against
`http://127.0.0.1:8001` directly, which bypasses Cloudflare.

Two traps, both hit on 2026-08-23:

- **Never `pkill -f "port 8001"` over SSH.** The pattern matches your own remote
  command line and kills the SSH session, silently, with empty output. Kill the
  listener by PID instead:
  ```
  PID=$(sudo ss -ltnp | grep ":8001" | grep -o "pid=[0-9]*" | head -1 | cut -d= -f2); kill "$PID"
  ```
- **A fresh `FALCONEYE_DB` has no `phishing_scans` table**, so `/api/scanner/scan`
  returns 500 `no such table: phishing_scans` on a clean staging DB. That table
  comes from `scripts/db_init.py`; the scanner router does not self-create it the
  way newer routers do. It is a staging artifact, not a regression. Copy the
  schema in **as `ubuntu`, not root** (root writes fail with "attempt to write a
  readonly database"):
  ```
  sudo sqlite3 /opt/falconeye/data/falconeye.db ".schema phishing_scans" > /tmp/ps.sql
  sqlite3 /tmp/falconeye_staging.db < /tmp/ps.sql
  ```

## Notes

- **Do NOT `git push` from the VPS** — its `origin` is HTTPS with no credentials.
  Push from the Mac. `git fetch` from the VPS is fine (public repo).
- **Cloudflare purge is not a release step.** The `?v=<version>` cache-bust from
  step 2 changes the cache key, so the edge refetches on its own. Verified on the
  v3.28.0 deploy: minutes after the restart the edge served
  `/static/app.js?v=3.28.0` with `cf-cache-status: HIT` and the new build's
  content, while `index.html` stayed `cf-cache-status: DYNAMIC`. There is no CF
  API token on either machine and none should be added; if a purge is ever wanted,
  it is a manual dashboard action, never a gate on the release.
- nginx config exists in **two** places (repo `nginx/falconeye.conf` and live
  `/etc/nginx/sites-available/falconeye`); patch both, `sudo systemctl reload
  nginx`.
- Verify origin CSP (bypassing the Cloudflare challenge):
  `curl -skI --resolve falconeye.osintph.info:443:127.0.0.1
  https://falconeye.osintph.info/`.
- No `node` on Mac or VPS; syntax-check `app.js` with macOS JavaScriptCore:
  `osascript -l JavaScript` + `new Function(<source>)` (parses, doesn't execute).
