# FalconEye deploy / release runbook

The canonical, verified deploy sequence for FalconEye. This is the **real**
mechanism the production box uses — earlier briefs that described a `git pull`
deploy did not match it. Keep this doc in sync with reality.

## Where it runs

- Host: single OVH VPS, SSH on port 9999 as `ubuntu` (see private ops notes).
- App: gunicorn under systemd unit **`falconeye`** — `User=ubuntu`,
  `WorkingDirectory=/opt/falconeye/app_src`, bound `127.0.0.1:8000`, 3 workers,
  `--timeout 90`. nginx in front; Cloudflare at the edge.
- Code tree: `/opt/falconeye/app_src` (a git checkout, but **not** deployed by
  pulling — see below). Runtime data/config live **outside** the tree:
  `/opt/falconeye/data/` (SQLite DBs), `/opt/falconeye/private/` (watchlist etc.),
  `/opt/falconeye/venv/` (Python), `/opt/falconeye/backups/`.

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
`ssh … 'stat -c "%U:%G %n" /opt/falconeye/app_src/app /opt/falconeye/app_src/app/utils'`.

## Standard release sequence

Author on the Mac (`/Users/sigmund/code/falconeye`); the VPS checkout is a mirror.

1. **Make the change** on the Mac.
2. **Version bump — 4 places** (only when cutting a release):
   - `app/main.py` — `FastAPI(version=…)` **and** the `/health` return.
   - `app/static/index.html` — JSON-LD `softwareVersion`.
   - `app/static/index.html` — the `?v=` cache-bust on **both** `app.js` and
     `style.css` (this is what makes browsers/Cloudflare refetch — no manual
     purge needed).
3. **CHANGELOG.md** — Keep a Changelog format: `## [x.y.z] — YYYY-MM-DD`, newest
   on top, `---` between entries.
4. **Commit (surgical), tag, push, GitHub release — all from the Mac** (Mac
   `origin` is SSH with a key; `gh` is authed as `osintph` and is **not** on the
   VPS): `git commit … && git tag -a vX.Y.Z && git push origin main && git push
   origin vX.Y.Z && gh release create vX.Y.Z …`.
5. **Deploy files to the box.** With the ownership invariant satisfied, either:
   - **In-place file changes** (edits to existing files): overwrite as `ubuntu`
     (rsync, scp, or `cat >` redirect). Static-only changes work with no restart.
   - **New files / deletions, or a full sync**: `rsync -a --relative -e "ssh -p
     9999" --rsync-path="sudo rsync" <files> ubuntu@<host>:/opt/falconeye/app_src/`
     then `ssh … 'sudo chown -R ubuntu:ubuntu <paths>'` (the chown is mandatory —
     see the invariant). Or, now that ownership is normalized, simply
     `ssh … 'cd /opt/falconeye/app_src && git fetch && git reset --hard
     origin/main'`.
6. **Dependencies** (if `requirements.txt` changed):
   `sudo /opt/falconeye/venv/bin/pip install -r requirements.txt`.
7. **Restart** if any `.py` changed: `sudo systemctl restart falconeye`
   (passwordless sudo). Static-only needs no restart.
8. **Verify:**
   - Origin: `curl -s http://127.0.0.1:8000/health` → expect the new version.
   - Public edge: `curl -s https://falconeye.osintph.info/ | grep 'app.js?v='`.
   - If an IP-response field changed, flush stale rows:
     `sudo sqlite3 /opt/falconeye/data/falconeye.db "DELETE FROM ip_intel_cache
     WHERE response_json NOT LIKE '%<newfield>%';"`.
9. **Keep the checkout in sync** so it never drifts again:
   `ssh … 'cd /opt/falconeye/app_src && git fetch && git reset --hard origin/main'`.

## Notes

- **Do NOT `git push` from the VPS** — its `origin` is HTTPS with no credentials.
  Push from the Mac.
- nginx config exists in **two** places (repo `nginx/falconeye.conf` and live
  `/etc/nginx/sites-available/falconeye`); patch both, `sudo systemctl reload
  nginx`.
- Verify origin CSP (bypassing the Cloudflare challenge):
  `curl -skI --resolve falconeye.osintph.info:443:127.0.0.1
  https://falconeye.osintph.info/`.
- No `node` on Mac or VPS; syntax-check `app.js` with macOS JavaScriptCore:
  `osascript -l JavaScript` + `new Function(<source>)` (parses, doesn't execute).
