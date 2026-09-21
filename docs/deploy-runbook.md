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

## Prerequisites: system packages

`requirements.txt` does not cover everything the app needs. Two kinds of native
dependency exist outside pip, both invisible to `ldd` and to `pip install`, and
both failing only later:

- a shared library **dlopened at runtime through ctypes**, which fails at import
- a **binary invoked as a subprocess**, which fails when the feature is used

Compiled extension modules are not the problem. The wheels for `lxml`, `Pillow`
and `rapidfuzz` statically link what they need, verified with `ldd` against the
installed venv: every `.so` resolves only `libc`, `libm`, `libstdc++`, `libgcc_s`
and `libz`, all of which are on any Ubuntu. So the full list is short:

```
sudo apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    git redis-server \
    libzbar0 whois
```

| Package | Needed by | Failure if missing |
|---|---|---|
| `python3`, `python3-pip`, `python3-venv` | the venv | provisioning cannot start |
| `git` | `scripts/provision.sh` clone, and tag deploys | provisioning cannot start |
| `redis-server` | Prospect tab response cache | cache disabled, tab still works |
| `libzbar0` | `pyzbar`, QR Code tab | **`ImportError: Unable to find zbar shared library`, and the whole app fails to import** |
| `whois` | `app/routers/domain_intel.py`, `app/utils/domain_age.py` | silent: the whois fallback returns nothing |

Two traps in that table.

**`libzbar0` is the one that takes the app down completely.** `pyzbar` loads the
library with `ctypes.util.find_library("zbar")` rather than linking it, so
nothing in `pip install` or `ldd` reveals the dependency. `app/main.py` imports
the QR router at module level, so the failure is not confined to that tab: the
process will not start at all. On Ubuntu 24.04 the real package is
`libzbar0t64` after the `time_t` transition, but it declares
`Provides: libzbar0`, so the name `libzbar0` resolves correctly on 22.04 and
24.04 alike. Use that name.

**`whois` fails quietly, which is worse to diagnose.** Both call sites wrap the
subprocess in a broad `except` and log, so a missing binary shows up
as a Domain Intel tab that simply has no whois text, with nothing in the UI to
say why. Its Debian priority is `standard`, meaning it is present on a full
Ubuntu install but **not** on the minimal cloud images most VPS and AWS
instances boot from, which is exactly where this bites.

Optional, not required by the service:

- `sqlite3` for the CLI used by the verification commands throughout this
  runbook. The app itself uses Python's built-in `sqlite3` module and needs no
  package.
- `build-essential` and `python3-dev` only if pip has to build a wheel from
  source, which happens on architectures without prebuilt wheels. On amd64 and
  arm64 every pinned dependency ships one, so these are not installed by
  default.

### The provisioning smoke test

`scripts/provision.sh` step 7 runs `venv/bin/python -c "import app.main"` before
enabling the service, and aborts if it fails. This exists because a missing
native library otherwise surfaces inside a gunicorn worker: systemd restarts it
every 5 seconds, the real traceback scrolls past in the journal, and the
operator sees a restart loop rather than an error. Run it by hand any time the
service will not start:

```
cd /opt/falconeye/app_src && /opt/falconeye/venv/bin/python -c "import app.main"
```

Clean output and exit 0 means every native dependency resolved. An `ImportError`
naming a shared library means a missing apt package, not a missing Python one.

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

   **Never remove `--forwarded-allow-ips 127.0.0.1` from the ExecStart line, and
   never set `FORWARDED_ALLOW_IPS` in `.env`.** Every per-IP rate limit depends
   on it. uvicorn rewrites the client peer from `X-Forwarded-For` only for peers
   in that list, taking the **right-most** entry — which nginx sets to the
   Cloudflare edge IP, and which `app/utils/client_ip.py` then checks against the
   Cloudflare ranges. With `*` uvicorn takes the **left-most** entry instead,
   which is fully caller-supplied: the peer becomes attacker-chosen and the paid
   LLM endpoints lose their limits. An explicit CLI flag beats the env var, which
   is why the flag is there rather than a comment. `tests/unit/test_client_ip.py`
   fails if it is removed. If the unit file changed, `sudo systemctl
   daemon-reload` before restarting or systemd keeps running the old ExecStart.
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

## nginx files, and what the repo ships

The vhost `nginx/falconeye.conf` does not stand alone. It has one required
dependency and one optional one, both of which live in the repo:

| File | Installs to | Required |
|---|---|---|
| `nginx/falconeye.conf` | `/etc/nginx/sites-available/falconeye` | yes |
| `nginx/snippets/cloudflare-origin-allow.conf` | `/etc/nginx/snippets/` | yes, the vhost includes it |
| `nginx/conf.d/goaccess-logformat.conf` | `/etc/nginx/conf.d/` | no, opt in |

`scripts/provision.sh` installs the first two. The third is a deliberate manual
step, described below.

History worth keeping: until v3.32.2 the vhost named `log_format goaccess_cf`,
whose only definition sat in an uncommitted file on the production box. Every
deploy from a clean clone died at `nginx -t` with
`unknown log format "goaccess_cf" in /etc/nginx/sites-enabled/falconeye:68`.
`tests/unit/test_nginx_config.py` now assembles a throwaway nginx prefix out of
the repo's `nginx/` tree alone and runs a real `nginx -t` over it, so any
reference to something the repo does not ship fails in CI rather than on a
stranger's server. That test needs the `nginx` and `openssl` binaries and skips
without them, so it does not run on the Mac. Run it on the VPS before a release
that touches nginx.

### Upgrading an install whose nginx files were hand-edited

The v3.32.1 vhost did not deploy from a clean clone, so anyone who hit the
`goaccess_cf` error most likely fixed it by editing
`/etc/nginx/sites-available/falconeye` by hand, usually by deleting the format
name from the `access_log` line. That edit and v3.32.2 do not conflict.

Re-running the provision step overwrites the live file with the repo's copy,
which now carries the same plain `access_log` line as the hand edit, plus the
snippet includes:

```
cd /opt/falconeye/app_src && git fetch --tags origin && git reset --hard v3.32.2
sudo cp nginx/snippets/*.conf /etc/nginx/snippets/
sudo cp /etc/nginx/sites-available/falconeye /etc/nginx/sites-available/falconeye.bak-$(date +%Y%m%d-%H%M%S)
sudo cp nginx/falconeye.conf /etc/nginx/sites-available/falconeye
sudo nginx -t && sudo systemctl reload nginx
```

Copy the snippets **before** the vhost. The vhost includes them, so in the other
order `nginx -t` fails and the reload is refused, leaving the old config running.

Anything else that was hand-edited in that file is overwritten too, so diff
first if the install has local changes beyond the `access_log` line:

```
diff -u /etc/nginx/sites-available/falconeye /opt/falconeye/app_src/nginx/falconeye.conf
```

To keep real visitor IPs in the log after upgrading, follow the GoAccess step
below. It is now an explicit opt-in rather than a hidden dependency.

### GoAccess log format (optional, Cloudflare only)

The default `access_log` line uses nginx's built-in `combined` format, which
logs `$remote_addr`. Behind Cloudflare that is the edge IP, so every line looks
like it came from Cloudflare and GoAccess reports are useless. To log the real
visitor IP instead:

```
sudo cp /opt/falconeye/app_src/nginx/conf.d/goaccess-logformat.conf /etc/nginx/conf.d/
sudo vi /etc/nginx/sites-available/falconeye     # append goaccess_cf to the access_log line
sudo nginx -t && sudo systemctl reload nginx
```

The line becomes:

```
access_log /var/log/nginx/falconeye_access.log goaccess_cf;
```

Order matters and is already correct: `nginx.conf` includes `conf.d/*.conf`
before `sites-enabled/*`, so the format is defined by the time the vhost refers
to it. Install the conf.d file first, or `nginx -t` fails.

**This format only works behind Cloudflare.** It logs
`$http_cf_connecting_ip`, which is empty when nothing sets that header, and
every log line then starts with a bare `-`. Without Cloudflare, stay on the
default format.

## Deploying behind Cloudflare on other infrastructure

The stock config assumes Cloudflare in front, which is the supported path, but
it also assumes a single VPS with a public IP. Running it behind Cloudflare on
AWS or similar needs four things settled. Nothing in `nginx/falconeye.conf`
changes for this topology: keep the origin allow include exactly as shipped.

**1. Origin certificate.** Generate one in the Cloudflare dashboard under
SSL/TLS > Origin Server, and save the pair at the paths the vhost already
expects:

```
/etc/ssl/falconeye/origin.crt
/etc/ssl/falconeye/origin.key
```

`sudo chmod 600 /etc/ssl/falconeye/origin.key`. An Origin CA certificate is
trusted by Cloudflare and by nothing else, which is the point: it is only ever
presented to the edge.

**2. SSL/TLS mode: Full (strict).** Anything less undermines the rest of this
section. *Flexible* sends plaintext from the edge to the origin. *Full* accepts
any certificate the origin presents, including a self-signed one, so it does not
authenticate the origin at all. Only *Full (strict)* validates it.

**3. Inbound firewall: Cloudflare ranges only.** On AWS this is the security
group on the instance or load balancer, and it replaces nothing in nginx: the
`allow`/`deny` snippet stays as a second, independent layer. Allow **443 from
the published IPv4 and IPv6 ranges only**, from
https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6.
`nginx/snippets/cloudflare-origin-allow.conf` carries the same two lists and is
the convenient copy source. Do not leave 443 open to `0.0.0.0/0` on the theory
that nginx will deny it: that is one config mistake away from an exposed origin,
and it lets anyone confirm the origin address.

Both lists matter. An IPv6-only inbound rule is easy to forget on AWS, and
Cloudflare will reach an instance over IPv6 if the subnet has it.

**4. Cloudflare Access is enforced at the edge only.** If you put Zero Trust
Access with SSO in front, understand where the boundary is: **FalconEye does not
validate `Cf-Access-Jwt-Assertion`.** There is no JWT verification anywhere in
the application. Access is a door in front of the origin, not a check inside it,
so anything that reaches the origin directly is unauthenticated and gets the
full tool, including the endpoints that spend money on LLM calls.

That makes step 3 load-bearing rather than defence in depth. The origin must be
unreachable except through Cloudflare, or Access is decorative.

### Cloudflare Tunnel

Tunnel is the usual pairing with Access on AWS, and it changes the client IP
handling, because `cloudflared` connects to nginx over the loopback interface.

**Origin allow list.** The peer is `127.0.0.1`, which is not a Cloudflare edge
range, so the shipped snippet denies everything. Replace its contents with:

```
allow 127.0.0.1;
deny all;
```

With a Tunnel there is no inbound port to firewall, so this replaces step 3
above: `cloudflared` makes an outbound connection and the instance need not
accept any inbound traffic at all.

**Client IP: use the header, not the chain.** Verified behaviour of
`cloudflared`, which is not what the naive reading suggests:

- It sets `CF-Connecting-IP` to the real visitor, correctly. Cloudflare
  overwrites any client-supplied value at the edge, so it is not spoofable.
- It does **not** sanitise `X-Forwarded-For`. It *appends* the visitor to
  whatever `X-Forwarded-For` the caller sent
  (https://github.com/cloudflare/cloudflared/issues/1426, still open), so that
  header arrives partly caller-controlled.

With the shipped nginx config the right-most untrusted entry happens to be the
real visitor today, so rate limiting is correct **by accident**: it depends on
`cloudflared` appending rather than prepending. If that open issue is ever fixed
in the obvious way, the right-most untrusted entry becomes the caller's own
first value and `get_client_ip()` starts returning an attacker-chosen address.
Do not rely on it. Pin the behaviour to the header instead.

In the `location /` block, stop forwarding the chain:

```
proxy_set_header X-Forwarded-For "";
```

An empty value means nginx omits the header entirely, so uvicorn has nothing to
rewrite the peer from and the app's peer stays `127.0.0.1`. `CF-Connecting-IP`
passes through untouched. Then, in `/opt/falconeye/.env`:

```
TRUSTED_PROXY_CIDRS=127.0.0.1/32
```

Now the peer is a trusted proxy, the authoritative header is believed, and the
result is correct regardless of what `cloudflared` does to `X-Forwarded-For`.

**Both halves are required.** Clearing `X-Forwarded-For` without setting
`TRUSTED_PROXY_CIDRS` makes every request key on `127.0.0.1`: one shared
rate-limit bucket for the entire internet. This is the one topology where that
variable is the right answer, and it is why it exists.

Verify after deploying, from two different networks, that the rate-limit
counters move independently.

## Deploying without Cloudflare

The stock config assumes Cloudflare is in front. Three separate things encode
that assumption, and they have to be dealt with together, because fixing one
and not the others is worse than fixing none.

**1. The origin allow list.** `nginx/falconeye.conf` includes
`snippets/cloudflare-origin-allow.conf`, which allows Cloudflare's published
edge ranges and denies everything else. On a deployment that is not behind
Cloudflare this denies every request, because no client ever matches. Either
delete the `include` line, or replace the snippet's contents with the CIDRs of
whatever actually fronts the origin.

**2. TLS.** `ssl_certificate` points at `/etc/ssl/falconeye/origin.crt`, a
Cloudflare Origin CA certificate. It is only trusted by Cloudflare, so a browser
reaching the origin directly will reject it. Issue a publicly trusted
certificate (certbot) and repoint both `ssl_certificate` and
`ssl_certificate_key`.

**3. The real client IP, which is what every rate limit keys on.** This is the
one that fails silently, so read the next section rather than skipping it.

### Rate limiting off Cloudflare: the failure to avoid

Every per-IP limit, including the daily caps on the paid LLM endpoints, keys on
`get_client_ip()` in `app/utils/client_ip.py`. It returns the app's TCP peer
address unless that peer is a trusted proxy that also sent `CF-Connecting-IP`.

Put a load balancer in front without adjusting nginx and the peer the app sees
becomes **the load balancer**, identically for every visitor on the internet.
Limits do not break loudly. They collapse into a single shared bucket: the
first ten callers that day consume the global allowance and everyone else gets
429s. Nothing in the UI says so.

**Setting `TRUSTED_PROXY_CIDRS` to the load balancer's CIDR does not fix this
on its own, and makes it harder to spot.** That variable only decides whose
`CF-Connecting-IP` header to believe. If nothing is setting that header, the
code still falls through to the peer address, so you keep the single bucket and
additionally suppress the one warning that would have told you
(`CF-Connecting-IP arrived from untrusted peer ...`). Leave it unset unless the
recipe below says otherwise.

The fix belongs in nginx: make `$remote_addr` the real client before it is
forwarded, using the realip module.

### Worked example: AWS Application Load Balancer

Placeholder CIDRs. Substitute the subnets your ALB's network interfaces live in
(the VPC subnets you attached it to), not the ALB's DNS name.

In the `server` block of `/etc/nginx/sites-available/falconeye`, replace the
Cloudflare include with:

```
# Trust X-Forwarded-For only from the ALB's own subnets, and resolve the chain
# back to the originating client. After this, $remote_addr IS the real visitor.
set_real_ip_from 10.0.0.0/24;      # ALB subnet A
set_real_ip_from 10.0.1.0/24;      # ALB subnet B
real_ip_header    X-Forwarded-For;
real_ip_recursive on;
```

Leave the rest of the `location /` block exactly as shipped. With `realip`
active, `$proxy_add_x_forwarded_for` already carries the real client, uvicorn
takes the right-most untrusted entry from it, and the app's peer becomes the
visitor. Rate limits then key correctly with no application change and
**`TRUSTED_PROXY_CIDRS` stays unset**. The default `combined` log format also
starts logging real visitor IPs, which is why the GoAccess format is not needed
here.

**In one sentence: behind an ALB, setting only `TRUSTED_PROXY_CIDRS` collapses
rate limiting because that variable only decides whose `CF-Connecting-IP` to
believe, and an ALB does not send that header, so every request still falls
through to the peer address, which is the load balancer, which is the same for
everyone.** Verified against the pinned uvicorn 0.29.0: with
`TRUSTED_PROXY_CIDRS` set to the ALB subnet and no `realip`, `get_client_ip()`
returns the ALB's address for every caller. The `set_real_ip_from` block above
is the fix; the variable is not.

Two traps specific to this layout:

- **Do not pair `realip` with `allow`/`deny` on the ALB CIDRs.** The realip
  module runs in the post-read phase, before the access phase, so by the time
  `allow`/`deny` is evaluated `$remote_addr` is already the visitor's address
  and an ALB-CIDR allow list denies everyone. Restrict the origin with the EC2
  security group instead: accept 443 only from the ALB's security group. That is
  the equivalent of the Cloudflare origin lock, and it is enforced before the
  packet reaches nginx.
- **The ALB must be the only thing that can reach the instance.** `realip`
  trusts `X-Forwarded-For` from those subnets. If a caller can hit the instance
  directly from inside them, it can name any client IP it likes.

### `--forwarded-allow-ips` off Cloudflare

`falconeye.service` pins `--forwarded-allow-ips 127.0.0.1` on the gunicorn
ExecStart line. **In the layout above it does not change.** That flag is about
gunicorn's immediate TCP peer, which is still the local nginx on the loopback
address no matter what sits upstream of nginx.

It only changes if you drop the local nginx and point the load balancer straight
at gunicorn. Then list the proxy's own addresses:

```
--forwarded-allow-ips 10.0.0.17,10.0.1.23
```

Two constraints on that value, both verified against the pinned uvicorn 0.29.0:

- **It matches literal addresses, not CIDRs.** `trusted_hosts` is a set of
  strings compared with `in`, so `10.0.0.0/24` matches nothing and silently
  leaves the peer as the proxy. An ALB's node addresses are not stable, which is
  a good reason to keep nginx on the instance.
- **Never `*`.** With `*` uvicorn stops scanning from the right and takes the
  **left-most** `X-Forwarded-For` entry, which is entirely caller-supplied. The
  peer address becomes attacker-chosen, and with it every rate-limit key.
  `tests/unit/test_client_ip.py` fails if the flag is removed or set to `*`.

### When `TRUSTED_PROXY_CIDRS` is the right tool

Exactly one condition: the fronting proxy sets `CF-Connecting-IP` itself, **and**
the app sees that proxy's own address as its peer. Both halves, or it does
nothing useful.

The Cloudflare Tunnel recipe above is the worked example, and is the case the
variable was added for: `cloudflared` supplies the header, nginx is configured
so the peer stays `127.0.0.1`, and `TRUSTED_PROXY_CIDRS=127.0.0.1/32` is what
connects the two.

It is the wrong tool everywhere else. Behind a plain load balancer that does not
send `CF-Connecting-IP`, setting it changes no behaviour and suppresses the one
warning that would have flagged the problem:

```
CF-Connecting-IP arrived from untrusted peer ... and was ignored;
rate limits are keying on the peer address.
```

Seeing that in the journal means the client IP is not being resolved correctly.
Fix the proxy configuration; do not silence it.

Every CIDR listed in the variable is a network permitted to name any IP as the
rate-limited client, so keep it as narrow as possible and never put `0.0.0.0/0`
in it.

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
- nginx config exists in **two** places, and as of v3.32.2 it is more than one
  file in each. Repo: `nginx/falconeye.conf` plus `nginx/snippets/*.conf`.
  Live: `/etc/nginx/sites-available/falconeye` plus `/etc/nginx/snippets/*.conf`
  (and optionally `/etc/nginx/conf.d/goaccess-logformat.conf`). Patch both
  sides, copy snippets **before** the vhost that includes them, then
  `sudo nginx -t && sudo systemctl reload nginx`. Security headers and the
  Cloudflare allow list now live in the snippets, not the vhost.
- Verify origin CSP (bypassing the Cloudflare challenge):
  `curl -skI --resolve falconeye.osintph.info:443:127.0.0.1
  https://falconeye.osintph.info/`.
- No `node` on Mac or VPS; syntax-check `app.js` with macOS JavaScriptCore:
  `osascript -l JavaScript` + `new Function(<source>)` (parses, doesn't execute).
