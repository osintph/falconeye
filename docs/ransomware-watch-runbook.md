# Ransomware Watch — ops runbook

v3.16.0 adds a Ransomware Watch tab. Per Part 1 of its brief, the tab never
calls ransomware.live or RansomLook directly — a scheduled collector writes
to a local SQLite database, and the tab (`app/ransomware/routes.py`) only
ever reads that database. This doc covers the three pieces that are
deliberately **not** in the git tree: the systemd unit/timer, the SQLite
database, and the watchlist config.

## Why these stay outside the tracked tree

Same convention as `FALCONEYE_DB` (the main app database) and the Telegram
session file: runtime state and host-specific service config don't belong in
a portable app checkout. `app/collectors/ransomware_collect.py` (the
collector script itself) **is** tracked — only its scheduling unit and the
data/config it produces/reads are not.

## Paths on the VPS

| What | Path | Tracked? |
|---|---|---|
| Collector script | `/opt/falconeye/app_src/app/collectors/ransomware_collect.py` | Yes (repo) |
| Database | `/opt/falconeye/data/ransomware.db` | No |
| Watchlist config | `/opt/falconeye/private/ransomware_watchlist.txt` | No |
| systemd service | `/etc/systemd/system/ransomware-collect.service` | No |
| systemd timer | `/etc/systemd/system/ransomware-collect.timer` | No |

`RANSOMWARE_LIVE_API_KEY` lives in `/opt/falconeye/.env` (already present,
loaded via the service's `EnvironmentFile=`). `RANSOMWARE_DB` and
`RANSOMWARE_WATCHLIST_PATH` default to the paths above in `app/config.py` if
not overridden.

## systemd unit (reference copy — the live files are deployed directly, not via git)

`/etc/systemd/system/ransomware-collect.service`:

```ini
[Unit]
Description=FalconEye Ransomware Watch collector
After=network.target

[Service]
Type=oneshot
User=ubuntu
Group=ubuntu
WorkingDirectory=/opt/falconeye/app_src
EnvironmentFile=/opt/falconeye/.env
Environment=RANSOMWARE_DB=/opt/falconeye/data/ransomware.db
Environment=RANSOMWARE_WATCHLIST_PATH=/opt/falconeye/private/ransomware_watchlist.txt
ExecStart=/opt/falconeye/venv/bin/python -m app.collectors.ransomware_collect
```

`/etc/systemd/system/ransomware-collect.timer`:

```ini
[Unit]
Description=Run the FalconEye Ransomware Watch collector every 30 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=30min
RandomizedDelaySec=5min
Persistent=true

[Install]
WantedBy=timers.target
```

`RandomizedDelaySec` is the jitter Part 4 of the brief asks for. The timer
fires roughly every 30 minutes; the script itself decides internally whether
the ~6-hourly mirror-health phase is also due this run (it checks
`collector_runs` for the last `mirror_health` row and skips if under 6h old)
— there's only one timer, not one per cadence.

Install/enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ransomware-collect.timer
```

## Watchlist config format

Two tiers, in `[tier1]` / `[tier2]` sections (case-insensitive header,
brackets required). `#` starts a comment, blank lines are ignored. A term
appearing before either header is skipped with a warning, not guessed into a
tier. Terms shorter than 2 characters are dropped before any outbound call
is made (RansomLook's `/api/search` requires `q` to be at least 2
characters).

- **Tier 1** — high-precision proper nouns only. Meant to alert (the actual
  alert wiring into the daily operator report is a follow-up, not part of
  this release — see below). Prefer the full legal/brand name over a bare
  word that collides with something unrelated: `BDO Unibank`, not `bdo` —
  BDO is also a large global accounting network that shows up in unrelated
  breach reporting, so the bare term throws confident false positives.
- **Tier 2** — broad geographic terms. Logged to `watchlist_hits` and shown
  in the tab for manual review, but never alerts — these terms are
  deliberately noisy (a hit for `philippines` or `.ph` can be any unrelated
  org whose site happens to use that TLD or word). Confirmed live before
  including `.ph`: `GET /api/search?q=.ph` does match on domain fragments
  (`FAST.COM.PH`, `jumpsolutions.ph`, etc.), ~47 posts / 14 leaks / 11 notes
  at time of writing — contained enough to be worth the noise. Re-check this
  if RansomLook's search behavior ever changes.

```
# Ransomware Watch watchlist — RansomLook /api/search terms
# [tier1] / [tier2] section headers, '#' comments and blank lines ignored.
# Terms under 2 characters are skipped before any outbound call.
# Tier 1 = high-precision named orgs (alerting). Tier 2 = broad geographic
# terms, logged for review only, never alerts.

[tier1]
# Government and health — where actual PH incidents have landed
PhilHealth
Department of Health Philippines
DOH Philippines
DepEd
Social Security System Philippines
GSIS
Philippine Statistics Authority
COMELEC
Bureau of Internal Revenue
Land Transportation Office

# Financial
BPI
Bank of the Philippine Islands
BDO Unibank
Landbank
UnionBank
RCBC
Metrobank
Security Bank
China Bank
GCash
PayMaya

# Conglomerates, telecoms, infrastructure, aviation
Ayala
SM Investments
San Miguel Corporation
PLDT
Globe Telecom
Meralco
ICTSI
Aboitiz
JG Summit
Petron
Converge ICT
Cebu Pacific
Philippine Airlines
Jollibee

[tier2]
philippines
pilipinas
manila
cebu
davao
makati
.ph
```

Note what's deliberately absent: bare `maya` (too common a word to be a
usable search term) and bare `bdo`/`bank` style single-word financial terms
(collision risk, see above).

Hits land in the `watchlist_hits` table in `ransomware.db` with a `tier`
column (1, 2, or `NULL` for hits recorded before tiering existed — the
column was added via an additive `ALTER TABLE`, so pre-existing rows aren't
retroactively classified). Same shape as the other rate-limit/event tables
the daily operator report already reads from `falconeye.db` — wiring
tier-1-only alerts into that report is a follow-up, not part of this
release.

## Database

SQLite, 6 tables (`victims`, `groups`, `mirrors`, `press`, `watchlist_hits`,
`collector_runs`) — see `app/ransomware/store.py` for schema. Self-creates on
first collector run or first app request via `init_tables()` (same
self-initializing-table convention as every other FalconEye router).

**Reset the database** (wipes all collected data; the tab falls back to its
cold-start state until the next collector run):

```bash
sudo systemctl stop ransomware-collect.timer
sudo rm -f /opt/falconeye/data/ransomware.db
sudo systemctl start ransomware-collect.timer
```

(Stopping the timer isn't strictly required — the collector recreates the
schema on its next run either way — but avoids a race with an in-flight run.)

**Trigger a manual collection** (doesn't wait for the timer):

```bash
sudo systemctl start ransomware-collect.service
journalctl -u ransomware-collect.service -n 50 --no-pager
```

The first line of output on every run is the PRO key validation result
(`PRO key validation PASS` or `FAIL`) — check this first if panels look
empty or stale. The key itself is never printed, logged, or returned in any
API response under any code path (see `tests/test_ransomware_collect.py`).

## Credential handling (why `mirrors` never has a URL column)

RansomLook's `/api/health/{name}` returns the raw mirror URL, and for some
groups that URL embeds live leak-site credentials
(`scheme://user:pass@host`). The collector hashes the slug immediately on
receipt (`store.hash_mirror_slug`) and never lets the raw string reach a
variable that outlives that line — not the database, not a log line, not an
exception message. `store.upsert_mirror()` independently refuses to write
anything that still matches a credential-bearing URI pattern, as a backstop
against a future call site skipping the hash. The UI shows positional labels
only ("Mirror 1", "Mirror 2", …), never a URL or hostname.

## Permalink

Every victim entry links out to `https://www.ransomware.live/id/...` —
ransomware.live's own hosted page for that claim, populated from PRO's
`permalink` field only. Never from `post_url`/`claim_url`/`url`, which are
the raw leak-site address (confirmed live: `post_url` for a real victim was
an `.onion` link). `store.safe_permalink()` enforces an https + hostname
allowlist (`ransomware.live`/`www.ransomware.live`) at write time as a
backstop, and `app.js`'s `rwSafePermalink()` re-checks the same thing
client-side before rendering a link — belt and suspenders on a field that,
if it ever pointed at a leak site instead, would be exactly the "become the
thing that republishes" risk Part 6 exists to prevent. v2 fallback records
have no `permalink` field at all, so a victim ingested via the v2 fallback
simply has no permalink until PRO recovers and re-supplies one.

## first_seen_via (diagnostic column, no UI surface yet)

`victims.first_seen_via` records the *trigger* that caused a row to first
exist, not the endpoint used — `'collector'` for anything the scheduled
collector ingests (including its own per-country queries), reserved values
`'country_filter'`/`'search'` for a future user-triggered on-demand lookup.
Set once on INSERT, deliberately excluded from the `ON CONFLICT DO UPDATE`
column list so it's never overwritten on a later re-ingestion of the same
victim. Existing rows from before this column existed are `NULL` — that's
the honest answer ("predates this column"), not backfilled, since a v3.16.0
review found no reliable way to reconstruct which of the two collector
ingestion paths (`/victims/recent` vs `/victims/?country=`) first surfaced
each of the already-live 1,189 rows.

## country_coverage (forward-compat table, no consumer yet)

Created empty in v3.16.0 even though nothing reads it until a later release
— the point is avoiding a schema migration against a much larger `victims`
table by then. On every collector run, `run_victims_phase()` stamps one row
per standing-scope country (`store.SEA_COUNTRIES`: PH, SG, MY, ID, TH, VN,
HK, TW) with the API's own all-time `count` for that country filter,
`last_fetched`, and `source='collector'`. A failed per-country call leaves
the existing row untouched rather than overwriting a good prior count with a
false "just checked, zero" — `victim_count`/`last_fetched` only update when
the upstream call actually succeeds that run.

## Expected behavior: some groups have hundreds of mirror entries

Observed live during development: `lockbit3` alone returned ~640 distinct
entries from `/api/health/lockbit3` — RansomLook keeps a long historical
record of every mirror/proxy URL it has ever seen for a group, not just the
currently-live ones, and long-established groups accumulate a lot of dead
history. This is expected, not a bug. `store.mirrors_by_group()` ranks by
`uptime_30d` and shows at most 8 per group, with a "+N more mirror(s) with
historical/offline entries, not shown" note for the rest — if a group's
Leak Site Health card looks capped, that's the cap working as intended, not
missing data.
