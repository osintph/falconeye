# IMPLEMENTATION_NOTES.md

Operational details for building and deploying FalconEye v0.1. Read after `SPEC.md`. This file is for Claude Code and the operator. It carries the concrete decisions, verified URLs, and config templates that the spec deliberately abstracts.

## 1. Target environment

- **VPS:** OVH VPS-1 2027 tier (2 vCPU, 4 GB RAM, 40 GB SSD NVMe, Ubuntu 24.04 LTS)
- **Hostname:** to be set by operator
- **Subdomain:** `falconeye.osintph.info`
- **DNS:** Cloudflare, DNS-only (grey cloud), not proxied
- **SSH:** key-only, port already hardened by operator
- **Firewall:** ufw allowing inbound 22 (or operator-configured port), 80, 443
- **TLS:** Let's Encrypt via certbot with the nginx plugin

## 2. Filesystem layout

```
/opt/falconeye/
├── src/                  # Python source (git clone of osintph/falconeye)
├── public/               # SSG output directory served by nginx
│   ├── index.html
│   ├── feed.xml
│   ├── feed.json
│   ├── manifest.json
│   └── static/           # CSS, no JS framework in v0.1
├── db/
│   └── falconeye.db      # SQLite WAL-mode database
├── venv/                 # Python virtual environment
├── logs/                 # Worker stdout/stderr (also goes to journald)
└── config/
    ├── brand_strings.yaml
    └── cpe_inventory.yaml
```

All paths owned by the `falconeye` system user (created during VPS prep). nginx reads `public/` but has no write access anywhere.

## 3. Service user

Created with:

```bash
sudo useradd --system --create-home --home-dir /opt/falconeye --shell /usr/sbin/nologin falconeye
```

- System UID (under 1000), no login shell, home is `/opt/falconeye`.
- All ingest workers run as this user via `systemd --user` or system unit with `User=falconeye`.
- No sudo, no group memberships beyond its own primary group.

## 4. Python environment

```bash
sudo bash /opt/falconeye/src/deploy/install-venv.sh
```

Dependencies (target minimum set):

- `requests` (for sources requiring auth headers like URLhaus)
- `pyyaml` (for brand and CPE inventory configs)
- `jinja2` (SSG)
- `python-dateutil` (timezone-aware parsing)
- `tldextract` (Public Suffix List for TLD match)
- `feedgen` (RSS/JSON Feed generation)

Avoid: ORMs (SQLAlchemy etc.). Use the stdlib `sqlite3` module directly. Schema is small and explicit.

## 5. systemd units

Two units per ingest source: a `.service` unit defining the worker command and a `.timer` unit firing it on schedule.

Example for the URLhaus ingest worker at `/etc/systemd/system/falconeye-urlhaus.service`:

```ini
[Unit]
Description=FalconEye URLhaus ingest worker
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=falconeye
Group=falconeye
WorkingDirectory=/opt/falconeye/src
EnvironmentFile=/opt/falconeye/config/secrets.env
ExecStart=/opt/falconeye/venv/bin/python -m falconeye.ingest.urlhaus
StandardOutput=journal
StandardError=journal
SyslogIdentifier=falconeye-urlhaus

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/falconeye/db /opt/falconeye/logs
```

Paired timer at `/etc/systemd/system/falconeye-urlhaus.timer`:

```ini
[Unit]
Description=Run FalconEye URLhaus ingest every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
RandomizedDelaySec=30s
Persistent=true

[Install]
WantedBy=timers.target
```

The SSG runs as a separate unit triggered after any ingest worker completes (use `OnSuccess=` in the service units, or a separate timer that fires every 5 minutes and only regenerates if the corpus changed since last run).

Cadences by source:

| Source | Timer interval |
|---|---|
| URLhaus | 15 minutes |
| CISA KEV | 6 hours |
| NVD CVE | 30 minutes |
| APNIC delegated | 24 hours |
| SSG | 5 minutes (or on-change) |

## 6. Secrets handling

A single `/opt/falconeye/config/secrets.env` file owned by `falconeye` with `chmod 600` holds all four required variables:

```
URLHAUS_AUTH_KEY=<key from auth.abuse.ch>
NVD_API_KEY=<key from nvd.nist.gov/developers/request-an-api-key>
FALCONEYE_DB_PATH=/opt/falconeye/db/falconeye.db
FALCONEYE_OUTPUT_DIR=/opt/falconeye/public
```

Bootstrap it from the committed example:

```bash
sudo -u falconeye cp /opt/falconeye/src/config/secrets.env.example /opt/falconeye/config/secrets.env
sudo -u falconeye chmod 600 /opt/falconeye/config/secrets.env
sudo -u falconeye vi /opt/falconeye/config/secrets.env   # fill in the two API keys
```

The `EnvironmentFile=` directive in each systemd unit reads this file. The file itself is `.gitignore`d — only `secrets.env.example` is committed.

## 7. Upstream source URLs

Claude Code: verify these are current at implementation time by hitting the landing page rather than assuming the URL from this file. Sources occasionally change paths and we want correctness over speed.

### URLhaus

- Landing: https://urlhaus.abuse.ch/
- API base: https://urlhaus-api.abuse.ch/v1/
- Auth-Key obtained at: https://auth.abuse.ch/
- Bulk downloads: https://urlhaus.abuse.ch/downloads/ (verify which still work without auth)

### CISA KEV

- Landing: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- JSON (canonical): typically at `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, verify at landing page
- GitHub mirror: https://github.com/cisagov/kev-data (CC0, easier to ETag-poll)

### NVD CVE 2.0

- Landing: https://nvd.nist.gov/developers/vulnerabilities
- API base: https://services.nvd.nist.gov/rest/json/cves/2.0
- API key request: https://nvd.nist.gov/developers/request-an-api-key
- Rate limits: documented at the developers page (with key: 50 requests per 30 seconds rolling window; without key: 5 per 30 seconds. Verify current at implementation time)

### APNIC delegated stats

- Landing: https://www.apnic.net/about-apnic/corporate-documents/documents/resource-guidelines/rir-statistics-exchange-format/
- Files: ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest and delegated-apnic-extended-latest
- Schema: documented at the landing page

## 8. nginx vhost (two-phase deploy)

The nginx deploy is split into two phases to avoid the chicken-and-egg problem where `nginx -t` fails because TLS certificates do not exist yet.

**Phase 1 — HTTP vhost** (`deploy/install-nginx.sh`):

Installs `deploy/nginx/falconeye.conf` (HTTP-only, port 80) and verifies `nginx -t` passes. The dashboard is immediately reachable on port 80. `text/html` is omitted from `gzip_types` because nginx handles it by default; listing it is redundant.

```bash
sudo bash /opt/falconeye/src/deploy/install-nginx.sh
```

**Phase 2 — TLS certificate** (`deploy/install-tls.sh`):

Runs `certbot --nginx` which adds the HTTPS server block and HSTS header automatically. Requires a DNS A record pointing to the VPS.

```bash
sudo bash /opt/falconeye/src/deploy/install-tls.sh
```

Both scripts source `deploy/lib/preflight.sh` and will fail with clear remediation messages if any prerequisite is missing.

## 9. Healthcheck

The SSG writes `/opt/falconeye/public/healthz.json` after each successful regeneration. Format:

```json
{
  "status": "ok",
  "manifest_version": "2026.173.04",
  "last_regeneration_utc": "2026-06-22T01:39:14Z",
  "sources": {
    "urlhaus":  {"last_success_utc": "...", "row_count": 1234, "age_seconds": 421},
    "kev":      {"last_success_utc": "...", "row_count": 1456, "age_seconds": 7301},
    "nvd":      {"last_success_utc": "...", "row_count": 285341, "age_seconds": 1102},
    "apnic":    {"last_success_utc": "...", "row_count": 4218, "age_seconds": 14401}
  }
}
```

Future Nagios checks (operator already runs the Nagios stack) hit `/healthz` and alert on stale `age_seconds` per source.

## 10. License attribution per source

The dashboard, RSS, JSON feed, and manifest each carry an attributions block. Per record, the source name is cited inline. Bulk attribution text at the dashboard footer:

> Threat intelligence sourced from abuse.ch URLhaus (community use), CISA Known Exploited Vulnerabilities Catalog (US Government public domain), National Vulnerability Database (US Government public domain), and APNIC delegated statistics (APNIC member services). FalconEye is independent of these sources and republishes their data for PH community defense purposes under fair use principles. See the GitHub repository for full attribution details.

## 11. Known failure modes Claude Code should handle gracefully

- **crt.sh-style 502 outages.** abuse.ch is rarely down but the project should treat any 4xx/5xx as a logged failure for that cycle without crashing the worker.
- **NVD rate limit (429).** Back off and retry per source's documented policy. Without an API key, NVD limits are very tight.
- **APNIC file format quirks.** The delegated-apnic-latest file has a header section (lines starting with `2|` etc.) and the actual records. Worker must skip header lines and handle the `*|*` summary lines.
- **URLhaus tags can contain commas inside quoted strings.** Use a proper CSV parser, not naive `split(',')`.
- **Network partitions during cycle.** Use `OnFailure=` systemd directive to log and move on. No retries within a single cycle, next cycle handles it.

## 12. v0.1 acceptance checklist (operator-facing)

```
[ ] Repo cloned to /opt/falconeye/src
[ ] deploy/install-venv.sh run successfully (venv at /opt/falconeye/venv)
[ ] config/secrets.env populated with all four keys:
    URLHAUS_AUTH_KEY, NVD_API_KEY, FALCONEYE_DB_PATH, FALCONEYE_OUTPUT_DIR
[ ] config/brand_strings.yaml committed with initial PH banks, telcos, government agencies
[ ] config/cpe_inventory.yaml committed with initial PH-relevant CPE entries
[ ] All four ingest workers tested manually: sudo bash scripts/run.sh urlhaus (etc.)
[ ] SSG generates index.html, feed.xml, feed.json, manifest.json, healthz.json
[ ] systemd units installed and enabled (4 service + 4 timer + 1 SSG service + 1 SSG timer)
[ ] deploy/install-nginx.sh run — nginx serves HTTP on port 80
[ ] deploy/install-tls.sh run — certbot issues TLS certificate, HTTPS active
[ ] DNS A record points to VPS, dig resolves
[ ] curl https://falconeye.osintph.info/ returns 200
[ ] curl https://falconeye.osintph.info/feed.xml returns valid RSS
[ ] curl https://falconeye.osintph.info/healthz returns JSON with all sources green
[ ] 48-hour soak test: all timers fire correctly, no journald errors
```

## 13. Build sequence for Claude Code

Recommended order. Do not parallelize across sources; finish one ingest worker end-to-end before starting the next.

1. Repo scaffolding (`pyproject.toml`, `requirements.txt`, `README` skeleton already exists, `falconeye/` package, test config)
2. SQLite schema and migration script
3. URLhaus ingest worker, tested against live endpoint
4. CISA KEV ingest worker, tested against live endpoint
5. NVD CVE ingest worker (longer because of incremental sync), tested against live endpoint
6. APNIC delegated worker, tested against live file
7. PH sieve module (ASN trie, TLD, brand, CPE)
8. Apply sieve to existing corpus, verify match counts
9. Jinja2 templates and SSG
10. systemd unit files
11. nginx vhost
12. Healthz writer
13. End-to-end test: stop all timers, run a full cycle by hand, verify outputs
14. Re-enable timers, soak for 48 hours
15. Tag v0.1.0 release

On the VPS, the deploy sequence wrapping steps 10–13:
- `deploy/install-venv.sh` — creates Python venv (run before install-systemd.sh)
- `deploy/install-nginx.sh` — Phase 1 HTTP vhost
- `deploy/install-tls.sh` — Phase 2 TLS certificate via certbot
- `deploy/install-systemd.sh` — systemd units (sources preflight.sh, fails fast if venv or secrets missing)
- `scripts/run.sh all` — manual full cycle (urlhaus → kev → nvd → apnic → sieve → ssg)
- `scripts/run.sh <worker>` — manual single-worker run

All install scripts source `deploy/lib/preflight.sh` and fail with clear remediation messages if prerequisites are missing. `scripts/run.sh` must be run as root; it sources `secrets.env` automatically.

After each step Claude Code stops and shows the operator the test output before proceeding.
