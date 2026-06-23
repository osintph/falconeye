# IMPLEMENTATION_NOTES.md

Operational details for building and deploying FalconEye v0.2. Read after `SPEC.md`. This file is for Claude Code and the operator. It carries the concrete decisions, verified URLs, and config templates that the spec deliberately abstracts.

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
│   ├── falconeye/
│   │   ├── ingest/       # urlhaus.py, kev.py, nvd.py, apnic.py, shodan_enrich.py
│   │   ├── ssg/          # __init__.py, templates/
│   │   ├── cluster.py    # campaign clustering
│   │   ├── digest.py     # Ghost daily digest publisher
│   │   ├── stix.py       # STIX 2.1 serializers
│   │   ├── sieve.py
│   │   ├── db.py
│   │   └── config.py
│   ├── config/
│   │   ├── asn_operators.yaml     # 20 PH ASN operator names
│   │   ├── action_templates.yaml  # defender guidance per URLhaus tag
│   │   ├── brand_strings.yaml
│   │   └── cpe_inventory.yaml
│   ├── deploy/
│   │   ├── systemd/      # all .service and .timer units
│   │   └── nginx/        # falconeye.conf
│   └── scripts/
│       └── run.sh
├── public/               # SSG output directory served by nginx
│   ├── index.html
│   ├── feed.xml          # campaign-primary RSS
│   ├── feed.json         # campaign-primary JSON Feed
│   ├── feed-iocs.xml     # raw IOC+CVE RSS
│   ├── feed-iocs.json    # raw IOC+CVE JSON Feed
│   ├── manifest.json
│   ├── healthz.json
│   ├── robots.txt
│   ├── sitemap.xml
│   ├── asn/              # per-ASN pages
│   ├── campaign/         # per-campaign pages
│   ├── api/v1/taxii/     # STIX 2.1 / TAXII-compatible static API
│   └── static/           # CSS
├── db/
│   └── falconeye.db      # SQLite WAL-mode database
├── venv/                 # Python virtual environment
├── logs/                 # Worker stdout/stderr (also goes to journald)
└── config/
    └── secrets.env       # not committed, see secrets.env.example
```

All paths owned by the `falconeye` system user. nginx reads `public/` but has no write access anywhere.

## 3. Service user

Created with:

```bash
sudo useradd --system --create-home --home-dir /opt/falconeye --shell /usr/sbin/nologin falconeye
```

System UID, no login shell, home is `/opt/falconeye`. All ingest workers run as this user. No sudo, no group memberships beyond its own primary group.

## 4. Python environment

```bash
sudo bash /opt/falconeye/src/deploy/install-venv.sh
```

Dependencies:

- `requests` — HTTP with retry semantics (URLhaus auth header, Shodan backoff)
- `pyyaml` — config files (brand strings, CPE inventory, ASN operators, action templates)
- `jinja2` — SSG templates
- `python-dateutil` — timezone-aware timestamp parsing
- `tldextract` — Public Suffix List for TLD match and effective grouping domain
- `feedgen` — RSS 2.0 / JSON Feed 1.1 generation
- `PyJWT>=2.8` — Ghost Admin API JWT authentication

No ORM. Schema is small, explicit, and managed with `IF NOT EXISTS` DDL in `falconeye/db.py`.

## 5. systemd units

Two units per ingest source: a `.service` unit defining the worker command and a `.timer` unit firing it on schedule. All units live under `deploy/systemd/`.

```ini
# Example: deploy/systemd/falconeye-urlhaus.service
[Unit]
Description=FalconEye URLhaus ingest worker
After=network-online.target
Wants=network-online.target
OnSuccess=falconeye-ssg.service

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

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/falconeye/db /opt/falconeye/logs
```

Cadences:

| Unit | Cadence |
|---|---|
| `falconeye-urlhaus` | 15 minutes |
| `falconeye-kev` | 6 hours |
| `falconeye-nvd` | 30 minutes |
| `falconeye-apnic` | 24 hours |
| `falconeye-ssg` | 5 minutes (fallback timer; also triggered via `OnSuccess=` chain) |
| `falconeye-shodan` | 1 hour |
| `falconeye-digest` | Daily at 22:00 UTC (06:00 PHT) via `OnCalendar=` |

The SSG timer is a fallback — it fires if none of the ingest workers triggered `OnSuccess=falconeye-ssg.service` within the 5-minute window. Clustering and Shodan enrichment are not in the `OnSuccess` chain; their own timers run them independently.

## 6. Secrets handling

A single `/opt/falconeye/config/secrets.env` owned by `falconeye` with `chmod 600`:

```bash
URLHAUS_AUTH_KEY=<key from auth.abuse.ch>
NVD_API_KEY=<key from nvd.nist.gov/developers/request-an-api-key>
FALCONEYE_DB_PATH=/opt/falconeye/db/falconeye.db
FALCONEYE_OUTPUT_DIR=/opt/falconeye/public

# Ghost digest (optional — digest module is a no-op if these are unset)
GHOST_API_URL=https://blog.osintph.info
GHOST_ADMIN_KEY=<id_hex:secret_hex from Ghost Admin > Settings > Integrations>
GHOST_AUTHOR_SLUG=sigmund
FALCONEYE_DIGEST_MODE=draft   # or 'published' to auto-publish
```

The `EnvironmentFile=` directive in each unit reads this file. The file is `.gitignore`d — only `config/secrets.env.example` is committed.

Ghost integration is optional: if `GHOST_API_URL`, `GHOST_ADMIN_KEY`, or `GHOST_AUTHOR_SLUG` are absent, `run_digest()` logs and returns 0 without error.

## 7. Upstream source URLs

Verify these are current at implementation time by hitting the landing page.

### URLhaus

- Landing: https://urlhaus.abuse.ch/
- API base: https://urlhaus-api.abuse.ch/v1/
- Auth-Key obtained at: https://auth.abuse.ch/

### CISA KEV

- JSON: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- GitHub mirror (CC0): https://github.com/cisagov/kev-data

### NVD CVE 2.0

- API base: https://services.nvd.nist.gov/rest/json/cves/2.0
- Rate limits: 50 requests/30s with key; 5/30s without. Incremental pulls via `lastModStartDate`/`lastModEndDate`.

### APNIC delegated stats

- File: `https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest`

### Shodan InternetDB

- Base: `https://internetdb.shodan.io/<ip>` (keyless, no auth required)
- Returns: `ports`, `cpes`, `hostnames`, `tags`, `vulns` JSON fields
- 404 = no data for IP (not an error); 429 = rate limited (see backoff below)
- Backoff sequence on 429: 5s → 10s → 20s → 40s → 60s → bail and log WARNING
- Daily cap: 10,000 requests per UTC day, enforced per-worker-run in `shodan_enrich.py`
- Staleness: skip IPs enriched within the last 6 hours

## 8. Campaign clustering details

`falconeye/cluster.py` runs three bucket strategies against the `iocs` and `sieve_matches` tables:

**Domain clustering** (all-time): groups by `effective_grouping_domain()`. For PSL hosting-platform domains (`workers`, `pages`, `github`, `netlify`, `vercel`, `glitch`), the key is `{account}.{domain}.{suffix}` using the last subdomain component — this prevents `chris-smart.workers.dev` and `victim.workers.dev` from merging into the same campaign.

**ASN+tag clustering** (14-day rolling): groups by `(asn, tag)` where `asn` may be NULL for IPs not cross-referenced to a specific ASN in the APNIC data.

**/24 prefix clustering** (14-day rolling): groups by `/24` IPv4 prefix derived from the IP address.

Minimum cluster size: 3 IOCs. Slugs are stable: `dom-`, `ast-`, or `pfx-` prefix + normalized cluster key, max 80 chars. The `run_clustering()` function upserts by slug using `ON CONFLICT(slug) DO UPDATE` — disappeared slugs get `status='expired'` and `expired_at` set.

`config/asn_operators.yaml` maps 20 PH ASN numbers to operator names for display. `config/action_templates.yaml` maps URLhaus tags to defender guidance blocks rendered on campaign pages.

## 9. STIX 2.1 output

`falconeye/stix.py` produces STIX 2.1 objects hand-written as dicts (no STIX library dependency).

All object IDs are UUIDv5: `uuid.uuid5(FALCONEYE_NS, f"{object_type}:{key}")` where `FALCONEYE_NS = uuid.UUID("c40e7b5b-eac2-471d-a05f-2bb8e2be4b39")`. This guarantees the same IOC value always produces the same STIX indicator ID across pipeline runs.

STIX threat-type mapping (URLhaus `threat_type` → STIX `threat_types` label):

| URLhaus tag | STIX label |
|---|---|
| malware_download, malware, malware_distribution, dropper, exploit | malicious-activity |
| c2, botnet_cc | command-and-control |
| phishing, phishing_kit | phishing |
| unknown | malicious-activity (+ WARNING log) |

The TAXII-compatible static layout:

```
api/v1/taxii/
├── index.json                          # TAXII APIRoot discovery
├── collections/
│   └── index.json                      # Collections manifest
│   └── ph-iocs/
│       └── objects.json                # STIX Bundle with all indicators
│   └── ph-campaigns/
│       └── objects.json                # STIX Bundle with campaigns + relationships
│   └── ph-cves/
│       └── objects.json                # STIX Bundle with Vulnerability objects
```

nginx serves `api/v1/taxii/` with `Content-Type: application/taxii+json`, `Cache-Control: public, max-age=900, stale-while-revalidate=300`, and `Access-Control-Allow-Origin: *`.

## 10. Ghost digest details

`falconeye/digest.py` posts to Ghost Admin API using JWT auth:

```python
kid, secret_hex = admin_api_key.split(":", 1)
secret = bytes.fromhex(secret_hex)
payload = {"iat": now, "exp": now + 300, "aud": "/admin/"}
token = jwt.encode(payload, secret, algorithm="HS256", headers={"kid": kid})
```

Post content uses Ghost HTML cards (not Lexical format). The comment in `digest.py` explains why: HTML cards require no client-side conversion, are indefinitely supported as a Ghost legacy content type, and keep the module dependency-free beyond PyJWT + requests.

Post slug: `falconeye-digest-YYYY-MM-DD` for yesterday's UTC date. The worker checks for an existing post with this slug and updates it if found; otherwise creates it. The mode (`draft` or `published`) is controlled by `FALCONEYE_DIGEST_MODE` env var (default: `draft`).

## 11. nginx vhost (two-phase deploy)

**Phase 1 — HTTP vhost** (`deploy/install-nginx.sh`):

Installs `deploy/nginx/falconeye.conf` (HTTP-only, port 80) and verifies `nginx -t` passes.

**Phase 2 — TLS certificate** (`deploy/install-tls.sh`):

Runs `certbot --nginx`. Requires a DNS A record pointing to the VPS.

The nginx config includes a dedicated `location /api/v1/taxii/` block:

```nginx
location /api/v1/taxii/ {
    try_files $uri $uri/index.json =404;
    default_type application/taxii+json;
    add_header Cache-Control "public, max-age=900, stale-while-revalidate=300";
    add_header Access-Control-Allow-Origin "*";
}
```

## 12. Healthcheck

The SSG writes `/opt/falconeye/public/healthz.json` after each regeneration:

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

Future Nagios checks hit `/healthz` and alert on stale `age_seconds`.

## 13. robots.txt and sitemap.xml

Both are regenerated by the SSG on every run. `robots.txt` allows all user-agents and references the sitemap. `sitemap.xml` enumerates the root paths (`/`, `/asn/`, `/campaign/`, `/api/v1/taxii/`) plus all active and dormant campaign slugs and all ASNs with `ioc_count > 0`.

## 14. Known failure modes

- **URLhaus/abuse.ch 5xx outages.** Logged as failure for that cycle; next cycle retries.
- **NVD 429.** Back off per NVD policy. API key dramatically improves rate limits.
- **Shodan 429.** Exponential backoff (5s→10s→20s→40s→60s→bail). Daily cap enforced at 10,000 requests.
- **APNIC file format quirks.** Header lines (starting with `2|`, `*|*`) must be skipped. Parser uses `|`-delimited records, not `split(',')`.
- **URLhaus tags with commas.** Use a proper CSV parser.
- **Ghost API errors.** `run_digest()` logs and returns 0. Ghost outages never block the main pipeline.

## 15. v0.2 acceptance checklist (operator-facing)

```
[ ] scripts/run.sh all completes without errors: urlhaus → kev → nvd → apnic → sieve → cluster → shodan → ssg
[ ] At least one campaign appears at /campaign/
[ ] Shodan enrichment log shows enriched/skipped counts, no daily cap exceeded
[ ] /api/v1/taxii/collections/ph-iocs/objects.json is valid STIX 2.1 Bundle
[ ] /robots.txt allows all user-agents and references /sitemap.xml
[ ] /sitemap.xml contains /campaign/<slug>/ entries for active campaigns
[ ] ASN pages render SVG sparklines; curl the HTML and grep for 'sr-only'
[ ] Ghost digest: set GHOST_ADMIN_KEY, run scripts/run.sh digest, check Ghost Admin for draft post
[ ] feed.xml items link to campaign pages (not raw IOC URLs)
[ ] feed-iocs.xml items are raw IOC entries
[ ] All systemd timers enabled: systemctl list-timers | grep falconeye
[ ] Test suite: 265+ tests pass with .venv/bin/python -m pytest -q
```

## 16. Build sequence for Claude Code (v0.2 additions)

Steps 1–8 are the v0.1 foundation (ingest workers, sieve, SSG, deploy scripts). v0.2 adds:

9. DB schema additions: `ip_enrichments`, `campaigns`, `campaign_iocs` (Step 1 of v0.2)
10. `falconeye/ingest/shodan_enrich.py` with rate limiting and daily cap (Step 2)
11. `falconeye/cluster.py` with three bucket strategies and idempotent upsert (Step 3)
12. SSG: per-ASN pages with sparklines (Step 4)
13. SSG: per-campaign pages with action templates (Step 5)
14. SSG: index.html pivot to campaign-centric dashboard (Step 6)
15. SSG: STIX 2.1 output + TAXII static layout (Step 7); `falconeye/stix.py`; nginx TAXII block
16. `falconeye/digest.py` + PyJWT dependency (Step 8)
17. systemd units for shodan and digest; `scripts/run.sh` updated (Step 9)
18. Documentation update (Step 10); robots.txt + sitemap.xml in SSG (Adjustment 8)
