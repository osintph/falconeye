# FalconEye

Continuous threat intelligence and vulnerability watchdog for Philippine digital infrastructure. Part of the OSINT-PH suite. Public-good, zero-cost, zero-attack-surface, community self-hostable.

This is the authoritative design document for FalconEye v0.2. All implementation decisions should refer back to this spec. Operational details (exact URLs, system configs, deployment steps) live in `IMPLEMENTATION_NOTES.md`.

## 1. Mission

FalconEye monitors authoritative global threat intelligence feeds and vulnerability catalogs, filters them to surface entries with PH relevance (.ph TLDs, PH-allocated ASNs, local brand strings, and technology stacks heavily deployed in PH government and financial sectors), clusters matching IOCs into named campaigns, and publishes the filtered result as a public, static, zero-attack-surface dashboard with machine-readable STIX 2.1 and a TAXII-compatible static API.

The tool exists because no public, free, PH-scoped continuous threat surface monitor currently does this. Defenders at PH banks, government agencies, ISPs, and MSPs scroll global feeds manually or pay enterprise threat intel vendors. FalconEye is the public-good middle layer.

## 2. Design constraints

- **Zero cost.** All data sources are free with no card-on-file requirement and no commercial-tier-only features blocking core functionality.
- **Zero attack surface.** The public face is static files served by nginx. There is no dynamic application code in the request path. No database queries, no user input handling, no auth surface.
- **Low maintenance.** Every ingest source uses an official JSON, CSV, or plain-text endpoint with a versioned or stable schema. No HTML scraping anywhere in the pipeline.
- **Self-hostable.** Anyone with a 2 vCPU / 4 GB VPS can run a private instance via Docker Compose published in this repo.
- **Public-good positioning.** FalconEye serves the PH security community as a defensive intelligence resource, not a commercial product. License is AGPL v3.

## 3. Architecture

```
[Global Threat Feeds]    [Vulnerability Catalogs]    [Regional Registry Data]
        |                          |                            |
        +--------------------------+----------------------------+
                                   |
                                   v
                  +----------------------------------+
                  |     Python Ingest Workers        |
                  |  (one worker per source, cron)   |
                  +----------------------------------+
                                   |
                                   v
                  +----------------------------------+
                  |     PH Sieve & Normalization     |
                  | (ASN trie, TLD match, brand YAML,|
                  |  CPE inventory YAML)             |
                  +----------------------------------+
                                   |
                  +----------------+----------------+
                  |                                 |
                  v                                 v
   +------------------------------+   +------------------------------+
   | Campaign Clustering          |   | Shodan InternetDB Enrichment |
   | (domain / ASN+tag / /24)     |   | (keyless, IP enrichment)     |
   +------------------------------+   +------------------------------+
                  |                                 |
                  +-----------------+---------------+
                                    |
                                    v
                  +----------------------------------+
                  |     SQLite (WAL mode)            |
                  |     with provenance per record   |
                  +----------------------------------+
                                   |
                                   v
                  +----------------------------------+
                  | Jinja2 Static Site Generator     |
                  | (HTML, feeds, STIX, TAXII,       |
                  |  robots.txt, sitemap.xml)        |
                  +----------------------------------+
                  |
                  v
                  +----------------------------------+
                  |     Static Output Directory      |
                  |  index.html, /campaign/, /asn/,  |
                  |  feed.xml, feed.json,            |
                  |  feed-iocs.xml, feed-iocs.json,  |
                  |  /api/v1/taxii/, manifest.json,  |
                  |  robots.txt, sitemap.xml         |
                  +----------------------------------+
                                   |
                                   v
                  +----------------------------------+
                  |   nginx with gzip_static         |
                  |   (custom telemetry log format)  |
                  +----------------------------------+
                                   |
                                   v
                          [Public consumers]
```

### 3.1 Tech stack

- **Language:** Python 3.9+ (tested on 3.9.6 locally, Ubuntu 24.04 ships 3.12).
- **Ingest framework:** standard library where possible (`urllib`, `csv`, `json`, `sqlite3`). `requests` for sources requiring auth headers or robust retry semantics.
- **Scheduler:** systemd timers. Not cron, not APScheduler. Native systemd units give us journald logs and unit-level observability without adding a dependency.
- **Database:** SQLite in WAL mode. One file at `db/falconeye.db`. No ORM — raw `sqlite3` module with explicit DDL.
- **Templating:** Jinja2.
- **Web server:** nginx-full (Ubuntu package).
- **STIX output:** hand-written JSON, UUIDv5 stable IDs from a fixed namespace (`FALCONEYE_NS`). No STIX library dependency.
- **No queue, no Redis, no Postgres, no Docker required for production.**

## 4. Data sources (v0.2)

### 4.1 abuse.ch URLhaus

Malicious URL feed. API at `urlhaus-api.abuse.ch/v1/`. Free Auth-Key required. **Cadence:** 15 minutes.

### 4.2 CISA Known Exploited Vulnerabilities (KEV)

Active exploitation CVE list. JSON at `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. **Cadence:** 6 hours.

### 4.3 NVD CVE 2.0 API

Full CVE database. `services.nvd.nist.gov/rest/json/cves/2.0`. Incremental pulls via `lastModStartDate`/`lastModEndDate`. **Cadence:** 30 minutes.

### 4.4 APNIC delegated statistics

PH ASN and IP prefix allocations. `ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest`. **Cadence:** daily.

### 4.5 Shodan InternetDB (v0.2)

Passive IP enrichment. `https://internetdb.shodan.io/<ip>`. Keyless. Returns ports, CPEs, hostnames, tags, vulns for a given IP. FalconEye does not perform any active scanning — InternetDB returns Shodan's pre-existing scan data only.

**Rate limiting:** exponential backoff on 429 (5s → 10s → 20s → 40s → 60s → bail). Hard daily cap of 10,000 requests per UTC day enforced in the worker. Stale records (< 6 hours old) are skipped. Every 429 is logged at WARNING.

## 5. PH Sieve logic

Each incoming record is evaluated against four match criteria. A record passes the sieve if it matches at least one.

### 5.1 ASN match (radix tree)

The APNIC ingest worker produces an in-memory radix tree of current PH IP prefixes and ASN numbers. Any IOC with an IP address is matched against this trie.

### 5.2 TLD match

Any IOC with a domain or URL is parsed via the Public Suffix List. If the registrable domain ends in `.ph` (including `.com.ph`, `.gov.ph`, etc.), it matches.

### 5.3 Brand string match

`config/brand_strings.yaml` lists PH-relevant brand strings. Case-insensitive substring match with surrounding-token disambiguation.

### 5.4 CPE inventory match

`config/cpe_inventory.yaml` lists CPE 2.3 vendor/product strings for technology stacks heavily deployed in PH government and financial sectors. Incoming CVE records are matched against this inventory.

## 6. Campaign clustering (v0.2)

`falconeye/cluster.py` groups PH-matched IOCs into named campaigns using three bucket strategies:

### 6.1 Domain clustering (all-time)

All IOCs sharing the same effective grouping domain are merged into one campaign. For hosting-platform PSL domains (`workers.dev`, `pages.dev`, `github.io`, `netlify.app`, `vercel.app`, `glitch.me`), the grouping key is `{account}.{domain}.{suffix}` to avoid merging unrelated actors. For all other domains, the key is `{domain}.{suffix}`.

### 6.2 ASN + tag clustering (14-day rolling window)

IOCs sharing both ASN and URLhaus tag within the last 14 days form a campaign. Captures botnet families (e.g. Mirai nodes across a single ISP) that don't share a domain.

Tag selection uses a two-layer filter:

1. **Priority selection** (`config/cluster_tag_priority.yaml`): picks the single highest-priority tag per IOC. Levels (highest first): `family` (malware family names), `functional` (c2, dropper, phishing, etc.). Architecture/platform tags (`arm`, `mips`, `elf`, `32-bit`, …) are no longer a priority level and are never selected.

2. **Whitelist gate** (`config/cluster_tag_whitelist.yaml`): the selected tag must appear in this positive allowlist. Tags not in the whitelist produce no campaign label, and the IOC is excluded from ASN+tag clustering. This prevents spurious campaigns from novel or low-signal tags.

### 6.3 /24 prefix clustering (14-day rolling window)

IOCs sharing a /24 IPv4 prefix within the last 14 days form a campaign. Captures dense IP-range activity from bulletproof hosting.

### 6.4 Campaign lifecycle

Minimum cluster size is 3 IOCs. Slugs are stable (`dom-<key>`, `ast-<key>`, `pfx-<key>` prefix + normalized key, max 80 chars). Idempotent upsert by slug: campaigns that disappear from clustering get `status='expired'` and `expired_at` set. Status values: `active` (last IOC ≤ 7 days), `dormant` (≤ 30 days), `expired` (> 30 days or no longer clustering).

### 6.5 Action templates

`config/action_templates.yaml` maps URLhaus tags (e.g. `Mirai`, `CobaltStrike`, `phishing`) to defender guidance blocks rendered on per-campaign pages.

## 7. SQLite schema (v0.2)

All tables include provenance fields. WAL mode enabled at database creation.

Core tables (v0.1):
- `iocs` — one row per indicator (URL, IP, domain, hash)
- `cves` — one row per CVE
- `cve_cpe_matches` — CVE-to-CPE junction
- `ph_asns` — current PH ASN allocations from APNIC
- `ph_prefixes` — current PH IP prefix allocations from APNIC
- `sieve_matches` — IOC/CVE-to-match-criterion junction

New tables (v0.2):
- `ip_enrichments` — one row per IP enriched via Shodan InternetDB. Columns: `ip_address` (PK), `ports`, `cpes`, `hostnames`, `tags`, `vulns` (all JSON), `fetched_at`, `source_url`. Re-enriched if older than 6 hours.
- `campaigns` — one row per cluster. Columns: `slug` (UNIQUE), `name`, `summary`, `campaign_type` (domain/asn_tag/prefix24), `cluster_key`, `status` (active/dormant/expired), `ioc_count`, `first_seen`, `last_seen`, `expired_at`, `generated_at`.
- `campaign_iocs` — campaign-to-IOC junction with UNIQUE constraint on (campaign_id, ioc_id).

## 8. Output surfaces (v0.2)

Generated by the SSG into `/opt/falconeye/public/`:

**Root files:**
- `index.html` — dashboard with stats, active campaigns grid, PH ASN table, recent CVEs
- `feed.xml` / `feed.json` — primary feeds: campaign-level items (RSS 2.0 / JSON Feed 1.1)
- `feed-iocs.xml` / `feed-iocs.json` — secondary feeds: raw IOC+CVE stream
- `manifest.json` — corpus-level metadata, per-source row counts, schema version
- `healthz.json` — per-source last-success timestamps for monitoring
- `robots.txt` — allows all user-agents, references sitemap
- `sitemap.xml` — enumerates `/`, `/asn/`, `/campaign/`, `/api/v1/taxii/`, all active/dormant campaign slugs, all ASNs with IOC count > 0

**Per-ASN pages** under `/asn/`:
- `asn/index.html` — ASN roster table with IOC counts and last-seen dates
- `asn/<ASN>/index.html` — per-ASN page: IOC table, weekly sparkline (inline SVG + sr-only accessibility span), open ports/CPEs from Shodan

**Per-campaign pages** under `/campaign/`:
- `campaign/index.html` — campaigns grouped by active / dormant / expired; each card has a 4 px status-coloured left border
- `campaign/<slug>/index.html` — per-campaign page: IOC table with pivot links per IOC type (IP → AbuseIPDB / Shodan / VirusTotal / HE.net; URL → URLhaus / VirusTotal domain; domain → VirusTotal / URLhaus), defender guidance from action templates (with port list and external reference link when present), ISP abuse contact block for ASN-attributed campaigns

**STIX 2.1 / TAXII-compatible static API** under `/api/v1/taxii/`:
- `api/v1/taxii/index.json` — TAXII discovery object
- `api/v1/taxii/collections/index.json` — collections manifest
- `api/v1/taxii/collections/<id>/objects.json` — STIX Bundle (indicators, vulnerabilities, campaign objects, relationships)
- Served with `Content-Type: application/taxii+json` and CORS `Access-Control-Allow-Origin: *`

All files regenerate on every SSG run.

### 8.1 STIX 2.1 ID stability

All STIX IDs are UUIDv5 derived from a fixed namespace `FALCONEYE_NS = uuid.UUID("c40e7b5b-eac2-471d-a05f-2bb8e2be4b39")`. Same IOC value always produces the same STIX indicator ID across runs.

### 8.2 Sparkline accessibility

ASN pages include an inline SVG polyline sparkline for 12-week IOC activity. Immediately preceding the SVG, a `<span class="sr-only">` lists weekly counts in text form for screen readers. The `.sr-only` CSS class (clip + 1px box) is defined inline in the template.

## 9. Roadmap

### v0.1 (shipped)

Dashboard + RSS + JSON + manifest. Four ingest sources. Public-readable, no auth, no JavaScript app.

### v0.2 (this release)

Campaign clustering (domain, ASN+tag, /24 prefix), Shodan InternetDB enrichment, per-campaign and per-ASN static pages, STIX 2.1 output, TAXII-compatible static API, robots.txt/sitemap.xml, dual feeds (campaign-primary + IOC-secondary).

### v0.3 (planned)

Brotli precompression, FalconEye-Match analyst lookup (Bloom filter prefilter, 2-hex sharded indices, `falconeye-cli`), EPSS API integration, OSV.dev for open-source vulnerabilities, GitHub Security Advisories, additional ingest sources (Spamhaus DROP/EDROP, abuse.ch SSLBL, DShield).

## 10. Explicit non-goals for v0.2

- Active scanning of any kind (FalconEye reads existing data only — Shodan InternetDB is passive)
- Real-time TAXII server (static files serve the same content without a database query path)
- Blog/newsletter integration (manual posts via Ghosler; no automated digest pipeline)
- User accounts of any kind (never)
- Discord/Telegram/Slack bot integrations (separate repo if ever)
- Commercial threat intel source ingestion (never)
- FalconEye-Match CLI lookup tool (v0.3)

## 11. Acceptance criteria for v0.2.3

FalconEye v0.2.3 ships when all of the following are true:

- All v0.1 criteria remain satisfied.
- `scripts/run.sh all` runs `urlhaus → kev → nvd → apnic → sieve → cluster → shodan → ssg` without errors.
- `falconeye-prefix-enrich` timer runs weekly, populates `ph_prefixes.asn` via RIPEstat, and triggers SSG via `OnSuccess`.
- `_query_asns_with_ioc_counts` uses SQL JOIN on `ph_prefixes.asn` as the primary attribution path; Python CIDR fallback runs only for unenriched prefixes.
- Campaign clustering produces at least one named campaign from the live corpus.
- No campaign is created from architecture-only tags (`arm`, `mips`, `elf`, etc.) — `cluster_tag_whitelist.yaml` gates all primary tags.
- Shodan enrichment runs within daily cap (< 10,000 requests) and respects the 6-hour staleness window.
- Per-campaign pages render IOC pivot links: AbuseIPDB/Shodan/VT/HE.net for IP IOCs; URLhaus/VT for URL IOCs; VT for domain IOCs.
- Per-campaign pages for ASN-attributed campaigns render the ISP abuse contact block when the ASN is in `asn_abuse_contacts.yaml`.
- Defender guidance blocks render `ports` list and `rule_ref` link when present in `action_templates.yaml`.
- Per-ASN pages are only written for ASNs with at least one recent IOC — empty ASN pages are skipped.
- ASN pages include SVG sparkline and sr-only weekly count span.
- STIX bundle at `/api/v1/taxii/collections/ph-iocs/objects.json` validates as a STIX 2.1 Bundle with at least one Indicator.
- `robots.txt` allows all crawlers and references `sitemap.xml`.
- `sitemap.xml` enumerates root paths and all active campaign/ASN URLs.
- Primary feeds (`feed.xml`, `feed.json`) carry campaign-level items; secondary feeds (`feed-iocs.xml`, `feed-iocs.json`) carry raw IOC stream.
- Test suite: all 311+ tests pass.

## 12. License and acknowledgments

FalconEye is licensed under AGPL v3.

Data sources are credited per record in the dashboard UI and in `manifest.json`. Shodan InternetDB is credited in each enrichment record's `source_url` field.

The OSINT-PH suite is maintained by Sigmund Brandstaetter (sigmund@osintph.info). FalconEye is the second public tool in the suite (following Bantay-Eye).
