# FalconEye

Continuous threat intelligence and vulnerability watchdog for Philippine digital infrastructure. Part of the OSINT-PH suite. Public-good, zero-cost, zero-attack-surface, community self-hostable.

This is the authoritative design document for FalconEye v0.1. All implementation decisions should refer back to this spec. Operational details (exact URLs, system configs, deployment steps) live in `IMPLEMENTATION_NOTES.md`.

## 1. Mission

FalconEye monitors authoritative global threat intelligence feeds and vulnerability catalogs, filters them to surface entries with PH relevance (.ph TLDs, PH-allocated ASNs, local brand strings, and technology stacks heavily deployed in PH government and financial sectors), and publishes the filtered result as a public, static, zero-attack-surface dashboard.

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
                                   v
                  +----------------------------------+
                  |     SQLite (WAL mode)            |
                  |     with provenance per record   |
                  +----------------------------------+
                                   |
                                   v
                  +----------------------------------+
                  |     Jinja2 Static Site Generator |
                  +----------------------------------+
                                   |
                                   v
                  +----------------------------------+
                  |     Static Output Directory      |
                  |  index.html, feed.xml, feed.json,|
                  |  manifest.json                   |
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

- **Language:** Python 3.12 (Ubuntu 24.04 default).
- **Ingest framework:** standard library where possible (`urllib`, `csv`, `json`, `sqlite3`). `requests` only if a source needs robust retry semantics or non-trivial headers (abuse.ch Auth-Key handling).
- **Scheduler:** systemd timer firing every 15 minutes. Not cron, not APScheduler. Native systemd units give us journald logs and unit-level observability without adding a dependency.
- **Database:** SQLite in WAL mode. One file at `db/falconeye.db`.
- **Templating:** Jinja2.
- **Web server:** nginx-full (Ubuntu package).
- **No queue, no Redis, no Postgres, no Docker required for production.** Docker Compose is published for community self-hosting convenience but the canonical deployment is bare systemd plus nginx.

## 4. Data sources (v0.1)

Four sources land in v0.1. All are verified free, with stable schemas, and operator-maintained (not third-party scrapes).

### 4.1 abuse.ch URLhaus

Malicious URL feed maintained by abuse.ch (now operated jointly with Spamhaus). API at `urlhaus-api.abuse.ch/v1/` requires a free Auth-Key header (obtained at https://auth.abuse.ch via social login). Bulk CSV/JSON dumps available at `urlhaus.abuse.ch/downloads/` may or may not require auth (Claude Code verifies at implementation time and uses whichever path is cleanest).

**Ingest cadence:** every 15 minutes.

**Schema fields consumed:** URL, host, threat type, tags, date added, payload SHA256 (when available), reference link.

**License:** community use free, commercial subscriptions exist for high-volume. FalconEye is non-commercial public-good use and stays in the free tier.

### 4.2 CISA Known Exploited Vulnerabilities (KEV)

US CISA's authoritative list of CVEs being actively exploited in the wild. JSON feed at `cisa.gov/known-exploited-vulnerabilities-catalog` (canonical) or the mirror at `github.com/cisagov/kev-data`.

**Ingest cadence:** every 6 hours. CISA typically updates once per US weekday.

**Schema fields consumed:** CVE ID, vendor, product, vulnerability name, date added, due date, required action, notes, ransomware use flag, CWE IDs.

**License:** US government public domain (CC0 on the GitHub mirror). Fully redistributable.

### 4.3 NVD CVE 2.0 API

National Vulnerability Database REST API at `services.nvd.nist.gov/rest/json/cves/2.0`. Public, no card required. A free API key is recommended for higher rate limits and can be requested at `nvd.nist.gov/developers/request-an-api-key`.

**Ingest cadence:** every 30 minutes for incremental pulls using `lastModStartDate` and `lastModEndDate` parameters. Full backfill on first run.

**Schema fields consumed:** CVE ID, published date, last modified date, descriptions, CVSS v3.1 score, CVSS severity, affected CPEs, references.

**License:** US government public domain.

### 4.4 APNIC delegated statistics

APNIC publishes daily `delegated-apnic-latest` and `delegated-apnic-extended-latest` files listing all IP and ASN allocations to APNIC members, including PH-allocated ASNs and IPv4/IPv6 prefixes. Hosted at `ftp.apnic.net/apnic/stats/apnic/`.

**Ingest cadence:** daily.

**Schema fields consumed:** registry, country code, type (asn/ipv4/ipv6), value, count, status. We filter on country code `PH`.

**License:** APNIC stats files are published under APNIC's terms allowing free use for legitimate purposes. Verify current terms before publishing.

## 5. PH Sieve logic

Each incoming record is evaluated against four match criteria. A record passes the sieve if it matches at least one.

### 5.1 ASN match (radix tree)

The APNIC ingest worker produces an in-memory radix tree of current PH IP prefixes and ASN numbers. Any IOC with an IP address is matched against this trie. Match returns the PH ASN integer that contains the IP, or none.

### 5.2 TLD match

Any IOC with a domain or URL is parsed via the Public Suffix List. If the registrable domain ends in `.ph` (including `.com.ph`, `.gov.ph`, `.org.ph`, `.edu.ph`, etc.), it matches.

### 5.3 Brand string match

A curated `config/brand_strings.yaml` file lists PH-relevant brand strings (banks, telcos, government agencies, major enterprises). Sources include the BSP-published bank list, PSE-listed companies, and major PH government agency names. Brand match is case-insensitive substring with surrounding-token disambiguation to avoid false positives on short acronyms.

### 5.4 CPE inventory match

A curated `config/cpe_inventory.yaml` file lists CPE 2.3 vendor/product strings representing technology stacks heavily deployed in PH government and financial sectors. Initial inventory drawn from operator knowledge of PH consulting engagements. Incoming CVE records are matched against this inventory.

## 6. SQLite schema (v0.1)

All tables include provenance fields: `source` (which feed), `source_id` (upstream record ID), `fetched_at` (UTC timestamp of ingest), `source_url` (where the record came from), `manifest_version` (which ingest cycle produced it).

Core tables:

- `iocs` - one row per indicator of compromise (URL, IP, domain, hash). Columns include ioc_type, ioc_value, threat_type, tags, confidence, first_seen, last_seen, plus provenance.
- `cves` - one row per CVE. Columns include cve_id, published_date, last_modified, description, cvss_v3_score, cvss_v3_severity, plus provenance.
- `cve_cpe_matches` - junction table linking CVEs to affected CPEs.
- `ph_asns` - current PH ASN allocations from APNIC.
- `ph_prefixes` - current PH IP prefix allocations from APNIC.
- `sieve_matches` - junction table linking iocs/cves to the matching criterion (asn, tld, brand, cpe) and the matched value.

WAL mode is enabled at database creation. Indexes on ioc_value, cve_id, fetched_at.

## 7. Output surfaces (v0.1)

Generated by the SSG into `/opt/falconeye/public/`:

- `index.html` - the dashboard. Recent IOCs and CVEs with PH relevance, sortable client-side (no JavaScript framework, vanilla DOM).
- `feed.xml` - RSS 2.0 of new PH-matched items in the last 24 hours.
- `feed.json` - JSON Feed 1.1 equivalent of the RSS.
- `manifest.json` - corpus-level metadata: per-source last-fetched timestamp, row counts, schema version, license attributions. Consumed by future FalconEye-Match v0.2.

All four files regenerate after every ingest cycle. nginx serves them with `gzip_static`.

## 8. Roadmap

### v0.1 (this release)

Dashboard + RSS + JSON + manifest. Four ingest sources. Public-readable, no auth, no JavaScript app. Goal: ship a working continuous-monitoring surface in two weekends.

### v0.2 (FalconEye-Match)

Analyst lookup function. Inputs: domain, subdomain, IP, ASN, CPE string, free-form technology name. Output: matching IOCs and CVEs from the FalconEye corpus.

Architecture: pre-published sharded JSON indices (2-hex domain shards, ASN-keyed bulk file, CPE vendor-letter shards), client-side matching in a vanilla JS SPA at `/lookup/`, plus a CLI (`falconeye-cli`) that consumes the same indices. Bloom filter prefilter provides instant negative results with zero network round trips for the common case. k-anonymity via 2-hex hash-prefix lookup.

### v0.3 (operational maturity)

Brotli precompression (requires `nginx-extras` package change), TAXII 2.1 server endpoint for SOC ingestion, EPSS API integration, OSV.dev for open-source vulnerabilities, GitHub Security Advisories, additional ingest sources (Spamhaus DROP/EDROP, abuse.ch SSLBL, DShield).

## 9. Explicit non-goals for v0.1

The following are deliberately excluded from v0.1 to keep the scope shippable in two weekends:

- FalconEye-Match analyst lookup (v0.2)
- CLI tool (v0.2)
- Bloom filter generation (v0.2)
- TAXII or STIX export (v0.3)
- Per-sector RSS feeds (v0.2 if needed)
- Brotli compression (v0.3)
- User accounts of any kind (never)
- Discord/Telegram/Slack bot integrations (never in this repo, separate repo if ever)
- Commercial threat intel source ingestion (never)
- Active scanning of PH infrastructure (separate tool, scope creep risk)

## 10. Acceptance criteria for v0.1

FalconEye v0.1 ships when all of the following are true:

- Four ingest workers (URLhaus, KEV, NVD, APNIC) run successfully on the production VPS and land records into SQLite without errors for 48 consecutive hours.
- Sieve correctly filters at least 100 IOCs and at least 5 CVEs as PH-relevant during that 48-hour window.
- Dashboard, RSS, and JSON outputs regenerate after every cycle without errors.
- `/healthz` endpoint returns 200 with per-source last-success timestamps.
- nginx serves the static directory with gzip_static and the custom telemetry log format.
- Cloudflare DNS points `falconeye.osintph.info` at the VPS (DNS-only, not proxied).
- A blog post on blog.osintph.info announces the tool with a link to the public dashboard and the GitHub repo.

## 11. License and acknowledgments

FalconEye is licensed under AGPL v3.

Data sources are credited per record in the dashboard UI and in `manifest.json`. Specifically:

- abuse.ch URLhaus: cited in every URL-derived record
- CISA KEV: cited in every KEV-derived record
- NVD: cited in every NVD-derived CVE record
- APNIC: cited in the regional context section

The OSINT-PH suite is maintained by Sigmund Brandstaetter (sigmund@osintph.net). FalconEye is the second public tool in the suite (following Bantay-Eye).
