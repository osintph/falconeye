# FalconEye

Continuous threat intelligence and vulnerability watchdog for Philippine digital infrastructure.

FalconEye monitors authoritative global threat feeds and vulnerability catalogs, filters them to surface entries with PH relevance (.ph TLDs, PH-allocated ASNs, local brand strings, and technology stacks heavily deployed in PH government and financial sectors), clusters matching IOCs into named campaigns, and publishes everything as a public, static, zero-attack-surface dashboard with machine-readable STIX 2.1 / TAXII-compatible feeds.

Part of the [OSINT-PH](https://osintph.info) tool suite.

## Status

**v0.2.3: operational threat intelligence ledger.** Public dashboard is not yet live. See the [project spec](SPEC.md) for the design and the [implementation notes](IMPLEMENTATION_NOTES.md) for operational details.

## What it does

- Ingests four authoritative free threat intelligence and vulnerability sources every 15 minutes to 24 hours
- Filters records against PH-specific criteria: ASN allocations from APNIC, .ph TLD, PH brand string watchlist, PH-relevant CPE inventory
- Enriches PH IP prefixes with origin ASN via the RIPEstat Data API (weekly, no auth required); populates `ph_prefixes.asn` for accurate IOC-to-ASN attribution even when the APNIC delegation file doesn't carry routing data
- Clusters PH-matched IOCs into named campaigns by domain, ASN+tag (family/functional tags only — architecture tags excluded via `cluster_tag_whitelist.yaml`), and /24 prefix
- Enriches IPs via Shodan InternetDB (keyless, open ports, CPEs, CVEs, hostnames)
- Generates a static HTML dashboard, per-campaign and per-ASN pages, RSS/JSON feeds, STIX 2.1 bundles, and a TAXII-compatible static API
- Per-campaign pages include IOC pivot links (AbuseIPDB, Shodan, VirusTotal, HE.net for IPs; URLhaus and VirusTotal for URLs/domains), ISP abuse contact blocks for ASN-attributed campaigns, and defender guidance with port lists and reference links
- Per-ASN pages are skipped when the ASN has no recent IOCs (no stub pages)
- Regenerates `robots.txt` and `sitemap.xml` on every SSG run
- Serves everything via nginx as static files (no dynamic application code in the public request path)
- Maintains chain-of-custody provenance for every record (source feed, fetch timestamp, source URL, manifest version)

## Data sources (v0.2)

| Source | What it provides |
|---|---|
| [abuse.ch URLhaus](https://urlhaus.abuse.ch/) | Active malicious URL feed |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities |
| [NVD CVE 2.0](https://nvd.nist.gov/) | All CVE records |
| [APNIC delegated stats](https://ftp.apnic.net/apnic/stats/apnic/) | PH ASN and IP prefix allocations |
| [Shodan InternetDB](https://internetdb.shodan.io/) | Open ports, CPEs, CVEs, hostnames per IP (keyless) |

All sources are free, require no credit card, and use stable JSON/CSV/text endpoints with versioned schemas.

## Roadmap

- **v0.1 (shipped):** ingest + static dashboard + RSS + JSON
- **v0.2 (current):** campaign clustering, Shodan enrichment, per-campaign and per-ASN pages, STIX 2.1, TAXII-compatible static API, robots.txt/sitemap.xml
- **v0.3 (planned):** Brotli precompression, FalconEye-Match analyst lookup with Bloom filter prefilter, EPSS API integration, additional ingest sources (Spamhaus DROP/EDROP, abuse.ch SSLBL, OSV.dev)

See [SPEC.md](SPEC.md) for full design details.

## Self-hosting

Canonical deployment: Ubuntu 24.04 LTS, bare systemd + nginx, no Docker required. Minimum VPS: 2 vCPU, 4 GB RAM, 40 GB SSD. Estimated setup time: 10 minutes.

You need two free API keys (no payment method required):
- [abuse.ch](https://auth.abuse.ch/) for URLhaus
- [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) for NVD (technically optional, but rate limits are punishing without one)

```bash
# 1. Create system user and directory layout
sudo useradd --system --create-home --home-dir /opt/falconeye --shell /usr/sbin/nologin falconeye
sudo -u falconeye mkdir -p /opt/falconeye/{src,public,db,logs,config}

# 2. Clone repo
sudo -u falconeye git clone https://github.com/osintph/falconeye.git /opt/falconeye/src

# 3. Create Python venv and install package
sudo bash /opt/falconeye/src/deploy/install-venv.sh

# 4. Populate secrets (fill in URLHAUS_AUTH_KEY, NVD_API_KEY, and optionally Ghost keys)
sudo -u falconeye cp /opt/falconeye/src/config/secrets.env.example /opt/falconeye/config/secrets.env
sudo -u falconeye vi /opt/falconeye/config/secrets.env

# 5. Phase 1: install nginx HTTP vhost (verifies the dashboard serves on port 80)
sudo bash /opt/falconeye/src/deploy/install-nginx.sh

# 6. Phase 2: obtain TLS certificate (requires DNS A record pointing to VPS)
sudo bash /opt/falconeye/src/deploy/install-tls.sh

# 7. Install and enable systemd timers
sudo bash /opt/falconeye/src/deploy/install-systemd.sh

# 8. Run first full ingest cycle to populate the corpus
sudo bash /opt/falconeye/src/scripts/run.sh all
```

For subsequent manual runs: `sudo bash /opt/falconeye/src/scripts/run.sh <worker>` where worker is `urlhaus`, `kev`, `nvd`, `apnic`, `sieve`, `cluster`, `shodan`, `ssg`, or `all`.

Full operational details are in [IMPLEMENTATION_NOTES.md](IMPLEMENTATION_NOTES.md).

## Defensive use only

FalconEye is built to help PH defenders. It is not a target acquisition tool, it does not perform any active scanning, and it does not enumerate vulnerabilities in PH systems beyond what the upstream sources have already publicly disclosed. Shodan InternetDB lookups are passive reads of Shodan's pre-existing scan data — FalconEye never sends network probes. The intended audience is PH government CERTs, bank SOCs, ISP security teams, MSPs, and independent investigators working on PH incidents.

If you are a PH organization and want a specific brand string added to the watchlist, please open a GitHub issue or contact the maintainer.

## License

[AGPL v3](LICENSE)

## Acknowledgments

FalconEye stands on the shoulders of free public threat intelligence projects. abuse.ch, CISA, NIST NVD, APNIC, and Shodan all publish their data in machine-consumable formats specifically so tools like this can exist. Their work is the foundation; FalconEye is the regional filter.

## Maintainer

Sigmund Brandstaetter, OSINT-PH. Reach me at [sigmund@osintph.info](mailto:sigmund@osintph.info) or via the [OSINT-PH blog](https://blog.osintph.info).

Part of the OSINT-PH suite alongside Bantay-Eye and related defensive tools.
